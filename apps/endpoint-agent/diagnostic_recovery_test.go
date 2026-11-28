package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

type diagnosticCrashInput struct {
	StateDir   string
	Authority  ed25519.PublicKey
	Assignment contracts.DiagnosticAssignmentV1
}

func TestDiagnosticCrashProcess(t *testing.T) {
	stage := os.Getenv("DEVICE_AUDIT_TEST_DIAGNOSTIC_CRASH")
	if stage == "" {
		t.Skip("subprocess entry")
	}
	var input diagnosticCrashInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		t.Fatal(err)
	}
	store, err := openIdentityStore(input.StateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	id, receipt, err := store.admitted()
	if err != nil {
		t.Fatal(err)
	}
	runner := workflows.NewProbeRunner(func(context.Context, workflows.Request) ([]byte, error) {
		if stage == "running" {
			os.Exit(88)
		}
		return []byte(`{"original":true}`), nil
	})
	job := new(diagnosticJob)
	if _, err := store.executeDiagnosticAssignment(t.Context(), runner, input.Assignment, input.Authority, id, receipt, "boot:original", job, new(sync.Mutex)); err != nil {
		t.Fatal(err)
	}
	os.Exit(88)
}

type testDiagnosticTransport struct {
	poll func() (workflows.PollResponse, error)
	send func(*diagnosticJob) error
}

func (t testDiagnosticTransport) pollDiagnostics(context.Context, string) (workflows.PollResponse, error) {
	return t.poll()
}

func (t testDiagnosticTransport) sendDiagnostic(_ context.Context, job *diagnosticJob) error {
	return t.send(job)
}

func TestDiagnosticOutboxProcessRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, crash, state string
		cancelled          bool
	}{
		{"offline completion", "completed", "succeeded", false},
		{"reboot during worker", "running", "rebooted", false},
		{"cancelled during outage", "running", "cancelled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, dir, id, receipt := admittedStore(t)
			deviceKey := id.signing.Public().(ed25519.PublicKey)
			spool, err := openEvidenceSpool(testServiceConfig(t, dir).EvidenceDir, minEvidenceCap, 8, deviceKey, receipt)
			if err != nil {
				t.Fatal(err)
			}
			defer spool.close()
			appendTelemetry := func(store *identityStore) {
				t.Helper()
				envelope, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if err := spool.append(envelope); err != nil {
					t.Fatal(err)
				}
			}
			appendTelemetry(store)
			store.close()

			authority, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			a := recoveryAssignment(t, receipt, private)
			data, err := json.Marshal(diagnosticCrashInput{dir, authority, a})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDiagnosticCrashProcess$")
			cmd.Env = append(os.Environ(), "DEVICE_AUDIT_TEST_DIAGNOSTIC_CRASH="+tc.crash)
			cmd.Stdin = bytes.NewReader(data)
			if out, err := cmd.CombinedOutput(); cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 88 {
				t.Fatalf("fault process did not exit at %s: %v %s", tc.crash, err, out)
			}

			store, err = openIdentityStore(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { store.close() }()
			appendTelemetry(store)
			job, err := store.loadDiagnosticJob(authority, deviceKey, receipt)
			if err != nil || job == nil || job.StartedAt.IsZero() {
				t.Fatalf("lost durable start: %+v %v", job, err)
			}
			original := bytes.Clone(job.Result)
			var sent []uint64
			d := diagnosticDelivery{
				store: store, identity: id, receipt: receipt, authority: authority, bootID: "boot:replacement",
				job: job, sequenceMu: new(sync.Mutex), nextPoll: time.Now().Add(time.Minute),
				runner: workflows.NewProbeRunner(func(context.Context, workflows.Request) ([]byte, error) {
					t.Fatal("recovery ran a worker")
					return nil, nil
				}),
			}
			online, accepted := false, false
			d.transport = testDiagnosticTransport{
				poll: func() (workflows.PollResponse, error) {
					if !online {
						return workflows.PollResponse{}, errDeliveryRetry
					}
					var response workflows.PollResponse
					if tc.cancelled {
						response.CancelAssignmentIDs = []string{a.AssignmentID}
					}
					return response, nil
				},
				send: func(job *diagnosticJob) error {
					result, err := job.result()
					if err != nil || result.VerifySignature(deviceKey) != nil ||
						result.State != tc.state || result.BootID != "boot:original" || result.StartedAt == nil {
						t.Fatalf("invalid recovered result: %+v, %v", result, err)
					}
					if tc.crash == "completed" {
						if !bytes.Equal(original, job.Result) || len(result.Evidence) != 1 ||
							store.verifyDiagnosticEvidence(result) != nil {
							t.Fatal("completed result or evidence was changed")
						}
					} else if len(result.Evidence) != 0 {
						t.Fatal("interrupted job claimed evidence")
					}
					if !online {
						return errDeliveryRetry
					}
					if !accepted {
						accepted = true
						sent = append(sent, result.Sequence)
						original = bytes.Clone(job.Result)
						return errDeliveryRetry // Controller committed but response was lost.
					}
					if !bytes.Equal(original, job.Result) {
						t.Fatal("retry changed signed bytes")
					}
					return nil
				},
			}
			send := func(_ context.Context, _ []byte, envelope contracts.EvidenceEnvelopeV1) (contracts.AcknowledgementV1, error) {
				sent = append(sent, envelope.Sequence)
				return spoolTestAck(t, private, envelope), nil
			}
			step := func() error {
				_, err := d.step(t.Context(), spool, authority, send)
				return err
			}

			if tc.crash == "completed" {
				if err := step(); err != nil { // Earlier queued telemetry.
					t.Fatal(err)
				}
			}
			if err := step(); !errors.Is(err, errDeliveryRetry) || d.job == nil {
				t.Fatalf("offline step lost job: %v", err)
			}
			online = true
			if tc.crash == "running" {
				if err := step(); err != nil { // Recover based on the authenticated poll.
					t.Fatal(err)
				}
				if err := step(); err != nil { // Earlier queued telemetry.
					t.Fatal(err)
				}
			}
			if err := step(); !errors.Is(err, errDeliveryRetry) {
				t.Fatalf("lost response did not retain job: %v", err)
			}
			store.close()
			store, err = openIdentityStore(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			d.store = store
			d.job, err = store.loadDiagnosticJob(authority, deviceKey, receipt)
			if err != nil || d.job == nil {
				t.Fatalf("unacknowledged result was lost: %v", err)
			}
			if err := step(); err != nil || d.job != nil {
				t.Fatalf("result was not retired: %v", err)
			}
			if err := step(); err != nil {
				t.Fatal(err)
			}
			if len(sent) != 3 || sent[0] != 2 || sent[1] != 3 || sent[2] != 4 {
				t.Fatalf("shared sequence order lost: %v", sent)
			}
			job, err = store.loadDiagnosticJob(authority, deviceKey, receipt)
			if err != nil || job != nil {
				t.Fatalf("retired result became active: %+v, %v", job, err)
			}
			if _, err := store.executeDiagnosticAssignment(t.Context(), d.runner, a, authority, id, receipt, d.bootID, new(diagnosticJob), d.sequenceMu); !errors.Is(err, workflows.ErrAssignmentReplay) {
				t.Fatalf("completed assignment was admitted again: %v", err)
			}
		})
	}
}

func recoveryAssignment(t *testing.T, receipt contracts.EnrollmentAcceptedV1, key ed25519.PrivateKey) contracts.DiagnosticAssignmentV1 {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	component := "storage:disk-0"
	keyID, _ := contracts.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	a := contracts.DiagnosticAssignmentV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.DiagnosticAssignmentV1Version, DeploymentID: receipt.DeploymentID,
			DeviceID: receipt.DeviceID, SigningKeyID: keyID, Sequence: 1,
			IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339),
		},
		AssignmentID: "assignment:recover", ProbeID: contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &component},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 5, MaxOutputBytes: 128},
	}
	message, err := a.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	return a
}

func TestDiagnosticCancelsRunningProbeOnReconnect(t *testing.T) {
	store, _, id, receipt := admittedStore(t)
	defer store.close()
	authority, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	assignment := recoveryAssignment(t, receipt, signer)
	polls := 0
	started := make(chan struct{})
	d := diagnosticDelivery{
		store: store, identity: id, receipt: receipt, authority: authority, bootID: "boot:test",
		sequenceMu: new(sync.Mutex),
		runner: workflows.NewProbeRunner(func(ctx context.Context, _ workflows.Request) ([]byte, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}),
		transport: testDiagnosticTransport{
			poll: func() (workflows.PollResponse, error) {
				select {
				case <-started:
				default:
					return workflows.PollResponse{}, errDeliveryRetry
				}
				polls++
				if polls == 1 {
					return workflows.PollResponse{}, errDeliveryRetry
				}
				return workflows.PollResponse{CancelAssignmentIDs: []string{assignment.AssignmentID}}, nil
			},
		},
	}
	job := new(diagnosticJob)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := d.executeWithCancellation(ctx, assignment, job, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	result, err := job.result()
	if err != nil || polls != 2 || result.State != "cancelled" || result.StartedAt == nil || len(result.Evidence) != 0 {
		t.Fatalf("reconnect did not cancel a running job: polls=%d result=%+v err=%v", polls, result, err)
	}
}
