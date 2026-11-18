package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func spoolTestAck(t *testing.T, key ed25519.PrivateKey, e contracts.EvidenceEnvelopeV1) contracts.AcknowledgementV1 {
	t.Helper()
	signing, err := e.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contracts.EnvelopeRequestSHA256V1(signing, e.Signature)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := contracts.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	a := contracts.AcknowledgementV1{
		SchemaVersion: contracts.AcknowledgementV1Version, DeploymentID: e.DeploymentID, DeviceID: e.DeviceID,
		ControllerKeyID: keyID, RequestSchemaVersion: e.SchemaVersion, RequestKeyID: e.SigningKeyID,
		RequestSequence: e.Sequence, RequestSHA256: digest, ReceivedAt: e.IssuedAt, Status: "accepted", LastSequence: &e.Sequence,
	}
	msg, err := a.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(key, msg))
	return a
}

func TestSpoolProcessRecovery(t *testing.T) {
	for _, stage := range []string{"append-staged", "append-committed", "dequeue-staged", "dequeue-committed"} {
		t.Run(stage, func(t *testing.T) {
			store, stateDir, i, receipt := admittedStore(t)
			dir := testServiceConfig(t, stateDir).EvidenceDir
			public := i.signing.Public().(ed25519.PublicKey)
			first, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			store.close()
			s, err := openEvidenceSpool(dir, minEvidenceCap, 2, public, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.append(first); err != nil {
				t.Fatal(err)
			}
			before, _, err := s.head()
			if err != nil {
				t.Fatal(err)
			}
			s.close()

			controller, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(spoolCrashInput{dir, stage, public, controller, receipt, second, spoolTestAck(t, private, first)})
			cmd := exec.Command(os.Args[0], "-test.run=^TestSpoolCrashProcess$")
			cmd.Env = append(os.Environ(), "DEVICE_AUDIT_TEST_SPOOL_CRASH=1")
			cmd.Stdin = bytes.NewReader(input)
			if out, err := cmd.CombinedOutput(); cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 88 {
				t.Fatalf("child did not exit at commit boundary: %v %s", err, out)
			}
			s, err = openEvidenceSpool(dir, minEvidenceCap, 2, public, receipt)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			switch stage {
			case "append-committed":
				if len(s.queue) != 2 {
					t.Fatal("committed append was lost")
				}
				if err := s.append(second); err == nil {
					t.Fatal("duplicate sequence accepted")
				}
			case "dequeue-committed":
				if _, _, err := s.head(); !errors.Is(err, io.EOF) || s.acknowledged != first.Sequence {
					t.Fatal("dequeue commit was lost")
				}
				data, err := os.ReadFile(filepath.Join(dir, spoolRetired))
				if err != nil || !bytes.Equal(data, before) {
					t.Fatal("retirement changed signed bytes")
				}
				return
			default:
				if len(s.queue) != 1 || s.acknowledged != 0 {
					t.Fatal("uncommitted operation affected the queue")
				}
			}
			after, _, err := s.head()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("recovery changed signed bytes")
			}
		})
	}
}

type spoolCrashInput struct {
	Dir, Stage         string
	Public, Controller ed25519.PublicKey
	Receipt            contracts.EnrollmentAcceptedV1
	Envelope           contracts.EvidenceEnvelopeV1
	Ack                contracts.AcknowledgementV1
}

func TestSpoolCrashProcess(t *testing.T) {
	if os.Getenv("DEVICE_AUDIT_TEST_SPOOL_CRASH") != "1" {
		return
	}
	var input spoolCrashInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		t.Fatal(err)
	}
	s, err := openEvidenceSpool(input.Dir, minEvidenceCap, 2, input.Public, input.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	spoolStage = func(stage string) {
		if stage == input.Stage {
			os.Exit(88)
		}
	}
	if input.Stage == "append-staged" || input.Stage == "append-committed" {
		err = s.append(input.Envelope)
	} else {
		err = s.acknowledge(input.Controller, input.Ack)
	}
	t.Fatalf("did not reach commit fault: %v", err)
}

func TestSpoolRetentionAndCorruption(t *testing.T) {
	store, stateDir, i, receipt := admittedStore(t)
	defer store.close()
	dir := testServiceConfig(t, stateDir).EvidenceDir
	public := i.signing.Public().(ed25519.PublicKey)
	first, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(first)
	legacy = append(append([]byte(" "), legacy...), '\n')
	if err := os.WriteFile(filepath.Join(dir, evidenceLogFile), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openEvidenceSpool(dir, minEvidenceCap, 1, public, receipt)
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := s.head()
	if err != nil || !bytes.Equal(data, legacy) {
		t.Fatal("migration changed the legacy bytes")
	}
	if err := s.append(second); !errors.Is(err, errEvidenceFull) {
		t.Fatalf("record cap: %v", err)
	}
	s.maxRecords = 2
	s.maxBytes = s.size
	if err := s.append(second); !errors.Is(err, errEvidenceFull) {
		t.Fatalf("byte cap: %v", err)
	}
	controller, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.acknowledge(controller, spoolTestAck(t, private, second)); err == nil {
		t.Fatal("accepted acknowledgement for a different sequence")
	}
	path := filepath.Join(dir, recordName(first.Sequence))
	if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.acknowledge(controller, spoolTestAck(t, private, first)); err == nil || s.acknowledged != 0 {
		t.Fatal("corrupt record was acknowledged")
	}
	s.close()
	if s, err := openEvidenceSpool(dir, minEvidenceCap, 1, public, receipt); err == nil {
		s.close()
		t.Fatal("corruption hidden on restart")
	}
}

func TestSpoolCommandAcknowledgesOnlyVerifiedHead(t *testing.T) {
	store, stateDir, i, receipt := admittedStore(t)
	cfg := testServiceConfig(t, stateDir)
	configPath := filepath.Join(t.TempDir(), "service.json")
	writeJSON(t, configPath, cfg)
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "ack.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, i.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		t.Fatal(err)
	}
	envelopes := make([]contracts.EvidenceEnvelopeV1, 2)
	for index := range envelopes {
		e, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		envelopes[index] = e
		if err := spool.append(e); err != nil {
			t.Fatal(err)
		}
	}
	spool.close()
	store.close()
	for _, e := range envelopes {
		var out bytes.Buffer
		if err := runSpoolCommand(configPath, "", false, nil, &out); err != nil {
			t.Fatal(err)
		}
		expected, _ := json.Marshal(e)
		if !bytes.Equal(out.Bytes(), append(expected, '\n')) {
			t.Fatal("spool command changed original bytes or order")
		}
		ack, _ := json.Marshal(spoolTestAck(t, key, e))
		if err := runSpoolCommand(configPath, keyPath, true, bytes.NewReader(ack), io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if err := runSpoolCommand(configPath, "", false, nil, io.Discard); err == nil {
		t.Fatal("retired record was redelivered")
	}
}
