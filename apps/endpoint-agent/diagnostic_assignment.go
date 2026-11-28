package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

func runAssignedProbe(stateDir, keyPath string, in io.Reader, out, errOut io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	result, err := executeDiagnosticAssignment(ctx, stateDir, keyPath, diagnosticBootID, workflows.NewProbeRunner(executeProbeWorker), in)
	if err != nil {
		fmt.Fprintf(errOut, "diagnostic result unavailable: %s\n", err)
		return 2
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		fmt.Fprintln(errOut, "write signed diagnostic result")
		return 1
	}
	if result.State == string(workflows.StatusSucceeded) {
		return 0
	}
	return 1
}

func executeDiagnosticAssignment(ctx context.Context, stateDir, keyPath string, bootID func() (string, error), runner *workflows.ProbeRunner, in io.Reader) (contracts.DiagnosticResultV1, error) {
	const maxAssignment = 16 << 10
	var assignment contracts.DiagnosticAssignmentV1
	data, err := io.ReadAll(io.LimitReader(in, maxAssignment+1))
	if err != nil || len(data) > maxAssignment || json.Unmarshal(data, &assignment) != nil {
		return contracts.DiagnosticResultV1{}, workflows.ErrAssignmentInvalid
	}
	key, err := loadControllerPublicKey(keyPath)
	if err != nil {
		return contracts.DiagnosticResultV1{}, err
	}
	store, err := openIdentityStore(stateDir, false)
	if err != nil {
		return contracts.DiagnosticResultV1{}, err
	}
	defer store.close()
	identity, receipt, err := store.admitted()
	if err != nil {
		return contracts.DiagnosticResultV1{}, err
	}
	defer clear(identity.signing)
	boot, err := bootID()
	if err != nil {
		return contracts.DiagnosticResultV1{}, err
	}
	if err := store.requireNoDiagnosticJob(); err != nil {
		return contracts.DiagnosticResultV1{}, err
	}
	return store.executeDiagnosticAssignment(ctx, runner, assignment, key, identity, receipt, boot, nil, nil)
}

func (s *identityStore) executeDiagnosticAssignment(ctx context.Context, runner *workflows.ProbeRunner, assignment contracts.DiagnosticAssignmentV1, authority ed25519.PublicKey, identity *identity, receipt contracts.EnrollmentAcceptedV1, bootID string, job *diagnosticJob, sequenceMu *sync.Mutex) (contracts.DiagnosticResultV1, error) {
	id := fmt.Sprintf("%x", sha256.Sum256([]byte(assignment.AssignmentID)))
	execution := workflows.AssignmentExecution{
		DeploymentID: receipt.DeploymentID,
		DeviceID:     receipt.DeviceID,
		BootID:       bootID,
		SigningKey:   identity.signing,
		Claim: func(digest string, admittedAt time.Time) (uint64, error) {
			if sequenceMu != nil {
				sequenceMu.Lock()
				defer sequenceMu.Unlock()
			}
			return s.claimDiagnosticAssignment(assignment, receipt, id, digest, bootID, admittedAt, job)
		},
		SaveEvidence: func(output []byte) (string, error) {
			ref := "diagnostic-" + id
			return ref, s.replace(ref+".evidence", ref+".evidence.tmp", output)
		},
	}
	if job != nil {
		execution.RecordStart = func(startedAt time.Time) error {
			job.StartedAt = startedAt
			return s.saveDiagnosticJob(job)
		}
	}
	result, err := workflows.ExecuteDiagnosticAssignment(ctx, runner, assignment, authority, execution)
	if err == nil && job != nil {
		err = s.finishDiagnosticJob(job, result)
	}
	return result, err
}

// Claim runs under the identity lock. The immutable assignment marker and
// controller high-water mark are both durable before a worker can start. A
// crash between writes can consume an assignment without running it.
func (s *identityStore) claimDiagnosticAssignment(a contracts.DiagnosticAssignmentV1, receipt contracts.EnrollmentAcceptedV1, id, digest, bootID string, admittedAt time.Time, job *diagnosticJob) (uint64, error) {
	claimFile := "diagnostic-" + id + ".claim"
	if _, err := s.root.Lstat(claimFile); err == nil {
		return 0, workflows.ErrAssignmentReplay
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, errors.New("inspect diagnostic claim")
	}
	watermark := "diagnostic-authority-" + strings.TrimPrefix(a.SigningKeyID, "ed25519:") + ".sequence"
	data, err := s.read(watermark)
	if errors.Is(err, os.ErrNotExist) && runtime.GOOS != "windows" {
		// Earlier builds used a colon, which is reserved in Windows paths.
		data, err = s.read("diagnostic-authority-" + a.SigningKeyID + ".sequence")
	}
	switch {
	case err == nil:
		body, valid := verifyChecksum(data)
		last, parseErr := strconv.ParseUint(string(body), 10, 64)
		if !valid || parseErr != nil || last == 0 || last > contracts.MaxEnvelopeSequence {
			return 0, workflows.ErrAssignmentCorrupt
		}
		if a.Sequence <= last {
			return 0, workflows.ErrAssignmentReplay
		}
	case !errors.Is(err, os.ErrNotExist):
		return 0, err
	}
	sequence, err := s.reserveSequence(receipt)
	if err != nil {
		return 0, err
	}
	claim := diagnosticClaim{digest, bootID, admittedAt, sequence}
	if err := s.replace(watermark, watermark+".tmp", checksummed([]byte(strconv.FormatUint(a.Sequence, 10)))); err != nil {
		return 0, err
	}
	if job != nil {
		job.Assignment, job.diagnosticClaim = a, claim
		if err := s.saveDiagnosticJob(job); err != nil {
			return 0, err
		}
	}
	return sequence, s.saveDiagnosticClaim(claimFile, claim)
}

func (s *identityStore) saveDiagnosticClaim(name string, claim diagnosticClaim) error {
	data, err := json.Marshal(claim)
	if err != nil {
		return err
	}
	return s.replace(name, name+".tmp", checksummed(data))
}
