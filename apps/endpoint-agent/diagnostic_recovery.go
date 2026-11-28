package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

const (
	activeDiagnosticJob  = "diagnostic-active.json"
	retiredDiagnosticJob = "diagnostic-acknowledged.json"
)

type diagnosticClaim struct {
	AssignmentSHA256 string    `json:"assignment_sha256"`
	BootID           string    `json:"boot_id"`
	AdmittedAt       time.Time `json:"admitted_at"`
	ResultSequence   uint64    `json:"result_sequence"`
}

// One managed job owns its reserved sequence until an authenticated controller
// accepts the exact terminal envelope. Evidence files outlive this outbox slot.
type diagnosticJob struct {
	diagnosticClaim
	Assignment contracts.DiagnosticAssignmentV1 `json:"assignment"`
	StartedAt  time.Time                        `json:"started_at"`
	Result     json.RawMessage                  `json:"result,omitempty"`
}

func (s *identityStore) requireNoDiagnosticJob() error {
	_, err := s.root.Lstat(activeDiagnosticJob)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("the managed diagnostic outbox requires service delivery")
}

func (s *identityStore) saveDiagnosticJob(job *diagnosticJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return s.replace(activeDiagnosticJob, activeDiagnosticJob+".tmp", checksummed(data))
}

func (s *identityStore) finishDiagnosticJob(job *diagnosticJob, result contracts.DiagnosticResultV1) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	job.Result = data
	return s.saveDiagnosticJob(job)
}

func (s *identityStore) loadDiagnosticJob(authority, deviceKey ed25519.PublicKey, receipt contracts.EnrollmentAcceptedV1) (*diagnosticJob, error) {
	data, err := s.read(activeDiagnosticJob)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var job diagnosticJob
	body, valid := verifyChecksum(data)
	if !valid || json.Unmarshal(body, &job) != nil {
		return nil, workflows.ErrAssignmentCorrupt
	}
	a := job.Assignment
	if a.VerifySignature(authority) != nil || a.DeploymentID != receipt.DeploymentID || a.DeviceID != receipt.DeviceID ||
		job.ResultSequence < contracts.FirstEvidenceSequenceV1 || job.ResultSequence > contracts.MaxEnvelopeSequence ||
		job.AdmittedAt.IsZero() || job.BootID == "" {
		return nil, workflows.ErrAssignmentCorrupt
	}
	message, _ := a.SigningBytes()
	digest, _ := contracts.EnvelopeRequestSHA256V1(message, a.Signature)
	if job.AssignmentSHA256 != digest {
		return nil, workflows.ErrAssignmentCorrupt
	}
	if len(job.Result) != 0 {
		result, err := job.result()
		if err != nil || result.VerifySignature(deviceKey) != nil || s.verifyDiagnosticEvidence(result) != nil {
			return nil, workflows.ErrAssignmentCorrupt
		}
	}
	// A crash after committing the job but before committing its replay
	// marker leaves a recoverable job. Repair the marker before retirement.
	name := fmt.Sprintf("diagnostic-%x.claim", sha256.Sum256([]byte(a.AssignmentID)))
	claim, err := s.read(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := s.saveDiagnosticClaim(name, job.diagnosticClaim); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		expected, _ := json.Marshal(job.diagnosticClaim)
		body, valid := verifyChecksum(claim)
		if !valid || !bytes.Equal(body, expected) {
			return nil, workflows.ErrAssignmentCorrupt
		}
	}
	return &job, nil
}

func (job *diagnosticJob) result() (contracts.DiagnosticResultV1, error) {
	var result contracts.DiagnosticResultV1
	if json.Unmarshal(job.Result, &result) != nil || result.CheckAssignment(job.Assignment) != nil ||
		result.Sequence != job.ResultSequence || result.BootID != job.BootID {
		return result, workflows.ErrAssignmentCorrupt
	}
	return result, nil
}

func (s *identityStore) verifyDiagnosticEvidence(result contracts.DiagnosticResultV1) error {
	expected := fmt.Sprintf("diagnostic-%x", sha256.Sum256([]byte(result.AssignmentID)))
	for _, ref := range result.Evidence {
		if ref.ReferenceID != expected {
			return workflows.ErrAssignmentCorrupt
		}
		data, err := s.readBounded(ref.ReferenceID+".evidence", int64(ref.SizeBytes))
		if err != nil || len(data) != int(ref.SizeBytes) || fmt.Sprintf("%x", sha256.Sum256(data)) != ref.SHA256 {
			return workflows.ErrAssignmentCorrupt
		}
	}
	return nil
}

func (job *diagnosticJob) expired(now time.Time) bool {
	deadline, _ := time.Parse(time.RFC3339, job.Assignment.ExpiresAt)
	if !now.Before(deadline.Add(workflows.DiagnosticReportingWindow)) {
		return true
	}
	if len(job.Result) == 0 {
		return false
	}
	result, err := job.result()
	if err != nil {
		return false
	}
	expires, _ := time.Parse(time.RFC3339, result.ExpiresAt)
	return !now.Before(expires)
}
