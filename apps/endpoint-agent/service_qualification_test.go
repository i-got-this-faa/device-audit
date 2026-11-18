package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// qualificationVerification is what the harness writes after checking the
// evidence the installed service signed.
type qualificationVerification struct {
	DeploymentID      string `json:"deployment_id"`
	SigningKeyID      string `json:"signing_key_id"`
	Envelopes         int    `json:"envelopes"`
	FirstSequence     uint64 `json:"first_sequence"`
	LastSequence      uint64 `json:"last_sequence"`
	SequenceGaps      int    `json:"sequence_gaps"`
	FirstIssuedAt     string `json:"first_issued_at"`
	LastIssuedAt      string `json:"last_issued_at"`
	KnownCPUSnapshots int    `json:"snapshots_with_cpu_value"`
}

// TestServiceQualificationHarness is the controller side of
// tools/service/Invoke-ServiceQualification.ps1. It serves the real enrollment
// handlers from a disposable PostgreSQL database, issues one bootstrap token at
// the repository boundary (no OIDC login), waits for the elevated script, then
// verifies every envelope the installed service signed against the key the
// controller committed. It runs only when both variables are set.
func TestServiceQualificationHarness(t *testing.T) {
	dir, configured := os.Getenv("DEVICE_AUDIT_SERVICE_QUALIFICATION_DIR"), os.Getenv("TEST_DATABASE_URL")
	if dir == "" || configured == "" {
		t.Skip("DEVICE_AUDIT_SERVICE_QUALIFICATION_DIR and TEST_DATABASE_URL are not set")
	}
	const device = "device:service-qualification"
	done := filepath.Join(dir, "evidence", "qualification-done")
	// A marker left by an earlier run would release the wait at once.
	if _, err := os.Stat(done); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the harness directory holds a previous run; use an empty directory")
	}
	server, ca, repo, db := postgresEnrollment(t, configured, "deployment:service-qualification")
	token, err := repo.IssueBootstrapToken(context.Background(), contracts.BootstrapTokenRequestV1{SchemaVersion: contracts.BootstrapTokenRequestV1Version, DeviceID: device}, "https://id.example.test", "admin:service-qualification")
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(dir, "bootstrap.json"), token)
	if os.WriteFile(filepath.Join(dir, "ca.pem"), pem, 0o600) != nil || os.WriteFile(filepath.Join(dir, "origin.txt"), []byte(server.URL), 0o600) != nil {
		t.Fatal("write harness files")
	}
	t.Logf("enrollment ready at %s; bootstrap expires %s", server.URL, token.ExpiresAt)
	waitFor(t, "the elevated qualification script", 45*time.Minute, func() bool {
		_, err := os.Stat(done)
		return err == nil
	})

	var signingKeyID string
	var public []byte
	if err := db.QueryRow(`SELECT signing_key_id, public_key FROM device_enrollments WHERE device_id=$1`, device).Scan(&signingKeyID, &public); err != nil {
		t.Fatal("the service did not commit an enrollment")
	}
	evidence := filepath.Join(dir, "evidence")
	files, err := os.ReadDir(evidence)
	if err != nil {
		t.Fatal(err)
	}
	result := qualificationVerification{DeploymentID: token.DeploymentID, SigningKeyID: signingKeyID}
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "spool-") || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(evidence, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var envelope contracts.EvidenceEnvelopeV1
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatalf("envelope %d: %v", result.Envelopes+1, err)
		}
		if err := envelope.VerifySignature(ed25519.PublicKey(public)); err != nil {
			t.Fatalf("envelope %d does not verify with the committed key: %v", result.Envelopes+1, err)
		}
		if envelope.DeploymentID != token.DeploymentID || envelope.DeviceID != device || envelope.SigningKeyID != signingKeyID {
			t.Fatalf("envelope %d is bound to another identity", result.Envelopes+1)
		}
		if result.Envelopes > 0 && envelope.Sequence <= result.LastSequence {
			t.Fatalf("sequence %d follows %d", envelope.Sequence, result.LastSequence)
		}
		if result.Envelopes == 0 {
			result.FirstSequence, result.FirstIssuedAt = envelope.Sequence, envelope.IssuedAt
		} else if envelope.Sequence != result.LastSequence+1 {
			result.SequenceGaps++
		}
		result.LastSequence, result.LastIssuedAt = envelope.Sequence, envelope.IssuedAt
		result.Envelopes++
		if cpuValue(t, envelope) != nil {
			result.KnownCPUSnapshots++
		}
	}
	if result.Envelopes == 0 {
		t.Fatal(errors.New("the service signed no evidence"))
	}
	writeJSON(t, filepath.Join(dir, "verification.json"), result)
	t.Logf("verified %+v", result)
}
