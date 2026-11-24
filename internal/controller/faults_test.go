package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// ML10 #106 over real PostgreSQL: persisted log references become fault
// reports, sampled days become coverage, and the windows exclude rows after
// asOf, before the baseline and from other devices.
func TestDeviceFaultHistoryReadsPersistedEvidence(t *testing.T) {
	b := newEnrollmentTestBed(t)
	for _, id := range []string{"device:a", "device:b", "device:new"} {
		token := b.issue(t, id)
		keys := newEnrollmentKeys(t)
		b.submit(t, token, admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys), http.StatusCreated)
	}
	asOf := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)
	day := func(offset int) time.Time { return time.Date(2026, 11, 24, 6, 0, 0, 0, time.UTC).AddDate(0, 0, offset) }
	ref := func(label string, at time.Time) contracts.LogReferenceV2 {
		sum := sha256.Sum256([]byte(label))
		return contracts.LogReferenceV2{ReferenceID: "errors:" + label, SHA256: hex.EncodeToString(sum[:]), ByteSize: 512, WindowStart: at.Add(-time.Minute), WindowEnd: at}
	}
	sequences := map[string]int{}
	insert := func(device string, collected time.Time, refs ...contracts.LogReferenceV2) {
		t.Helper()
		if refs == nil {
			refs = []contracts.LogReferenceV2{}
		}
		sequences[device]++
		payload, err := json.Marshal(contracts.TelemetryV2{SchemaVersion: contracts.TelemetryV2Version, DeviceID: device, CollectedAt: collected,
			Source: "endpoint", LogReferences: refs})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.db.Exec(`INSERT INTO device_evidence (deployment_id, device_id, sequence, envelope, payload_bytes, request_sha256, collected_at, received_at)
			VALUES ($1,$2,$3,'{}',$4,decode($5,'hex'),$6,$7)`, b.repo.deploymentID, device, sequences[device]+1, payload, strings.Repeat("ab", 32), collected, collected.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	// device:a has a sample on each of the 28 days. "disk" is reported in the
	// baseline and again today; "burst" once, then re-sent by the next sample.
	for offset := -27; offset <= 0; offset++ {
		switch offset {
		case -20:
			insert("device:a", day(offset), ref("disk-1", day(offset)))
		case -2:
			insert("device:a", day(offset), ref("burst", day(offset)))
		case -1:
			insert("device:a", day(offset), ref("burst", day(-2)))
		case 0:
			insert("device:a", day(offset), ref("disk-2", day(offset)))
		default:
			insert("device:a", day(offset))
		}
	}
	insert("device:a", asOf.Add(time.Microsecond), ref("future", asOf)) // after asOf
	insert("device:a", day(-28), ref("too-old", day(-28)))              // before the baseline
	insert("device:b", day(-1), ref("other-device", day(-1)))

	got, err := b.repo.DeviceFaultHistory(context.Background(), "device:a", asOf)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentID != b.repo.deploymentID || got.SamplesRead != 28 || got.LastSequence != 29 {
		t.Fatalf("provenance %+v", got)
	}
	h := got.History
	if !h.Current.Sufficient || !h.Baseline.Sufficient || h.Current.SampledDays != 7 || h.Baseline.SampledDays != 21 {
		t.Fatalf("windows %+v / %+v", h.Current, h.Baseline)
	}
	if len(h.Faults) != 1 || h.Faults[0].Type != FaultTypeUnclassified {
		t.Fatalf("faults %+v", h.Faults)
	}
	f := h.Faults[0]
	// disk-1 in the baseline; burst and disk-2 today; burst re-sent once.
	if f.Recurrence != health.FaultRecurrent || f.CurrentReports != 2 || f.BaselineReports != 1 || f.DuplicateReports != 1 || len(f.Evidence) != 3 {
		t.Fatalf("comparison %+v", f)
	}
	for _, e := range f.Evidence {
		if e.ReportedAt.After(asOf) || e.ReportedAt.Before(h.Baseline.From) {
			t.Fatalf("read evidence outside the windows: %+v", e)
		}
	}

	// A device enrolled with one week of samples: one report is not isolated.
	for offset := -6; offset <= 0; offset++ {
		if offset == -3 {
			insert("device:new", day(offset), ref("new-1", day(offset)))
		} else {
			insert("device:new", day(offset))
		}
	}
	fresh, err := b.repo.DeviceFaultHistory(context.Background(), "device:new", asOf)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.History.Baseline.Sufficient || len(fresh.History.Faults) != 1 || fresh.History.Faults[0].Recurrence != health.FaultInsufficientHistory ||
		fresh.History.Faults[0].CountChange != health.FaultCountUnknown {
		t.Fatalf("missing history was read as a baseline: %+v", fresh.History)
	}

	if _, err := b.repo.DeviceFaultHistory(context.Background(), "device:unknown", asOf); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
}
