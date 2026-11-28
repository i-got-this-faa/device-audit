package contracts

import (
	"strings"
	"testing"
	"time"
)

func TestPredictionHistoryRecordValidation(t *testing.T) {
	asOf := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	expires := asOf.Add(time.Hour)
	prob := 0.25
	horizon := uint32(168)
	modelDigest := strings.Repeat("a", 64)
	evDigest := strings.Repeat("b", 64)
	reqDigest := strings.Repeat("c", 64)
	policyDigest := strings.Repeat("d", 64)
	evalDigest := strings.Repeat("e", 64)

	validKnown := PredictionHistoryRecordV1{
		ID:           1,
		AsOf:         asOf,
		RecordedAt:   asOf.Add(time.Second),
		ExpiresAt:    &expires,
		RulesVersion: "health-rules.v1",
		RuleReason:   "model_healthy_with_sufficient_baseline",
		ModelStatus:  "healthy",
		ModelProvenance: &PredictionModelProvenanceV1{
			Version: "baseline.v1", SHA256: modelDigest,
			PolicyVersion: "ml05.v1", PolicySHA256: policyDigest, EvaluationSHA256: evalDigest,
		},
		Evidence: &PredictionEvidenceRefV1{
			Sequence: 2, CollectedAt: asOf.Add(-5 * time.Minute), ReceivedAt: asOf.Add(-4 * time.Minute),
			PayloadSHA256: evDigest, RequestSHA256: reqDigest, Source: "endpoint", TelemetrySchemaVersion: TelemetryV2Version,
		},
		Features: PredictionFeatureRefV1{
			FeatureVersion: FeatureVersionHDDSMART7DV1, WindowStart: "2026-11-22", WindowEnd: "2026-11-28",
			Status: FeatureStatusComplete, FeatureCount: 6, SamplesRead: 7, LastSequence: 2,
		},
		FaultBaseline: PredictionFaultBaselineRefV1{
			Current:         PredictionFaultWindowRefV1{From: asOf.AddDate(0, 0, -6), To: asOf, Days: 7, SampledDays: 7, Sufficient: true},
			Baseline:        PredictionFaultWindowRefV1{From: asOf.AddDate(0, 0, -27), To: asOf.AddDate(0, 0, -6), Days: 21, SampledDays: 21, Sufficient: true},
			ObservationNote: "ok", SamplesRead: 28, LastSequence: 2,
		},
		Health: HealthV2{Status: "healthy", Probability: &prob, ProbabilityUnit: "probability", HorizonHours: &horizon},
		Prediction: &PredictionV2{
			SchemaVersion: PredictionV2Version,
			DeviceID:      "device:a",
			Model:         &ModelReferenceV2{Version: "baseline.v1", SHA256: modelDigest},
			Evidence:      &EvidenceV2{Digest: evDigest, TelemetrySchemaVersion: TelemetryV2Version},
			GeneratedAt:   asOf,
			ExpiresAt:     expires,
			Health:        HealthV2{Status: "healthy", Probability: &prob, ProbabilityUnit: "probability", HorizonHours: &horizon},
			Forecasts:     []FaultForecastV2{},
		},
	}
	if err := validKnown.Validate("device:a"); err != nil {
		t.Fatalf("valid known record rejected: %v", err)
	}
	if err := validKnown.Validate("device:b"); err == nil {
		t.Fatal("cross-device prediction accepted")
	}

	noEvidence := validKnown
	noEvidence.ExpiresAt = nil
	noEvidence.Evidence = nil
	noEvidence.Prediction = nil
	noEvidence.Features.Status = FeatureStatusIncomplete
	noEvidence.Health = HealthV2{Status: "unknown", ProbabilityUnit: "probability", UnknownReason: "insufficient_evidence"}
	if err := noEvidence.Validate("device:a"); err != nil {
		t.Fatalf("valid no-evidence unknown record rejected: %v", err)
	}

	noEvidenceStale := noEvidence
	noEvidenceStale.Health.UnknownReason = "stale_evidence"
	if err := noEvidenceStale.Validate("device:a"); err == nil {
		t.Fatal("stale_evidence without evidence accepted")
	}

	mismatchedDigest := validKnown
	mismatchedDigest.Prediction = &PredictionV2{
		SchemaVersion: PredictionV2Version,
		DeviceID:      "device:a",
		Model:         &ModelReferenceV2{Version: "baseline.v1", SHA256: modelDigest},
		Evidence:      &EvidenceV2{Digest: strings.Repeat("f", 64), TelemetrySchemaVersion: TelemetryV2Version},
		GeneratedAt:   asOf,
		ExpiresAt:     expires,
		Health:        validKnown.Health,
		Forecasts:     []FaultForecastV2{},
	}
	if err := mismatchedDigest.Validate("device:a"); err == nil {
		t.Fatal("broken evidence digest match accepted")
	}

	badModelStatus := validKnown
	badModelStatus.ModelStatus = "invented"
	if err := badModelStatus.Validate("device:a"); err == nil {
		t.Fatal("invalid model_status accepted")
	}
}
