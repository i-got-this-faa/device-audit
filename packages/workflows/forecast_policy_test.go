package workflows

import (
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func floatPtr(v float64) *float64 { return &v }
func uintPtr(v uint32) *uint32    { return &v }

func TestPlanForecastDiagnosticsMapsOnlyEvaluatedStorageRiskAndAllowlistedProbes(t *testing.T) {
	degraded := &contracts.HealthV2{Status: "degraded", Probability: floatPtr(0.8), ProbabilityUnit: "probability", HorizonHours: uintPtr(168)}
	plans := PlanForecastDiagnostics(degraded, contracts.FeatureVersionHDDSMART7DV1, nil, ForecastDiagnosticMinProbability)
	if len(plans) != 1 || plans[0].Category != "storage" || plans[0].ProbeID != contracts.DiagnosticProbeStorageHealthV1 || plans[0].HorizonHours != 168 ||
		plans[0].Arguments.ValidateFor(plans[0].ProbeID) != nil || plans[0].Budget.WallSeconds < 1 || plans[0].ExpiresInSeconds < plans[0].Budget.WallSeconds {
		t.Fatalf("degraded storage plan: %+v", plans)
	}

	for name, h := range map[string]*contracts.HealthV2{
		"nil":      nil,
		"healthy":  {Status: "healthy", Probability: floatPtr(0.9), ProbabilityUnit: "probability", HorizonHours: uintPtr(168)},
		"unknown":  {Status: "unknown", ProbabilityUnit: "probability", UnknownReason: "stale_evidence"},
		"no_prob":  {Status: "degraded", ProbabilityUnit: "probability", HorizonHours: uintPtr(168)},
		"no_hours": {Status: "critical", Probability: floatPtr(0.9), ProbabilityUnit: "probability"},
		"bad_unit": {Status: "critical", Probability: floatPtr(0.9), ProbabilityUnit: "percent", HorizonHours: uintPtr(168)},
	} {
		if plans := PlanForecastDiagnostics(h, contracts.FeatureVersionHDDSMART7DV1, nil, ForecastDiagnosticMinProbability); len(plans) != 0 {
			t.Fatalf("%s health planned work: %+v", name, plans)
		}
	}
	// A model that is not a drive-failure model says nothing about storage.
	if plans := PlanForecastDiagnostics(degraded, "other-features.v1", nil, ForecastDiagnosticMinProbability); len(plans) != 0 {
		t.Fatalf("unrelated model planned storage work: %+v", plans)
	}

	forecasts := []contracts.FaultForecastV2{
		{Category: "memory", Probability: 0.6, ProbabilityUnit: "probability", HorizonHours: 24},
		{Category: "memory", Probability: 0.7, ProbabilityUnit: "probability", HorizonHours: 48},
		{Category: "thermal", Probability: 0.4, ProbabilityUnit: "probability", HorizonHours: 24},
		{Category: "network", Probability: 0.9, ProbabilityUnit: "probability", HorizonHours: 12},
		{Category: "storage", Probability: 0.95, ProbabilityUnit: "probability", HorizonHours: 72},
		{Category: "unmapped", Probability: 1, ProbabilityUnit: "probability", HorizonHours: 12},
	}
	plans = PlanForecastDiagnostics(degraded, contracts.FeatureVersionHDDSMART7DV1, forecasts, ForecastDiagnosticMinProbability)
	var got []string
	for _, p := range plans {
		got = append(got, p.Category+"/"+p.ProbeID)
		if p.ProbeID != contracts.DiagnosticProbeStorageHealthV1 && p.ProbeID != contracts.DiagnosticProbeSystemErrorsV1 {
			t.Fatalf("plan selected a probe outside the allowlist: %+v", p)
		}
		if p.Arguments.ValidateFor(p.ProbeID) != nil {
			t.Fatalf("plan arguments are not valid for their probe: %+v", p)
		}
	}
	want := []string{"storage/storage_health.v1", "network/system_errors.v1", "memory/system_errors.v1"}
	if len(got) != len(want) {
		t.Fatalf("plans = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plans = %v, want %v", got, want)
		}
	}
	if plans[0].Probability != 0.95 || plans[0].HorizonHours != 72 || plans[2].Probability != 0.7 {
		t.Fatalf("strongest forecast per category not kept: %+v", plans)
	}
}
