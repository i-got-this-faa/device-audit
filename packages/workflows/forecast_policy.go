package workflows

import (
	"sort"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	// ForecastDiagnosticPolicyVersion versions the forecast-to-probe mapping,
	// the probability threshold and the bounds below.
	ForecastDiagnosticPolicyVersion = "device-audit.forecast-diagnostic-policy.v1"
	// ForecastDiagnosticMinProbability is the lowest per-category fault forecast
	// probability that launches a diagnostic. Health assessments launch by status.
	ForecastDiagnosticMinProbability = 0.5

	forecastStorageComponent     = "storage:disk-0"
	forecastErrorsLookback       = uint32(3600)
	forecastErrorsMaxEntries     = uint32(64)
	forecastDiagnosticExpiresSec = uint32(3600)
)

// ForecastDiagnosticPlan is one bounded, read-only probe a forecast calls for.
type ForecastDiagnosticPlan struct {
	Category         string
	Probability      float64
	HorizonHours     uint32
	ProbeID          string
	Arguments        contracts.DiagnosticArgumentsV1
	Budget           contracts.DiagnosticBudgetV1
	ExpiresInSeconds uint32
}

// ForecastDiagnosticProbe returns the health-specific probe and bounds for a
// forecast category. A storage forecast reads storage health; every other
// category reads a bounded window of system error digests. The forecast does
// not name a disk, so storage always reads the first OS disk. Only the two
// allowlisted read-only probes are ever selected.
func ForecastDiagnosticProbe(category string) (string, contracts.DiagnosticArgumentsV1, contracts.DiagnosticBudgetV1, bool) {
	switch category {
	case "storage":
		component := forecastStorageComponent
		return contracts.DiagnosticProbeStorageHealthV1, contracts.DiagnosticArgumentsV1{ComponentID: &component},
			contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 65536}, true
	case "cpu", "gpu", "memory", "battery", "thermal", "network":
		lookback, entries := forecastErrorsLookback, forecastErrorsMaxEntries
		return contracts.DiagnosticProbeSystemErrorsV1, contracts.DiagnosticArgumentsV1{LookbackSeconds: &lookback, MaxEntries: &entries},
			contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 262144}, true
	}
	return "", contracts.DiagnosticArgumentsV1{}, contracts.DiagnosticBudgetV1{}, false
}

// PlanForecastDiagnostics returns the probes an available forecast calls for,
// strongest first, ties by category name. At most one plan is made per category.
//
//   - A degraded or critical health assessment from a hard-drive SMART model
//     (FeatureVersionHDDSMART7DV1) with a known probability and horizon calls
//     for a storage health probe. The model is a drive-failure model, so its
//     health is a storage forecast. Unknown and healthy assessments call for
//     nothing.
//   - Any per-category fault forecast at or above minProbability calls for the
//     probe mapped to its category. A category with no mapped probe is dropped.
//
// The caller has already established that the forecast is fresh and evaluated.
func PlanForecastDiagnostics(h *contracts.HealthV2, featureVersion string, forecasts []contracts.FaultForecastV2, minProbability float64) []ForecastDiagnosticPlan {
	best := map[string]contracts.FaultForecastV2{}
	keep := func(f contracts.FaultForecastV2) {
		if cur, ok := best[f.Category]; !ok || f.Probability > cur.Probability {
			best[f.Category] = f
		}
	}
	if h != nil && featureVersion == contracts.FeatureVersionHDDSMART7DV1 && (h.Status == "degraded" || h.Status == "critical") &&
		h.Probability != nil && h.HorizonHours != nil && *h.HorizonHours > 0 && h.ProbabilityUnit == "probability" {
		keep(contracts.FaultForecastV2{Category: "storage", Probability: *h.Probability, ProbabilityUnit: "probability", HorizonHours: *h.HorizonHours})
	}
	for _, f := range forecasts {
		if f.ProbabilityUnit == "probability" && f.Probability >= minProbability && f.HorizonHours > 0 {
			keep(f)
		}
	}
	plans := make([]ForecastDiagnosticPlan, 0, len(best))
	for category, f := range best {
		probe, args, budget, ok := ForecastDiagnosticProbe(category)
		if !ok {
			continue
		}
		plans = append(plans, ForecastDiagnosticPlan{Category: category, Probability: f.Probability, HorizonHours: f.HorizonHours,
			ProbeID: probe, Arguments: args, Budget: budget, ExpiresInSeconds: forecastDiagnosticExpiresSec})
	}
	sort.Slice(plans, func(i, j int) bool {
		if plans[i].Probability != plans[j].Probability {
			return plans[i].Probability > plans[j].Probability
		}
		return plans[i].Category < plans[j].Category
	})
	return plans
}
