package health

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// ErrIncompleteFeatures means a counter has no value on some window day. A model
// must not read the vector; the caller reports an unknown prediction instead.
var ErrIncompleteFeatures = errors.New("feature vector is incomplete")

// SMARTReading is one endpoint observation of the CT03 SMART counters. Nil is
// not observed, never zero. No endpoint collector produces counters yet, so
// every reading built today comes from ReadingFromTelemetry and is all nil.
type SMARTReading struct {
	ObservedAt                        time.Time
	SMART5Raw, SMART9Raw, SMART197Raw *int64
}

// ReadingFromTelemetry is the endpoint's only source of readings today.
// Telemetry v2 has no SMART metric, and host uptime or disk_used_percent are not
// substitutes (features-v1.md), so every counter stays not observed.
func ReadingFromTelemetry(t contracts.TelemetryV2) SMARTReading {
	return SMARTReading{ObservedAt: t.CollectedAt}
}

// ReadingFromHistory is the controller's counterpart of ReadingFromTelemetry for
// a persisted sample. History keeps telemetry v2 metrics, which hold no SMART
// counter, so the reading is all nil for the same reason.
func ReadingFromHistory(s contracts.HistorySampleV1) SMARTReading {
	return SMARTReading{ObservedAt: s.CollectedAt}
}

// Preprocess returns the frozen feature vector for what the endpoint held at
// asOf. The contract caps a window at 10,080 samples, far fewer than a 15 s
// sampler yields in seven days, so this keeps only each counter's latest
// reading per UTC day. That is exactly the value rule 3 of features-v1.md picks,
// so the vector is the same. A reading after asOf is never read. A tie between
// readings of one counter at the same instant goes to the later one in the slice.
func Preprocess(asOf time.Time, readings []SMARTReading) (contracts.FeatureVectorV1, error) {
	asOf = asOf.UTC()
	asOfSecond := asOf.Truncate(time.Second)
	end := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -(contracts.FeatureWindowDays - 1))

	type pick struct {
		at    time.Time
		value int64
		ok    bool
	}
	var latest [3][contracts.FeatureWindowDays]pick
	for _, r := range readings {
		at := r.ObservedAt.UTC()
		if at.Before(start) || at.After(asOf) {
			continue
		}
		day := int(at.Truncate(time.Second).Sub(start) / (24 * time.Hour))
		for i, v := range [3]*int64{r.SMART5Raw, r.SMART9Raw, r.SMART197Raw} {
			if v != nil && (!latest[i][day].ok || !at.Before(latest[i][day].at)) {
				latest[i][day] = pick{at, *v, true}
			}
		}
	}

	// One sample per observed second; each holds the counters picked at it.
	bySecond := map[time.Time]*contracts.FeatureSampleV1{}
	for i := range latest {
		for _, p := range latest[i] {
			if !p.ok {
				continue
			}
			second := p.at.Truncate(time.Second)
			sample := bySecond[second]
			if sample == nil {
				sample = &contracts.FeatureSampleV1{ObservedAt: second.Format(time.RFC3339)}
				bySecond[second] = sample
			}
			value := p.value
			*[3]**int64{&sample.SMART5Raw, &sample.SMART9Raw, &sample.SMART197Raw}[i] = &value
		}
	}
	samples := make([]contracts.FeatureSampleV1, 0, len(bySecond))
	for _, s := range bySecond {
		samples = append(samples, *s)
	}
	slices.SortFunc(samples, func(a, b contracts.FeatureSampleV1) int { return strings.Compare(a.ObservedAt, b.ObservedAt) })

	vector, err := contracts.FeatureWindowV1{
		SchemaVersion:  contracts.FeatureWindowV1Version,
		FeatureVersion: contracts.FeatureVersionHDDSMART7DV1,
		AsOf:           asOfSecond.Format(time.RFC3339),
		Samples:        samples,
	}.Features()
	if err != nil {
		return contracts.FeatureVectorV1{}, fmt.Errorf("preprocess features: %w", err)
	}
	return vector, nil
}

// ModelInput returns the ordered values a model may read. Only a vector that
// validates and is complete qualifies.
func ModelInput(v contracts.FeatureVectorV1) ([]float64, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	if v.Status != contracts.FeatureStatusComplete {
		return nil, ErrIncompleteFeatures
	}
	values := make([]float64, len(v.Features))
	for i, f := range v.Features {
		values[i] = *f.Value
	}
	return values, nil
}
