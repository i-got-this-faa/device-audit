package contracts

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// CT03 #32 freezes one feature version. Training, endpoint and controller
// preprocessing must produce the same vector from the same window; see
// features-v1.md for the rules and fixtures/features for the shared vectors.
const (
	FeatureWindowV1Version = "device-audit.feature-window.v1"
	FeatureVectorV1Version = "device-audit.feature-vector.v1"
	// FeatureVersionHDDSMART7DV1 is the ML01 SMART counter set over seven UTC days.
	FeatureVersionHDDSMART7DV1 = "hdd-smart-7d.v1"

	FeatureWindowDays = 7
	// MaxFeatureSamples allows one sample per minute for the whole window.
	MaxFeatureSamples = 10080
	// MaxFeatureCounter is the largest integer both JSON readers keep exactly.
	MaxFeatureCounter = 1<<53 - 1
	// FeatureTolerance bounds |go - other| <= tol + tol*|other| for each value.
	FeatureTolerance = 1e-12

	FeatureStatusComplete   = "complete"
	FeatureStatusIncomplete = "incomplete"

	FeatureMissingNoObservation     = "no_observation"
	FeatureMissingIncompleteHistory = "incomplete_history"
)

// ErrUnsupportedFeatureVersion marks a well-formed request for a feature
// version this reader does not implement. Callers must not fall back.
var ErrUnsupportedFeatureVersion = errors.New("unsupported feature version")

// FeatureSampleV1 is one SMART counter reading. Null means not observed.
type FeatureSampleV1 struct {
	ObservedAt  string `json:"observed_at"`
	SMART5Raw   *int64 `json:"smart_5_raw"`
	SMART9Raw   *int64 `json:"smart_9_raw"`
	SMART197Raw *int64 `json:"smart_197_raw"`
}

// FeatureWindowV1 is the preprocessing input. Samples may be in any order and
// may extend past the window; only samples in [start of window, as_of] count.
type FeatureWindowV1 struct {
	SchemaVersion  string            `json:"schema_version"`
	FeatureVersion string            `json:"feature_version"`
	AsOf           string            `json:"as_of"`
	Samples        []FeatureSampleV1 `json:"samples"`
}

type FeatureValueV1 struct {
	Name          string   `json:"name"`
	Value         *float64 `json:"value"`
	Unit          string   `json:"unit"`
	MissingReason string   `json:"missing_reason,omitempty"`
}

// FeatureVectorV1 is the preprocessing output in the frozen feature order.
type FeatureVectorV1 struct {
	SchemaVersion  string           `json:"schema_version"`
	FeatureVersion string           `json:"feature_version"`
	AsOf           string           `json:"as_of"`
	WindowStart    string           `json:"window_start"`
	WindowEnd      string           `json:"window_end"`
	Status         string           `json:"status"`
	Features       []FeatureValueV1 `json:"features"`
}

type featureCounter struct {
	name, unit string
	read       func(FeatureSampleV1) *int64
}

// The array order is the frozen feature order: each counter yields .last then .delta.
var hddSMART7DCounters = [...]featureCounter{
	{"smart_5_raw", "count", func(s FeatureSampleV1) *int64 { return s.SMART5Raw }},
	{"smart_9_raw", "hours", func(s FeatureSampleV1) *int64 { return s.SMART9Raw }},
	{"smart_197_raw", "count", func(s FeatureSampleV1) *int64 { return s.SMART197Raw }},
}

// FeatureNamesV1 returns the frozen names and units for a feature version.
func FeatureNamesV1(featureVersion string) (names, units []string, err error) {
	if featureVersion != FeatureVersionHDDSMART7DV1 {
		return nil, nil, fmt.Errorf("%w %q", ErrUnsupportedFeatureVersion, featureVersion)
	}
	for _, c := range hddSMART7DCounters {
		names = append(names, c.name+".last", c.name+".delta")
		units = append(units, "log1p_"+c.unit, "signed_log1p_"+c.unit)
	}
	return names, units, nil
}

func (s *FeatureSampleV1) UnmarshalJSON(data []byte) error {
	type wire FeatureSampleV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"observed_at", "smart_5_raw", "smart_9_raw", "smart_197_raw"}, "smart_5_raw", "smart_9_raw", "smart_197_raw"); err != nil {
		return err
	}
	*s = FeatureSampleV1(v)
	return nil
}

func (w *FeatureWindowV1) UnmarshalJSON(data []byte) error {
	type wire FeatureWindowV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "feature_version", "as_of", "samples"}); err != nil {
		return err
	}
	*w = FeatureWindowV1(v)
	return nil
}

func (f *FeatureValueV1) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	required := []string{"name", "value", "unit"}
	if _, ok := fields["missing_reason"]; ok {
		required = append(required, "missing_reason")
	}
	type wire FeatureValueV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, required, "value"); err != nil {
		return err
	}
	*f = FeatureValueV1(v)
	return nil
}

func (v *FeatureVectorV1) UnmarshalJSON(data []byte) error {
	type wire FeatureVectorV1
	var w wire
	if err := decodeEnvelopeJSON(data, &w, []string{"schema_version", "feature_version", "as_of", "window_start", "window_end", "status", "features"}); err != nil {
		return err
	}
	*v = FeatureVectorV1(w)
	return nil
}

func (w FeatureWindowV1) Validate() error {
	if w.SchemaVersion != FeatureWindowV1Version {
		return fmt.Errorf("unsupported feature window schema %q", w.SchemaVersion)
	}
	if w.FeatureVersion != FeatureVersionHDDSMART7DV1 {
		return fmt.Errorf("%w %q", ErrUnsupportedFeatureVersion, w.FeatureVersion)
	}
	if _, err := parseEnvelopeTime(w.AsOf); err != nil {
		return fmt.Errorf("as_of: %w", err)
	}
	if w.Samples == nil || len(w.Samples) > MaxFeatureSamples {
		return fmt.Errorf("samples are required and limited to %d", MaxFeatureSamples)
	}
	seen := make(map[string]bool, len(w.Samples))
	for _, s := range w.Samples {
		if _, err := parseEnvelopeTime(s.ObservedAt); err != nil {
			return fmt.Errorf("observed_at: %w", err)
		}
		// The timestamp format is fixed, so equal instants have equal spelling.
		if seen[s.ObservedAt] {
			return fmt.Errorf("duplicate sample at %s", s.ObservedAt)
		}
		seen[s.ObservedAt] = true
		for _, c := range hddSMART7DCounters {
			if v := c.read(s); v != nil && (*v < 0 || *v > MaxFeatureCounter) {
				return fmt.Errorf("%s outside 0..%d", c.name, int64(MaxFeatureCounter))
			}
		}
	}
	return nil
}

// Features runs the frozen preprocessing. It never fills a missing counter.
func (w FeatureWindowV1) Features() (FeatureVectorV1, error) {
	if err := w.Validate(); err != nil {
		return FeatureVectorV1{}, err
	}
	asOf, _ := parseEnvelopeTime(w.AsOf)
	end := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -(FeatureWindowDays - 1))

	type reading struct {
		at    time.Time
		value int64
		ok    bool
	}
	var daily [len(hddSMART7DCounters)][FeatureWindowDays]reading
	for _, s := range w.Samples {
		at, _ := parseEnvelopeTime(s.ObservedAt)
		if at.Before(start) || at.After(asOf) {
			continue
		}
		day := int(at.Sub(start) / (24 * time.Hour))
		for i, c := range hddSMART7DCounters {
			// The latest non-null reading of each UTC day is that day's value.
			if v := c.read(s); v != nil && (!daily[i][day].ok || at.After(daily[i][day].at)) {
				daily[i][day] = reading{at, *v, true}
			}
		}
	}

	vector := FeatureVectorV1{
		SchemaVersion:  FeatureVectorV1Version,
		FeatureVersion: w.FeatureVersion,
		AsOf:           w.AsOf,
		WindowStart:    start.Format(time.DateOnly),
		WindowEnd:      end.Format(time.DateOnly),
		Status:         FeatureStatusComplete,
	}
	for i, c := range hddSMART7DCounters {
		observed := 0
		for _, r := range daily[i] {
			if r.ok {
				observed++
			}
		}
		last := FeatureValueV1{Name: c.name + ".last", Unit: "log1p_" + c.unit}
		delta := FeatureValueV1{Name: c.name + ".delta", Unit: "signed_log1p_" + c.unit}
		switch observed {
		case FeatureWindowDays:
			first, final := daily[i][0].value, daily[i][FeatureWindowDays-1].value
			lastValue, deltaValue := math.Log1p(float64(final)), signedLog1p(final-first)
			last.Value, delta.Value = &lastValue, &deltaValue
		case 0:
			last.MissingReason, delta.MissingReason = FeatureMissingNoObservation, FeatureMissingNoObservation
		default:
			last.MissingReason, delta.MissingReason = FeatureMissingIncompleteHistory, FeatureMissingIncompleteHistory
		}
		if last.Value == nil {
			vector.Status = FeatureStatusIncomplete
		}
		vector.Features = append(vector.Features, last, delta)
	}
	return vector, nil
}

// signedLog1p keeps the sign of a counter change; inputs stay within 2^53.
func signedLog1p(x int64) float64 {
	if x < 0 {
		return -math.Log1p(float64(-x))
	}
	return math.Log1p(float64(x))
}

func (v FeatureVectorV1) Validate() error {
	if v.SchemaVersion != FeatureVectorV1Version {
		return fmt.Errorf("unsupported feature vector schema %q", v.SchemaVersion)
	}
	names, units, err := FeatureNamesV1(v.FeatureVersion)
	if err != nil {
		return err
	}
	asOf, err := parseEnvelopeTime(v.AsOf)
	if err != nil {
		return fmt.Errorf("as_of: %w", err)
	}
	end := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	if v.WindowEnd != end.Format(time.DateOnly) || v.WindowStart != end.AddDate(0, 0, -(FeatureWindowDays-1)).Format(time.DateOnly) {
		return fmt.Errorf("window does not end on the as_of UTC day")
	}
	if len(v.Features) != len(names) {
		return fmt.Errorf("feature count %d, want %d", len(v.Features), len(names))
	}
	complete := true
	for i, f := range v.Features {
		if f.Name != names[i] || f.Unit != units[i] {
			return fmt.Errorf("feature %d is %s/%s, want %s/%s", i, f.Name, f.Unit, names[i], units[i])
		}
		if f.Value == nil {
			complete = false
			if f.MissingReason != FeatureMissingNoObservation && f.MissingReason != FeatureMissingIncompleteHistory {
				return fmt.Errorf("%s: null value needs a missing reason", f.Name)
			}
		} else if f.MissingReason != "" || math.IsNaN(*f.Value) || math.IsInf(*f.Value, 0) {
			return fmt.Errorf("%s: known value must be finite without a missing reason", f.Name)
		}
		// A counter's .last and .delta come from the same days, so they share a state.
		if i%2 == 1 && ((f.Value == nil) != (v.Features[i-1].Value == nil) || f.MissingReason != v.Features[i-1].MissingReason) {
			return fmt.Errorf("%s and %s disagree on missing state", v.Features[i-1].Name, f.Name)
		}
		if i%2 == 0 && f.Value != nil && *f.Value < 0 {
			return fmt.Errorf("%s cannot be negative", f.Name)
		}
	}
	if (v.Status == FeatureStatusComplete) != complete || (v.Status != FeatureStatusComplete && v.Status != FeatureStatusIncomplete) {
		return fmt.Errorf("status %q does not match the feature values", v.Status)
	}
	return nil
}
