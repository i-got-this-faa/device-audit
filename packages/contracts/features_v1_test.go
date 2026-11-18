package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
)

type featureFixture struct {
	Name        string          `json:"name"`
	Payload     json.RawMessage `json:"payload"`
	SchemaValid bool            `json:"schema_valid"`
	Valid       bool            `json:"valid"`
	Rejection   *string         `json:"rejection"`
	Expected    json.RawMessage `json:"expected"`
}

func loadFeatureFixtures(t *testing.T) []featureFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "features", "v1-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		SchemaVersion  string           `json:"schema_version"`
		FeatureVersion string           `json:"feature_version"`
		Tolerance      float64          `json:"tolerance"`
		Vectors        []featureFixture `json:"vectors"`
	}
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	if collection.SchemaVersion != "device-audit.feature-fixtures.v1" || collection.FeatureVersion != FeatureVersionHDDSMART7DV1 ||
		collection.Tolerance != FeatureTolerance || len(collection.Vectors) == 0 {
		t.Fatal("missing or incompatible feature fixtures")
	}
	return collection.Vectors
}

func strictFeatureDecode(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// readFeatureFixture returns the computed vector for a window, nil for a vector payload.
func readFeatureFixture(payload []byte) (*FeatureVectorV1, error) {
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return nil, err
	}
	switch header.SchemaVersion {
	case FeatureWindowV1Version:
		var window FeatureWindowV1
		if err := strictFeatureDecode(payload, &window); err != nil {
			return nil, err
		}
		vector, err := window.Features()
		return &vector, err
	case FeatureVectorV1Version:
		var vector FeatureVectorV1
		if err := strictFeatureDecode(payload, &vector); err != nil {
			return nil, err
		}
		return nil, vector.Validate()
	}
	return nil, fmt.Errorf("unknown fixture schema %q", header.SchemaVersion)
}

func featureVectorsClose(got, want FeatureVectorV1) error {
	strip := func(v FeatureVectorV1) FeatureVectorV1 {
		v.Features = append([]FeatureValueV1(nil), v.Features...)
		for i := range v.Features {
			v.Features[i].Value = nil
		}
		return v
	}
	a, _ := json.Marshal(strip(got))
	b, _ := json.Marshal(strip(want))
	if !bytes.Equal(a, b) {
		return fmt.Errorf("vector shape differs:\n got %s\nwant %s", a, b)
	}
	for i, w := range want.Features {
		g := got.Features[i]
		if (g.Value == nil) != (w.Value == nil) {
			return fmt.Errorf("%s known state differs", w.Name)
		}
		if w.Value != nil && math.Abs(*g.Value-*w.Value) > FeatureTolerance+FeatureTolerance*math.Abs(*w.Value) {
			return fmt.Errorf("%s = %.17g, want %.17g within %g", w.Name, *g.Value, *w.Value, FeatureTolerance)
		}
	}
	return nil
}

func TestFeatureV1Vectors(t *testing.T) {
	for _, v := range loadFeatureFixtures(t) {
		t.Run(v.Name, func(t *testing.T) {
			got, err := readFeatureFixture(v.Payload)
			if (err == nil) != v.Valid {
				t.Fatalf("valid = %t, want %t (error: %v)", err == nil, v.Valid, err)
			}
			if err != nil {
				rejection := "invalid_contract"
				if errors.Is(err, ErrUnsupportedFeatureVersion) {
					rejection = "unsupported_feature_version"
				}
				if v.Rejection == nil || *v.Rejection != rejection {
					t.Fatalf("rejection = %s, want %v (error: %v)", rejection, v.Rejection, err)
				}
				return
			}
			if got == nil {
				return
			}
			var want FeatureVectorV1
			if err := strictFeatureDecode(v.Expected, &want); err != nil {
				t.Fatalf("expected vector: %v", err)
			}
			if err := want.Validate(); err != nil {
				t.Fatalf("expected vector is invalid: %v", err)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("computed vector is invalid: %v", err)
			}
			if err := featureVectorsClose(*got, want); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFeatureWindowV1SampleBound(t *testing.T) {
	zero := int64(0)
	window := FeatureWindowV1{SchemaVersion: FeatureWindowV1Version, FeatureVersion: FeatureVersionHDDSMART7DV1, AsOf: "2013-11-07T23:59:59Z"}
	for i := 0; i < MaxFeatureSamples; i++ {
		at := fmt.Sprintf("2013-11-%02dT%02d:%02d:00Z", 1+i/1440, i/60%24, i%60)
		window.Samples = append(window.Samples, FeatureSampleV1{ObservedAt: at, SMART5Raw: &zero, SMART9Raw: &zero, SMART197Raw: &zero})
	}
	vector, err := window.Features()
	if err != nil || vector.Status != FeatureStatusComplete {
		t.Fatalf("bounded window: status %q, error %v", vector.Status, err)
	}
	window.Samples = append(window.Samples, FeatureSampleV1{ObservedAt: "2013-10-31T00:00:00Z"})
	if err := window.Validate(); err == nil {
		t.Fatal("accepted more than MaxFeatureSamples samples")
	}
}

func TestFeatureNamesV1RejectsUnknownVersion(t *testing.T) {
	names, units, err := FeatureNamesV1(FeatureVersionHDDSMART7DV1)
	if err != nil || len(names) != 6 || names[0] != "smart_5_raw.last" || units[3] != "signed_log1p_hours" {
		t.Fatalf("names %v units %v error %v", names, units, err)
	}
	if _, _, err := FeatureNamesV1("hdd-smart-7d.v2"); !errors.Is(err, ErrUnsupportedFeatureVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
}
