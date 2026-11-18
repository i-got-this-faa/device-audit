package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDeviceRevocationV1Vectors(t *testing.T) {
	data, err := os.ReadFile("fixtures/revocation/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalogue struct {
		Vectors []struct {
			Name    string
			Payload json.RawMessage
			Valid   bool
		}
	}
	if err := json.Unmarshal(data, &catalogue); err != nil {
		t.Fatal(err)
	}
	for _, v := range catalogue.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var version struct {
				SchemaVersion string `json:"schema_version"`
			}
			if err := json.Unmarshal(v.Payload, &version); err != nil {
				t.Fatal(err)
			}
			var value interface{ Validate() error } = &DeviceRevocationRequestV1{}
			if version.SchemaVersion == DeviceRevocationV1Version {
				value = &DeviceRevocationV1{}
			}
			err := json.Unmarshal(v.Payload, value)
			if err == nil {
				err = value.Validate()
			}
			if (err == nil) != v.Valid {
				t.Fatalf("valid=%v err=%v", v.Valid, err)
			}
		})
	}
}

func TestDeviceRevocationStrictJSON(t *testing.T) {
	for _, wire := range []string{
		`{"schema_version":"device-audit.device-revocation-request.v1","device_id":"a","device_id":"b","reason_reference":"r"}`,
		`{"schema_version":"device-audit.device-revocation-request.v1","Device_id":"a","reason_reference":"r"}`,
		`{"schema_version":"device-audit.device-revocation-request.v1","device_id":null,"reason_reference":"r"}`,
	} {
		var request DeviceRevocationRequestV1
		if err := json.Unmarshal([]byte(wire), &request); err == nil {
			t.Fatalf("accepted ambiguous or incomplete wire: %s", wire)
		}
	}
}
