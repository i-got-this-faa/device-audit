package contracts

import (
	"encoding/json"
	"os"
	"testing"
)

func TestInventoryV1Vectors(t *testing.T) {
	data, err := os.ReadFile("fixtures/inventory/v1-vectors.json")
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
			var value interface{ Validate() error } = &InventoryUpdateV1{}
			if version.SchemaVersion == InventoryRecordV1Version {
				value = &InventoryRecordV1{}
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

func TestInventoryStrictJSON(t *testing.T) {
	for _, wire := range []string{
		`{"schema_version":"device-audit.inventory-update.v1","device_id":"a","device_id":"b"}`,
		`{"schema_version":"device-audit.inventory-update.v1","Device_id":"a"}`,
		`{"schema_version":"device-audit.inventory-update.v1"} {}`,
	} {
		var update InventoryUpdateV1
		if err := json.Unmarshal([]byte(wire), &update); err == nil {
			t.Fatal("accepted ambiguous or incomplete wire")
		}
	}
}
