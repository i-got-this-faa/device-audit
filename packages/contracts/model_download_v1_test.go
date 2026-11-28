package contracts

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestModelDownloadV1Fixture(t *testing.T) {
	data, err := os.ReadFile("fixtures/models/download-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var metadata ModelDownloadV1
	if err := json.Unmarshal(data, &metadata); err != nil {
		t.Fatal(err)
	}
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}

	for name, field := range map[string]string{
		"missing": "", "null": `"deployment_id": null,`,
		"unknown":   `"other": "synthetic-deployment",`,
		"duplicate": `"deployment_id": "synthetic-deployment", "deployment_id": "other",`,
	} {
		t.Run(name, func(t *testing.T) {
			payload := strings.Replace(string(data), `"deployment_id": "synthetic-deployment",`, field, 1)
			if err := json.Unmarshal([]byte(payload), &metadata); err == nil {
				t.Fatal("accepted malformed metadata")
			}
		})
	}
}
