package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
)

func TestPrintRegionIsAcceptedByMesh(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--print-region", "--hostname", "relay.example.org", "--port", "443", "--region-id", "900"}, &out); err != nil {
		t.Fatal(err)
	}
	r, err := mesh.DecodeRegion(out.Bytes())
	if err != nil || r.RegionID != 900 || r.Nodes[0].HostName != "relay.example.org" || r.Nodes[0].STUNPort != -1 || r.Nodes[0].InsecureForTests {
		t.Fatalf("printed region unusable: %v", err)
	}
	for _, args := range [][]string{
		{"--print-region", "--hostname", "203.0.113.7"},
		{"--print-region", "--hostname", "relay.example.org", "--port", "0"},
		{"--print-region", "--hostname", ""},
		{"--print-region", "--hostname", "relay.example.org", "--region-id", "0"},
	} {
		if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestInitKeyIsExclusiveAndServeRequiresConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.key")
	if err := run(context.Background(), []string{"--init-key", "--key-file", path}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"--init-key", "--key-file", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("relay key overwritten")
	}
	if err := run(context.Background(), []string{"--key-file", path, "--listen", "127.0.0.1:0"}, &bytes.Buffer{}); err == nil {
		t.Fatal("relay started without certificate, hostname and admission")
	}
}
