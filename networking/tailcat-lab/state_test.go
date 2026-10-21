package lab

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	server, client := filepath.Join(dir, "server.json"), filepath.Join(dir, "client.json")
	if err := InitializeServer(server); err != nil {
		t.Fatal(err)
	}
	if err := InitializeClient(client); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeServer(server); err == nil {
		t.Fatal("initialization overwrote identity")
	}
	after, err := os.ReadFile(server)
	if err != nil || string(before) != string(after) {
		t.Fatal("identity changed")
	}
	s, err := loadServer(server)
	if err != nil {
		t.Fatal(err)
	}
	c, err := loadClient(client)
	if err != nil {
		t.Fatal(err)
	}
	if s.Node.Public() == c.Node.Public() {
		t.Fatal("network identities are shared")
	}

	cases := []struct {
		name    string
		data    []byte
		mode    os.FileMode
		symlink bool
	}{
		{name: "missing"},
		{name: "corrupt", data: []byte(`{"version":1,"node":"SECRET_BAD_KEY"}`), mode: 0600},
		{name: "zero_node", data: []byte(`{"version":1}`), mode: 0600},
		{name: "missing_psk", data: mustJSON(t, s.ClientState), mode: 0600},
		{name: "bad_version", data: mustJSON(t, ServerState{ClientState: ClientState{Version: 2, Node: s.Node}, PSK: s.PSK}), mode: 0600},
		{name: "trailing", data: append(append([]byte(nil), before...), []byte("{}")...), mode: 0600},
		{name: "unknown_field", data: append([]byte(`{"unexpected":true,`), before[1:]...), mode: 0600},
		{name: "public_permissions", data: before, mode: 0644},
		{name: "symlink", symlink: true},
		{name: "oversized", data: make([]byte, 4097), mode: 0600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if tc.symlink {
				if err := os.Symlink(server, path); err != nil {
					t.Fatal(err)
				}
			} else if tc.data != nil {
				if err := os.WriteFile(path, tc.data, tc.mode); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := StartServer(context.Background(), path, c.Node.Public(), testRegion()); err == nil {
				t.Fatal("started with invalid server state")
			}
			if tc.name != "missing_psk" { // client files intentionally have no server PSK
				if _, err := loadClient(path); err == nil {
					t.Fatal("loaded invalid client state")
				}
			}
			if tc.name == "missing" {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("missing identity regenerated")
				}
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal("encode fixture failed")
	}
	return b
}

func testRegion() *tailcfg.DERPRegion {
	return &tailcfg.DERPRegion{RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "lab1", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: 443, STUNPort: -1, InsecureForTests: true}}}
}

func TestBootstrapConfigurationFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	if err := InitializeClient(path); err != nil {
		t.Fatal(err)
	}
	state := tailcat.NewPrivateKey()
	state.Public.Region = []*tailcfg.DERPRegion{testRegion()}
	if _, err := NewClient(path, state.Public.Addr(), state.Private.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(path, state.Public.Addr(), key.NewNode().Public()); err == nil {
		t.Fatal("accepted wrong server key pin")
	}
	state.Public.PresharedKey = tailcat.PresharedKey{}
	if _, err := NewClient(path, state.Public.Addr(), state.Private.Public()); err == nil {
		t.Fatal("accepted missing PSK")
	}
	if _, err := StartServer(context.Background(), "missing", key.NodePublic{}, testRegion()); err == nil {
		t.Fatal("accepted empty admission")
	}
	for _, region := range []*tailcfg.DERPRegion{nil, {}, {RegionID: 1, Nodes: []*tailcfg.DERPNode{nil}}} {
		if localRegion(region) {
			t.Fatal("accepted missing or default relay")
		}
	}
	region := testRegion()
	region.Nodes[0].IPv4 = "192.0.2.1"
	if localRegion(region) {
		t.Fatal("accepted remote relay")
	}
}
