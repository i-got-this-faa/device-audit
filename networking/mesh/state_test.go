package mesh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistedServerState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "server")
	if err := InitializeServer(dir); err != nil {
		t.Fatal(err)
	}
	first, err := ServerPublicKey(dir)
	if err != nil || len(first) != 64 {
		t.Fatal("persisted public key missing")
	}
	again, err := ServerPublicKey(dir)
	if err != nil || again != first {
		t.Fatal("persisted public key changed")
	}
	if err := InitializeServer(dir); err == nil {
		t.Fatal("existing mesh identity was reprovisioned")
	}
	held, release, err := loadServerState(dir)
	if err != nil || held.Node.IsZero() || held.PSK.IsZero() {
		t.Fatal("locked state did not reload")
	}
	if _, _, err := loadServerState(dir); err == nil {
		release()
		t.Fatal("second owner accepted")
	}
	release()
	const address = "mesh-address-fixture"
	if err := WriteAddress(dir, address); err != nil || WriteAddress(dir, address) != nil {
		t.Fatal("matching private address was rejected")
	}
	if err := WriteAddress(dir, address+"-other"); err == nil {
		t.Fatal("changed mesh address accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "server.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadServerState(dir); err == nil {
		t.Fatal("corrupt mesh state accepted")
	}
}
