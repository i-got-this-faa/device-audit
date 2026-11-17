//go:build linux

package mesh

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/networking/relay"
	"github.com/i-got-this-faa/device-audit/networking/relay/relaytest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// udpBlockedOptIn runs the relay phase with real blocked UDP instead of the
// upstream TS_DEBUG_ALWAYS_USE_DERP knob. Only infra/networking/run-relay-fallback.sh
// sets it, inside a fresh network namespace whose nftables drop all output UDP.
const udpBlockedOptIn = "DEVICE_AUDIT_RELAY_UDP_BLOCKED"

type scopedRelay struct {
	relay  *relay.Relay
	region *tailcfg.DERPRegion
	caFile string
	done   chan error
}

// deployScopedRelay starts the production relay package on loopback with a
// certificate trusted only through the children's SSL_CERT_FILE. The region has
// no InsecureForTests: children verify the selected certificate like production.
func deployScopedRelay(t *testing.T, admitted ...string) *scopedRelay {
	t.Helper()
	dir := t.TempDir()
	ca := relaytest.NewCA(t, dir)
	cert, k := ca.Valid(t, dir, relaytest.Hostname)
	nodeKey, admission := filepath.Join(dir, "relay.key"), filepath.Join(dir, "admission.json")
	if err := relay.InitializeNodeKey(nodeKey); err != nil {
		t.Fatal(err)
	}
	relaytest.WriteAdmission(t, admission, admitted...)
	r, err := relay.New(relay.Config{Hostname: relaytest.Hostname, CertFile: cert, KeyFile: k, NodeKeyFile: nodeKey, AdmissionFile: admission})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &scopedRelay{relay: r, caFile: ca.File, done: make(chan error, 1),
		region: relay.Region(900, relaytest.Hostname, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "")}
	go func() { s.done <- r.Serve(ln) }()
	t.Cleanup(func() { s.close(t) })
	if _, err := DecodeRegion(mustJSON(t, s.region)); err != nil {
		t.Fatal("generated production region rejected by the mesh adapter")
	}
	return s
}

func (s *scopedRelay) close(t *testing.T) {
	if s.relay == nil {
		return
	}
	s.relay.Close()
	if err := <-s.done; err != nil {
		t.Errorf("relay serve: %v", err)
	}
	s.relay = nil
}

func TestScopedRelayDirectAndRelayDelivery(t *testing.T) {
	blocked := os.Getenv(udpBlockedOptIn) == "1"
	dir := filepath.Join(t.TempDir(), "server")
	if err := InitializeServer(dir); err != nil {
		t.Fatal(err)
	}
	pin, err := ServerPublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	admitted, relayOnly, controllerOnly := key.NewNode(), key.NewNode(), key.NewNode()
	r := deployScopedRelay(t, pin, admitted.Public().UntypedHexString(), relayOnly.Public().UntypedHexString())
	controllerAllowed := admitted.Public().UntypedHexString() + "," + controllerOnly.Public().UntypedHexString()
	trust := "SSL_CERT_FILE=" + r.caFile

	if !blocked {
		s := meshProcess(t, transportConfig{Server: true, State: dir, Allowed: controllerAllowed, Region: r.region, CheckRelay: true}, trust)
		ready := s.read(t)
		if !ready.Ready || ready.RelayErr != "" {
			t.Fatalf("controller relay preflight failed with the selected certificate: %q", ready.RelayErr)
		}
		c := meshProcess(t, transportConfig{Region: r.region, Address: ready.Address, Pin: pin, Private: admitted, CheckRelay: true}, trust)
		direct := c.read(t)
		c.wait(t)
		if direct.RelayErr != "" || !direct.Direct || direct.Status != 204 {
			t.Fatalf("direct delivery through the configured relay map failed: %+v", direct)
		}
		stopProcess(t, s)
		t.Log("direct: trusted relay preflight passed; admitted peer delivered over direct UDP with HTTP 204")
	}

	// Relay phase. Without the namespace opt-in, the upstream knob makes both
	// peers refuse UDP so every packet must cross the scoped relay.
	env := []string{trust}
	if !blocked {
		env = append(env, "TS_DEBUG_ALWAYS_USE_DERP=1")
	}
	s := meshProcess(t, transportConfig{Server: true, State: dir, Allowed: controllerAllowed, Region: r.region, CheckRelay: true}, env...)
	ready := s.read(t)
	if !ready.Ready || ready.RelayErr != "" {
		t.Fatalf("controller relay preflight failed: %q", ready.RelayErr)
	}
	before := r.relay.Counters()
	c := meshProcess(t, transportConfig{Region: r.region, Address: ready.Address, Pin: pin, Private: admitted, Relay: true, CheckRelay: true}, env...)
	relayed := c.read(t)
	c.wait(t)
	after := r.relay.Counters()
	if relayed.RelayErr != "" || !relayed.Relay || relayed.RegionID == 0 || relayed.Status != 204 {
		t.Fatalf("relay delivery failed: %+v", relayed)
	}
	if after.OtherPackets <= before.OtherPackets || after.DiscoPackets <= before.DiscoPackets {
		t.Fatalf("relay counters do not show relayed WireGuard traffic: before %+v after %+v", before, after)
	}
	t.Logf("relay: admitted peer delivered over the configured DERP region (Tailcat local ID %d) with HTTP 204; relay non-disco packets %d -> %d", relayed.RegionID, before.OtherPackets, after.OtherPackets)

	// Relay admission grants no controller access.
	bad := meshProcess(t, transportConfig{Region: r.region, Address: ready.Address, Pin: pin, Private: relayOnly, Relay: true, CheckRelay: true, Denied: true}, env...)
	denied := bad.read(t)
	bad.wait(t)
	if denied.RelayErr != "" || denied.Status != 403 {
		t.Fatalf("relay-admitted but controller-unknown peer: %+v", denied)
	}
	// A controller-admitted key missing from relay admission is refused visibly.
	bad = meshProcess(t, transportConfig{Region: r.region, Address: ready.Address, Pin: pin, Private: controllerOnly, Relay: true, CheckRelay: true, Denied: true}, env...)
	denied = bad.read(t)
	bad.wait(t)
	if !strings.Contains(denied.RelayErr, ErrRelayUnavailable.Error()) || denied.Status != 403 {
		t.Fatalf("relay admission was not enforced visibly: %+v", denied)
	}
	t.Log("relay: relay-only key denied by controller; relay-unadmitted key reported relay failure and was not delivered")

	// The relay endpoint becomes invalid: the preflight reports it and the
	// request fails instead of using another path or weaker authentication.
	r.close(t)
	bad = meshProcess(t, transportConfig{Region: r.region, Address: ready.Address, Pin: pin, Private: admitted, Relay: true, CheckRelay: true, Denied: true}, env...)
	denied = bad.read(t)
	bad.wait(t)
	if !strings.Contains(denied.RelayErr, ErrRelayUnavailable.Error()) || denied.Status != 403 {
		t.Fatalf("unreachable relay did not fail visibly: %+v", denied)
	}
	stopProcess(t, s)
	t.Log("invalid endpoint: closed relay reported by preflight; no delivery")
	if blocked {
		if drops := udpDrops(t); drops == 0 {
			t.Fatal("namespace firewall did not drop any UDP")
		} else {
			t.Logf("udp-blocked: namespace nftables dropped %d output UDP packets", drops)
		}
	}
}

// An impostor relay on the configured name with a certificate from an
// untrusted issuer is rejected by both peers' TLS verification.
func TestScopedRelayUntrustedCertificateFailsVisibly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "server")
	if err := InitializeServer(dir); err != nil {
		t.Fatal(err)
	}
	pin, err := ServerPublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	admitted := key.NewNode()
	trusted := deployScopedRelay(t, pin, admitted.Public().UntypedHexString())
	impostor := deployScopedRelay(t, pin, admitted.Public().UntypedHexString())
	trust := "SSL_CERT_FILE=" + trusted.caFile
	s := meshProcess(t, transportConfig{Server: true, State: dir, Allowed: admitted.Public().UntypedHexString(), Region: impostor.region, CheckRelay: true}, trust)
	ready := s.read(t)
	if !strings.Contains(ready.RelayErr, ErrRelayUnavailable.Error()) {
		t.Fatalf("controller accepted an untrusted relay certificate: %q", ready.RelayErr)
	}
	c := meshProcess(t, transportConfig{Region: impostor.region, Address: ready.Address, Pin: pin, Private: admitted, Relay: true, CheckRelay: true, Denied: true}, trust)
	denied := c.read(t)
	c.wait(t)
	if !strings.Contains(denied.RelayErr, ErrRelayUnavailable.Error()) || denied.Status != 403 {
		t.Fatalf("endpoint accepted an untrusted relay certificate: %+v", denied)
	}
	stopProcess(t, s)
	// The test-only exception cannot be applied to the production name.
	weakened := *impostor.region.Nodes[0]
	weakened.InsecureForTests = true
	if validateDERP(DERPConfig{Region: &tailcfg.DERPRegion{RegionID: 900, Nodes: []*tailcfg.DERPNode{&weakened}}}) == nil {
		t.Fatal("TLS verification could be disabled for a non-loopback relay name")
	}
}

func stopProcess(t *testing.T, p *transportProcess) {
	t.Helper()
	if p.in.Encode(true) != nil {
		t.Fatal("stop pipe failed")
	}
	p.wait(t)
}

func udpDrops(t *testing.T) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", "device_audit_relay").Output()
	if err != nil {
		t.Fatal("cannot inspect namespace UDP-drop rule")
	}
	m := regexp.MustCompile(`meta l4proto udp counter packets (\d+)`).FindSubmatch(out)
	if m == nil {
		t.Fatal("namespace UDP-drop counter missing")
	}
	n, _ := strconv.ParseUint(string(m[1]), 10, 64)
	return n
}
