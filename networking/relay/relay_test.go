package relay_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/networking/relay"
	"github.com/i-got-this-faa/device-audit/networking/relay/relaytest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fixture struct {
	dir, cert, key, nodeKey, admission string
	ca                                 *relaytest.CA
}

func newFixture(t *testing.T, admitted ...string) fixture {
	t.Helper()
	dir := t.TempDir()
	ca := relaytest.NewCA(t, dir)
	cert, k := ca.Valid(t, dir, relaytest.Hostname)
	f := fixture{dir: dir, cert: cert, key: k, nodeKey: filepath.Join(dir, "relay.key"), admission: filepath.Join(dir, "admission.json"), ca: ca}
	if err := relay.InitializeNodeKey(f.nodeKey); err != nil {
		t.Fatal(err)
	}
	if len(admitted) == 0 {
		admitted = []string{key.NewNode().Public().UntypedHexString()}
	}
	relaytest.WriteAdmission(t, f.admission, admitted...)
	return f
}

func (f fixture) config() relay.Config {
	return relay.Config{Hostname: relaytest.Hostname, CertFile: f.cert, KeyFile: f.key, NodeKeyFile: f.nodeKey, AdmissionFile: f.admission}
}

func start(t *testing.T, cfg relay.Config) (*relay.Relay, int) {
	t.Helper()
	r, err := relay.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Serve(ln) }()
	t.Cleanup(func() {
		r.Close()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return r, ln.Addr().(*net.TCPAddr).Port
}

// The test certificate is not in the system roots, so the in-process mesh
// check uses the loopback-only test exception. Trusted verification without
// that exception is exercised by the Linux mesh relay test.
func loopbackRegion(port int) mesh.DERPConfig {
	return mesh.DERPConfig{Region: &tailcfg.DERPRegion{RegionID: 900, Nodes: []*tailcfg.DERPNode{{Name: "900a", RegionID: 900, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: -1, InsecureForTests: true}}}}
}

func raw(k key.NodePrivate) []byte {
	text, _ := k.MarshalText()
	b, _ := hex.DecodeString(strings.TrimPrefix(string(text), "privkey:"))
	return b
}

func TestRelayConfigurationFailsClosed(t *testing.T) {
	f := newFixture(t)
	if err := relay.InitializeNodeKey(f.nodeKey); err == nil {
		t.Fatal("existing relay key was replaced")
	}
	otherCert, otherKey := f.ca.Valid(t, f.dir, "other.device-audit.test")
	expiredCert, expiredKey := f.ca.Issue(t, f.dir, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour), "expired.device-audit.test")
	bad := func(name string, edit func(*relay.Config)) {
		t.Helper()
		cfg := f.config()
		edit(&cfg)
		if r, err := relay.New(cfg); err == nil {
			r.Close()
			t.Fatalf("%s accepted", name)
		}
	}
	bad("missing hostname", func(c *relay.Config) { c.Hostname = "" })
	bad("IP hostname", func(c *relay.Config) { c.Hostname = "127.0.0.1" })
	bad("certificate for another host", func(c *relay.Config) { c.CertFile, c.KeyFile = otherCert, otherKey })
	bad("expired certificate", func(c *relay.Config) {
		c.Hostname, c.CertFile, c.KeyFile = "expired.device-audit.test", expiredCert, expiredKey
	})
	bad("not yet valid certificate", func(c *relay.Config) { c.Now = func() time.Time { return time.Now().Add(-24 * time.Hour) } })
	bad("mismatched key", func(c *relay.Config) { c.KeyFile = otherKey })
	bad("missing relay key", func(c *relay.Config) { c.NodeKeyFile = filepath.Join(f.dir, "absent") })
	bad("missing admission", func(c *relay.Config) { c.AdmissionFile = filepath.Join(f.dir, "absent") })
	if runtime.GOOS != "windows" {
		loose := filepath.Join(f.dir, "loose.key")
		data, _ := os.ReadFile(f.nodeKey)
		if err := os.WriteFile(loose, data, 0644); err != nil {
			t.Fatal(err)
		}
		bad("world-readable relay key", func(c *relay.Config) { c.NodeKeyFile = loose })
	}
	for name, body := range map[string]string{
		"wrong version": `{"version":"v0","network_public_keys":["` + key.NewNode().Public().UntypedHexString() + `"]}`,
		"unknown field": `{"version":"device-audit.relay-admission.v1","network_public_keys":["` + key.NewNode().Public().UntypedHexString() + `"],"allow_all":true}`,
		"empty":         `{"version":"device-audit.relay-admission.v1","network_public_keys":[]}`,
		"bad key":       `{"version":"device-audit.relay-admission.v1","network_public_keys":["not-a-key"]}`,
		"uppercase key": `{"version":"device-audit.relay-admission.v1","network_public_keys":["` + strings.ToUpper(key.NewNode().Public().UntypedHexString()) + `"]}`,
		"trailing data": `{"version":"device-audit.relay-admission.v1","network_public_keys":["` + key.NewNode().Public().UntypedHexString() + `"]} {}`,
	} {
		path := filepath.Join(f.dir, "admission-"+strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		bad("admission "+name, func(c *relay.Config) { c.AdmissionFile = path })
	}
}

func TestRelayServesOnlyDERPRoutesWithSelectedCertificate(t *testing.T) {
	f := newFixture(t)
	_, port := start(t, f.config())
	roots := x509.NewCertPool()
	pem, _ := os.ReadFile(f.ca.File)
	roots.AppendCertsFromPEM(pem)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: relaytest.Hostname}, ForceAttemptHTTP2: true}}
	base := "https://" + relaytest.Hostname
	for path, want := range map[string]int{"/derp/probe": 200, "/derp/latency-check": 200, "/generate_204": 204, "/": 404, "/debug/": 404, "/v1/evidence": 404, "/bootstrap/dns": 404} {
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s: status %d, want %d", path, resp.StatusCode, want)
		}
		if resp.ProtoMajor != 1 {
			t.Fatalf("%s: negotiated HTTP/%d; DERP requires HTTP/1.1", path, resp.ProtoMajor)
		}
	}
	// A client that does not trust the selected certificate's issuer fails.
	untrusted := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), ServerName: relaytest.Hostname}}}
	if resp, err := untrusted.Get(base + "/derp/probe"); err == nil {
		resp.Body.Close()
		t.Fatal("untrusted relay certificate accepted")
	}
	// Plain HTTP on the TLS port is not served.
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: dial}}
	if resp, err := plain.Get("http://" + relaytest.Hostname + "/derp/probe"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("plaintext DERP probe served")
		}
	}
}

func TestRelayAdmissionIsEnforcedAndReloaded(t *testing.T) {
	admitted, other := key.NewNode(), key.NewNode()
	f := newFixture(t, admitted.Public().UntypedHexString())
	r, port := start(t, f.config())
	if len(r.PublicKey()) != 64 {
		t.Fatal("relay public key missing")
	}
	ctx := context.Background()
	region := loopbackRegion(port)
	if err := mesh.CheckRelay(ctx, region, raw(admitted)); err != nil {
		t.Fatalf("admitted key rejected: %v", err)
	}
	if err := mesh.CheckRelay(ctx, region, raw(other)); !errors.Is(err, mesh.ErrRelayUnavailable) {
		t.Fatalf("unadmitted key not rejected visibly: %v", err)
	}
	// Revocation in the file applies to the next connection without restart.
	relaytest.WriteAdmission(t, f.admission, other.Public().UntypedHexString())
	if err := mesh.CheckRelay(ctx, region, raw(admitted)); !errors.Is(err, mesh.ErrRelayUnavailable) {
		t.Fatalf("removed key still admitted: %v", err)
	}
	if err := mesh.CheckRelay(ctx, region, raw(other)); err != nil {
		t.Fatalf("newly admitted key rejected: %v", err)
	}
	// A damaged admission file denies everyone instead of opening the relay.
	if err := os.WriteFile(f.admission, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := mesh.CheckRelay(ctx, region, raw(other)); !errors.Is(err, mesh.ErrRelayUnavailable) {
		t.Fatalf("corrupt admission file failed open: %v", err)
	}
}

func TestRelayKeyPersistsAcrossRestart(t *testing.T) {
	f := newFixture(t)
	first, err := relay.New(f.config())
	if err != nil {
		t.Fatal(err)
	}
	pub := first.PublicKey()
	first.Close()
	second, err := relay.New(f.config())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.PublicKey() != pub {
		t.Fatal("relay key changed across restart")
	}
}

func TestRegionMatchesMeshValidation(t *testing.T) {
	r := relay.Region(900, relaytest.Hostname, "", 443, "")
	if r.Nodes[0].STUNPort != -1 || r.Nodes[0].InsecureForTests || r.Nodes[0].DERPPort != 443 {
		t.Fatal("unexpected production region")
	}
	if err := mesh.CheckRelay(context.Background(), mesh.DERPConfig{Region: r}, nil); err == nil || errors.Is(err, mesh.ErrRelayUnavailable) {
		t.Fatal("missing identity must be rejected before any relay connection")
	}
}
