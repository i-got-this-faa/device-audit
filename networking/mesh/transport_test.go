//go:build linux || darwin

package mesh

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type transportConfig struct {
	Server  bool
	State   string
	Allowed string
	Region  *tailcfg.DERPRegion
	Address string
	Pin     string
	Private key.NodePrivate
	Denied  bool
}
type transportReport struct {
	Address string
	Ready   bool
	Direct  bool
	Status  int
}

// Private configuration crosses anonymous pipes only. Each engine has its own process.
func TestTransportProcess(t *testing.T) {
	if os.Getenv("DEVICE_AUDIT_MESH_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	log.SetOutput(io.Discard)
	var cfg transportConfig
	in := json.NewDecoder(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	if in.Decode(&cfg) != nil {
		t.Fatal("private process configuration failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if cfg.Server {
		s, err := NewServer(ServerConfig{Context: ctx, StateDir: cfg.State, DERP: DERPConfig{Region: cfg.Region}, Allow: func(peer string) bool { return peer == cfg.Allowed }})
		if err != nil {
			t.Fatal("server startup failed: ", err)
		}
		defer s.Close()
		ln, err := s.Listen(ctx, "tcp", ":8080")
		if err != nil {
			t.Fatal("listen failed")
		}
		h := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
			if err != nil {
				w.WriteHeader(403)
				return
			}
			peer, err := s.PeerKey(remote)
			if err != nil || peer != cfg.Allowed {
				w.WriteHeader(403)
				return
			}
			w.WriteHeader(204)
		})}
		go h.Serve(ln)
		defer h.Close()
		if out.Encode(transportReport{Address: s.Addr(), Ready: true}) != nil {
			t.Fatal("private address pipe failed")
		}
		var stop bool
		_ = in.Decode(&stop)
		return
	}
	raw := cfg.Private.Raw32()
	c, err := NewClient(ClientConfig{NetworkPrivateKey: raw[:], ServerAddr: cfg.Address, ServerPublicKey: cfg.Pin, DERP: DERPConfig{Region: cfg.Region}})
	if err != nil {
		t.Fatal("client startup failed: ", err)
	}
	defer c.Close()
	if cfg.Denied {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		r, _ := http.NewRequestWithContext(ctx, "POST", "http://"+ApplicationHost+"/v1/evidence", nil)
		response, err := c.HTTPClient().Do(r)
		if err == nil {
			response.Body.Close()
			t.Fatal("unknown peer reached application")
		}
		_ = out.Encode(transportReport{Status: 403})
		return
	}
	for ctx.Err() == nil {
		probe, stop := context.WithTimeout(ctx, time.Second)
		result, err := c.(*client).node.DiscoPing(probe)
		stop()
		if err == nil && result.Endpoint != "" && result.DERPRegionID == 0 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("direct UDP path unavailable")
	}
	response, err := c.HTTPClient().Post("http://"+ApplicationHost+"/v1/evidence", "application/json", nil)
	if err != nil {
		t.Fatal("direct application request failed")
	}
	response.Body.Close()
	_ = out.Encode(transportReport{Direct: true, Status: response.StatusCode})
}

type transportProcess struct {
	cmd    *exec.Cmd
	in     *json.Encoder
	out    *bufio.Scanner
	waited bool
}

func meshProcess(t *testing.T, cfg transportConfig) *transportProcess {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestTransportProcess$", "-test.timeout=30s")
	cmd.Env = []string{"DEVICE_AUDIT_MESH_CHILD=1", "PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	p := &transportProcess{cmd: cmd, in: json.NewEncoder(in), out: bufio.NewScanner(out)}
	if cmd.Start() != nil {
		t.Fatal("start mesh process")
	}
	t.Cleanup(func() {
		if !p.waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	if p.in.Encode(cfg) != nil {
		t.Fatal("private configuration pipe")
	}
	return p
}
func (p *transportProcess) read(t *testing.T) transportReport {
	t.Helper()
	for p.out.Scan() {
		if len(p.out.Bytes()) > 0 && p.out.Bytes()[0] == '{' {
			var r transportReport
			if json.Unmarshal(p.out.Bytes(), &r) != nil {
				t.Fatal("invalid private report")
			}
			return r
		}
	}
	t.Fatal("mesh process failed; private output suppressed")
	return transportReport{}
}
func (p *transportProcess) wait(t *testing.T) {
	t.Helper()
	for p.out.Scan() {
	}
	p.waited = true
	if p.cmd.Wait() != nil {
		t.Fatal("mesh subprocess failed; private output suppressed")
	}
}

func TestPersistedAdmittedDirectTransport(t *testing.T) {
	d := derpserver.New(key.NewNode(), discardLog)
	defer d.Close()
	h := httptest.NewTLSServer(derpserver.Handler(d))
	defer h.Close()
	region := &tailcfg.DERPRegion{RegionID: 1, RegionCode: "private-test", Nodes: []*tailcfg.DERPNode{{Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: h.Listener.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	dir := filepath.Join(t.TempDir(), "server")
	if err := InitializeServer(dir); err != nil {
		t.Fatal(err)
	}
	pin, err := ServerPublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	admitted := key.NewNode()
	var address string
	for restart := 0; restart < 2; restart++ {
		s := meshProcess(t, transportConfig{Server: true, State: dir, Allowed: admitted.Public().UntypedHexString(), Region: region})
		r := s.read(t)
		if !r.Ready {
			t.Fatal("server readiness missing")
		}
		if restart > 0 && address != r.Address {
			t.Fatal("persisted server address changed")
		}
		address = r.Address
		c := meshProcess(t, transportConfig{Region: region, Address: address, Pin: pin, Private: admitted})
		result := c.read(t)
		c.wait(t)
		if !result.Direct || result.Status != 204 {
			t.Fatal("admitted direct HTTP request failed")
		}
		bad := meshProcess(t, transportConfig{Region: region, Address: address, Pin: pin, Private: key.NewNode(), Denied: true})
		denied := bad.read(t)
		bad.wait(t)
		if denied.Status != 403 {
			t.Fatal("unknown peer not rejected")
		}
		if s.in.Encode(true) != nil {
			t.Fatal("stop pipe failed")
		}
		s.wait(t)
		t.Logf("restart=%d: persisted identity, direct HTTP, peer binding, unknown-key rejection passed", restart)
	}
	if err := InitializeServer(dir); err == nil {
		t.Fatal("reprovisioned existing identity")
	}
	if err := os.WriteFile(filepath.Join(dir, "server.json"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadServerState(dir); err == nil {
		t.Fatal("corrupt identity accepted")
	}
}

func TestMeshConfigurationFailsClosed(t *testing.T) {
	if validateDERP(DERPConfig{AllowPublicRelays: true}) == nil {
		t.Fatal("public relay defaults accepted")
	}
	if _, err := NewClient(ClientConfig{}); err == nil {
		t.Fatal("missing key pin accepted")
	}
	if _, _, err := loadServerState(t.TempDir()); err == nil {
		t.Fatal("missing state accepted")
	}
}

func TestAdmissionLookupsBoundedBeforeAuthorization(t *testing.T) {
	d := derpserver.New(key.NewNode(), discardLog)
	defer d.Close()
	h := httptest.NewTLSServer(derpserver.Handler(d))
	defer h.Close()
	region := &tailcfg.DERPRegion{RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "test", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: h.Listener.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	dir := filepath.Join(t.TempDir(), "server")
	if err := InitializeServer(dir); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, maxConcurrentAdmissions)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	s, err := NewServer(ServerConfig{Context: context.Background(), StateDir: dir, DERP: DERPConfig{Region: region}, Allow: func(string) bool {
		entered <- struct{}{}
		<-release
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { unblock(); s.Close() }()
	allow := s.(*server).node.AllowClient
	results := make(chan bool, maxConcurrentAdmissions)
	for range maxConcurrentAdmissions {
		go func() { results <- allow(key.NewNode().Public()) }()
	}
	for range maxConcurrentAdmissions {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("admission lookup did not enter")
		}
	}
	saturated := make(chan bool, 1)
	go func() { saturated <- allow(key.NewNode().Public()) }()
	select {
	case allowed := <-saturated:
		if allowed {
			t.Fatal("saturated admission accepted a new key")
		}
	case <-time.After(time.Second):
		t.Fatal("saturated admission blocked instead of denying")
	}
	select {
	case <-entered:
		t.Fatal("saturated admission reached authorization storage")
	default:
	}
	unblock()
	for range maxConcurrentAdmissions {
		if !<-results {
			t.Fatal("in-flight authorized key was rejected")
		}
	}
	if !allow(key.NewNode().Public()) {
		t.Fatal("admission capacity was not released")
	}
}
