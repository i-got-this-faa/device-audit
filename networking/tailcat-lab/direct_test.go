package lab

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const labPort = 8087

// Child configuration is private local IPC, never test output or CLI arguments.
// Addr contains a PSK. Only its digest is included in published evidence.
type peerConfig struct {
	Role     string
	State    string
	Addr     tailcat.Addr
	Expected key.NodePublic
	Allowed  key.NodePublic
	Region   *tailcfg.DERPRegion
	Mode     string
}

type observation struct {
	Event         string  `json:"event"`
	PublicSHA256  string  `json:"public_sha256,omitempty"`
	AddressSHA256 string  `json:"address_sha256,omitempty"`
	Direct        bool    `json:"direct,omitempty"`
	EndpointClass string  `json:"endpoint_class,omitempty"`
	ElapsedMS     float64 `json:"elapsed_ms,omitempty"`
	RoundTrips    int     `json:"round_trips,omitempty"`
	PeerBound     bool    `json:"peer_bound,omitempty"`
	RXBytes       int64   `json:"rx_bytes,omitempty"`
	TXBytes       int64   `json:"tx_bytes,omitempty"`
	Accepted      int64   `json:"accepted,omitempty"`
	PeerCount     int     `json:"peer_count,omitempty"`
}

// TestLabPeer is invoked only as a fresh OS process by TestDirectLab.
// A single process owns its engine and persisted private node key.
func TestLabPeer(t *testing.T) {
	if os.Getenv("DEVICE_AUDIT_LAB_PEER") != "1" {
		t.Skip("subprocess entry point")
	}
	log.SetOutput(io.Discard)
	var cfg peerConfig
	in := json.NewDecoder(os.Stdin)
	if err := in.Decode(&cfg); err != nil {
		t.Fatal("invalid private configuration")
	}
	out := json.NewEncoder(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if cfg.Role == "server" {
		runServerPeer(t, ctx, cfg, in, out)
	} else if cfg.Role == "client" {
		runClientPeer(t, ctx, cfg, in, out)
	} else {
		t.Fatal("invalid role")
	}
}

func runServerPeer(t *testing.T, ctx context.Context, cfg peerConfig, in *json.Decoder, out *json.Encoder) {
	s, err := StartServer(ctx, cfg.State, cfg.Allowed, cfg.Region)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ln, err := s.Listen(ctx, "tcp", fmt.Sprintf(":%d", labPort))
	if err != nil {
		t.Fatal("Tailcat listener failed")
	}
	var accepted atomic.Int64
	var bound atomic.Bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(20 * time.Second))
				peer, ok := s.PeerKey(c.RemoteAddr())
				if !ok || peer != cfg.Allowed {
					return
				}
				bound.Store(true)
				// Fixed length fresh challenge, bounded exchange, no shell or forwarding.
				var challenge [32]byte
				for i := 0; i < 8; i++ {
					if _, err := io.ReadFull(c, challenge[:]); err != nil {
						return
					}
					reply := sha256.Sum256(challenge[:])
					if _, err := c.Write(reply[:]); err != nil {
						return
					}
				}
			}()
		}
	}()
	state, err := loadServer(cfg.State)
	if err != nil {
		t.Fatal(err)
	}
	addr := s.TailcatAddr()
	// The secret address is sent only through an anonymous pipe, before reports.
	if err := out.Encode(struct{ Address tailcat.Addr }{addr}); err != nil {
		t.Fatal("private bootstrap pipe failed")
	}
	emit(t, out, observation{Event: "server_ready", PublicSHA256: PublicDigest(state.Node.Public()), AddressSHA256: digest([]byte(addr))})
	for {
		var command string
		if err := in.Decode(&command); err != nil {
			return
		}
		switch command {
		case "snapshot":
			o := observation{Event: "server_snapshot", Accepted: accepted.Load(), PeerBound: bound.Load()}
			status := s.Status()
			o.PeerCount = len(status.Peer)
			for _, peer := range status.Peer {
				if peer.PublicKey == cfg.Allowed {
					o.Direct = peer.CurAddr != ""
					o.RXBytes = peer.RxBytes
					o.TXBytes = peer.TxBytes
				}
			}
			emit(t, out, o)
		case "disconnect":
			s.DisconnectClient(cfg.Allowed)
			emit(t, out, observation{Event: "disconnected"})
		case "stop":
			return
		default:
			t.Fatal("invalid command")
		}
	}
}

func runClientPeer(t *testing.T, ctx context.Context, cfg peerConfig, in *json.Decoder, out *json.Encoder) {
	start := time.Now()
	address := cfg.Addr
	if cfg.Mode == "wrong_psk" {
		info, err := tailcat.ParseAddr(address)
		if err != nil {
			t.Fatal("invalid private address")
		}
		info.PresharedKey = tailcat.NewPresharedKey()
		address = info.Addr()
	}
	c, err := NewClient(cfg.State, address, cfg.Expected)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if cfg.Mode != "" {
		timeout, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, pingErr := c.Ping(timeout)
		if cfg.Mode == "unknown" && pingErr == nil {
			t.Fatal("unknown network key passed admission")
		}
		if cfg.Mode == "wrong_psk" && pingErr != nil {
			t.Fatal("wrong-PSK discovery failed before handshake test")
		}
		dialCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		conn, err := c.DialTCPPort(dialCtx, labPort)
		if err == nil {
			conn.Close()
			t.Fatal("unauthorized client established application connection")
		}
		emit(t, out, observation{Event: cfg.Mode + "_refused", ElapsedMS: milliseconds(start)})
		return
	}
	var direct bool
	var endpointClass string
	for ctx.Err() == nil {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		result, err := c.DiscoPing(probe)
		cancel()
		if err == nil && result.Endpoint != "" && result.DERPRegionID == 0 {
			endpoint, parseErr := netip.ParseAddrPort(result.Endpoint)
			if parseErr != nil || !sameHostAddress(endpoint.Addr()) {
				t.Fatal("direct endpoint is not on this host")
			}
			endpointClass = "host-interface UDP"
			if endpoint.Addr().IsLoopback() {
				endpointClass = "loopback UDP"
			}
			direct = true
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !direct {
		t.Fatal("no direct UDP path observed before deadline")
	}
	// Establish WireGuard application traffic before removing the bootstrap.
	warmCtx, warmCancel := context.WithTimeout(ctx, 5*time.Second)
	warm, warmErr := c.DialTCPPort(warmCtx, labPort)
	warmCancel()
	if warmErr != nil {
		t.Fatal("application warmup dial failed")
	}
	if err := exchange(warm, 1); err != nil {
		warm.Close()
		t.Fatal(err)
	}
	warm.Close()
	emit(t, out, observation{Event: "direct_ready", PublicSHA256: PublicDigest(c.PublicKey()), Direct: true, EndpointClass: endpointClass, ElapsedMS: milliseconds(start)})
	var command string
	if err := in.Decode(&command); err != nil || command != "exchange" {
		t.Fatal("exchange command missing")
	}
	// Parent has closed the relay listener AND its existing hijacked DERP sockets.
	start = time.Now()
	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	defer dialCancel()
	conn, err := c.DialTCPPort(dialCtx, labPort)
	if err != nil {
		t.Fatal("direct application dial failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := exchange(conn, 8); err != nil {
		t.Fatal(err)
	}

	emit(t, out, observation{Event: "relay_off_exchange", Direct: true, RoundTrips: 8, ElapsedMS: milliseconds(start)})
}

func exchange(conn net.Conn, rounds int) error {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < rounds; i++ {
		var challenge [32]byte
		if _, err := rand.Read(challenge[:]); err != nil {
			return fmt.Errorf("random challenge failed")
		}
		expected := sha256.Sum256(challenge[:])
		if _, err := conn.Write(challenge[:]); err != nil {
			return fmt.Errorf("direct write failed")
		}
		var reply [32]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return fmt.Errorf("direct read failed")
		}
		if reply != expected {
			return fmt.Errorf("application response mismatch")
		}
	}
	return nil
}

func sameHostAddress(ip netip.Addr) bool {
	if ip.IsLoopback() {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err == nil && prefix.Addr().Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

func emit(t *testing.T, out *json.Encoder, o observation) {
	t.Helper()
	if err := out.Encode(o); err != nil {
		t.Fatal("report pipe failed")
	}
}
func digest(data []byte) string            { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func milliseconds(start time.Time) float64 { return float64(time.Since(start).Microseconds()) / 1000 }

type child struct {
	cmd      *exec.Cmd
	in       *json.Encoder
	out      *bufio.Scanner
	waitOnce sync.Once
}

func startPeer(t *testing.T, ctx context.Context, cfg peerConfig) *child {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestLabPeer$", "-test.timeout=40s")
	// Disallow inherited Tailcat debug knobs that can print secret bootstrap data.
	cmd.Env = []string{"DEVICE_AUDIT_LAB_PEER=1", "HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &child{cmd: cmd, in: json.NewEncoder(stdin), out: bufio.NewScanner(stdout)}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait must follow pipe consumption, otherwise Wait can close stdout early.
	t.Cleanup(func() { p.waitOnce.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) })
	if err := p.in.Encode(cfg); err != nil {
		t.Fatal("private peer configuration failed")
	}
	return p
}
func (p *child) read(t *testing.T, target any) {
	t.Helper()
	for p.out.Scan() {
		line := p.out.Bytes()
		for _, reason := range []string{"server never selected direct UDP path", "application warmup dial failed", "direct application dial failed", "direct read failed", "direct write failed", "exchange command missing", "test timed out"} {
			if strings.Contains(string(line), reason) {
				t.Log("peer failure category: " + reason)
			}
		}
		if len(line) > 0 && line[0] == '{' {
			if err := json.Unmarshal(line, target); err != nil {
				t.Fatal("invalid peer report; contents suppressed")
			}
			return
		}
	}
	t.Fatal("peer exited without report; private output suppressed")
}
func (p *child) command(t *testing.T, s string) {
	t.Helper()
	if err := p.in.Encode(s); err != nil {
		t.Fatal("peer command failed")
	}
}
func (p *child) wait(t *testing.T) {
	t.Helper()
	p.waitOnce.Do(func() {
		for p.out.Scan() {
		} // drain Go testing's PASS marker
		if err := p.cmd.Wait(); err != nil {
			t.Fatal("peer process failed; private output suppressed")
		}
	})
}

// startRelay uses the actual pinned upstream DERP server, exclusively on loopback.
// Stopping both closes the listening socket and DERP's hijacked TCP connections.
func startRelay(t *testing.T, address string) (*tailcfg.DERPRegion, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	d := derpserver.New(key.NewNode(), discardLog)
	hs := httptest.NewUnstartedServer(derpserver.Handler(d))
	hs.Listener.Close()
	hs.Listener = ln
	hs.Config.ErrorLog = log.New(io.Discard, "", 0)
	hs.StartTLS()
	reg := &tailcfg.DERPRegion{RegionID: 1, RegionCode: "lab", Nodes: []*tailcfg.DERPNode{{Name: "lab1", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: ln.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	stop := sync.OnceFunc(func() { hs.Close(); d.Close() })
	t.Cleanup(stop)
	return reg, stop
}

func TestDirectLab(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	dir := t.TempDir()
	serverPath, clientPath, unknownPath := filepath.Join(dir, "server.json"), filepath.Join(dir, "client.json"), filepath.Join(dir, "unknown.json")
	for _, err := range []error{InitializeServer(serverPath), InitializeClient(clientPath), InitializeClient(unknownPath)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	serverState, err := loadServer(serverPath)
	if err != nil {
		t.Fatal(err)
	}
	clientState, err := loadClient(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	var firstServer, firstClient, firstAddress string
	relayAddress := "127.0.0.1:0"
	for phase := 0; phase < 2; phase++ {
		reg, stopRelay := startRelay(t, relayAddress)
		relayAddress = fmt.Sprintf("127.0.0.1:%d", reg.Nodes[0].DERPPort)
		start := time.Now()
		s := startPeer(t, ctx, peerConfig{Role: "server", State: serverPath, Allowed: clientState.Node.Public(), Region: reg})
		var private struct{ Address tailcat.Addr }
		s.read(t, &private)
		var ready observation
		s.read(t, &ready)
		cfg := peerConfig{Role: "client", State: clientPath, Addr: private.Address, Expected: serverState.Node.Public()}
		c := startPeer(t, ctx, cfg)
		var direct observation
		c.read(t, &direct)
		if direct.Event != "direct_ready" || !direct.Direct {
			t.Fatal("direct path missing")
		}
		if phase == 0 {
			firstServer, firstClient, firstAddress = ready.PublicSHA256, direct.PublicSHA256, ready.AddressSHA256
		} else if ready.PublicSHA256 != firstServer || direct.PublicSHA256 != firstClient || ready.AddressSHA256 != firstAddress {
			t.Fatal("identity or bootstrap address changed after process restart")
		}
		if ready.PublicSHA256 != PublicDigest(serverState.Node.Public()) || direct.PublicSHA256 != PublicDigest(clientState.Node.Public()) {
			t.Fatal("peer did not load persisted key")
		}
		logObservation(t, phase, ready)
		logObservation(t, phase, direct)
		var before observation
		deadline := time.Now().Add(5 * time.Second)
		for {
			s.command(t, "snapshot")
			s.read(t, &before)
			if before.Direct {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("server never selected direct UDP path")
			}
			time.Sleep(50 * time.Millisecond)
		}
		logObservation(t, phase, before)
		logObservation(t, phase, observation{Event: "process_start_to_direct", ElapsedMS: milliseconds(start)})
		relayStopStart := time.Now()
		stopRelay()
		t.Logf("phase %d relay stopped in %.3f ms", phase, milliseconds(relayStopStart))
		// Check the bootstrap port is actually unreachable before a new app dial.
		if conn, err := net.DialTimeout("tcp", relayAddress, 100*time.Millisecond); err == nil {
			conn.Close()
			t.Fatal("relay listener still reachable")
		}
		c.command(t, "exchange")
		var exchange observation
		c.read(t, &exchange)
		c.wait(t)
		if exchange.RoundTrips != 8 || exchange.Event != "relay_off_exchange" {
			t.Fatal("bounded application exchange incomplete")
		}
		logObservation(t, phase, exchange)
		s.command(t, "snapshot")
		var snap observation
		s.read(t, &snap)
		if !snap.PeerBound || !snap.Direct || snap.Accepted != 2 || snap.RXBytes <= before.RXBytes || snap.TXBytes <= before.TXBytes {
			t.Fatal("missing authenticated peer or direct UDP byte evidence")
		}
		logObservation(t, phase, snap)
		s.command(t, "stop")
		s.wait(t)
	}
	// Admission failures run on a fresh server, apart from reconnect measurements.
	reg, _ := startRelay(t, relayAddress)
	s := startPeer(t, ctx, peerConfig{Role: "server", State: serverPath, Allowed: clientState.Node.Public(), Region: reg})
	var private struct{ Address tailcat.Addr }
	s.read(t, &private)
	var ready observation
	s.read(t, &ready)
	cfg := peerConfig{Role: "client", State: clientPath, Addr: private.Address, Expected: serverState.Node.Public()}

	for _, mode := range []string{"unknown", "wrong_psk"} {
		bad := cfg
		bad.Mode = mode
		if mode == "unknown" {
			bad.State = unknownPath
		}
		p := startPeer(t, ctx, bad)
		var result observation
		p.read(t, &result)
		p.wait(t)
		if result.Event != mode+"_refused" {
			t.Fatal("negative path did not complete")
		}
		logObservation(t, 2, result)
		s.command(t, "snapshot")
		var snap observation
		s.read(t, &snap)
		if snap.Accepted != 0 || (mode == "unknown" && snap.PeerCount != 0) {
			t.Fatal("denied client reached application listener")
		}
		logObservation(t, 2, snap)
		s.command(t, "disconnect")
		var disconnected observation
		s.read(t, &disconnected)
	}
	s.command(t, "stop")
	s.wait(t)

}
func logObservation(t *testing.T, phase int, o observation) {
	t.Helper()
	b, err := json.Marshal(struct {
		Phase int `json:"phase"`
		observation
	}{phase, o})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}
