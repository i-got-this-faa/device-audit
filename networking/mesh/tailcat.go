package mesh

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/tailscale/tailcat"
	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const ApplicationPort = 8080
const ApplicationHost = "controller.mesh:8080"

// Region is supplied locally by the operator, never fetched from a public map.
func validateDERP(cfg DERPConfig) error {
	if os.Getenv("TS_DEBUG_ADDR") != "" {
		return errors.New("TS_DEBUG_ADDR must be unset to protect mesh credentials")
	}
	r := cfg.Region
	if cfg.AllowPublicRelays || r == nil || r.RegionID <= 0 || len(r.Nodes) == 0 {
		return errors.New("explicit self-hosted DERP region required; public relay defaults forbidden")
	}
	for _, n := range r.Nodes {
		if n == nil || n.RegionID != r.RegionID || n.HostName == "" || n.DERPPort < 1 || n.DERPPort > 65535 || n.STUNPort != -1 {
			return errors.New("invalid explicit DERP node; STUN must be disabled")
		}
		if n.InsecureForTests {
			ip, err := netip.ParseAddr(n.HostName)
			v4, err4 := netip.ParseAddr(n.IPv4)
			if err != nil || err4 != nil || !ip.IsLoopback() || !v4.IsLoopback() || n.IPv6 != "none" {
				return errors.New("insecure DERP is restricted to loopback tests")
			}
		}
	}
	return nil
}

// DecodeRegion reads bounded operator configuration, with no remote map lookup.
func DecodeRegion(data []byte) (*tailcfg.DERPRegion, error) {
	var r tailcfg.DERPRegion
	if len(data) > 64<<10 || json.Unmarshal(data, &r) != nil || validateDERP(DERPConfig{Region: &r}) != nil {
		return nil, errors.New("invalid self-hosted DERP region file")
	}
	return &r, nil
}

type server struct {
	node    *tailcat.Server
	release func()
}

func NewServer(cfg ServerConfig) (Server, error) {
	if cfg.Allow == nil || cfg.Context == nil {
		return nil, errors.New("admission lookup and startup context required")
	}
	if err := validateDERP(cfg.DERP); err != nil {
		return nil, err
	}
	state, release, err := loadServerState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	n := &tailcat.Server{Key: state.Node, PresharedKey: state.PSK, Region: cfg.DERP.Region,
		AllowClient: func(k key.NodePublic) bool { return cfg.Allow(k.UntypedHexString()) }, Logf: discardLog}
	if n.StartContext(cfg.Context) != nil {
		n.Close()
		release()
		return nil, errors.New("start admitted Tailcat server failed")
	}
	return &server{n, release}, nil
}

// Addr contains the mesh PSK. Deliver it only through protected files or IPC.
func (s *server) Addr() string { return string(s.node.TailcatAddr()) }
func (s *server) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	if network != "tcp" || addr != ":8080" {
		return nil, errors.New("only the application TCP port is allowed")
	}
	return s.node.Listen(ctx, network, addr)
}
func (s *server) PeerKey(addr net.Addr) (string, error) {
	k, ok := s.node.PeerKey(addr)
	if !ok {
		return "", errors.New("unrecognized mesh peer")
	}
	return k.UntypedHexString(), nil
}
func (s *server) DisconnectClient(peer string) error {
	k, err := publicKey(peer)
	if err != nil {
		return err
	}
	s.node.DisconnectClient(k)
	return nil
}
func (s *server) Close() error { err := s.node.Close(); s.release(); return err }

type client struct {
	node *tailcat.Client
	http *http.Client
}

func NewClient(cfg ClientConfig) (Client, error) {
	if err := validateDERP(cfg.DERP); err != nil {
		return nil, err
	}
	expected, err := publicKey(cfg.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	info, err := tailcat.ParseAddr(tailcat.Addr(cfg.ServerAddr))
	if err != nil || info.ServerPublic.NodePublic != expected || info.PresharedKey.IsZero() || info.ServerDiscoPublic.IsZero() || info.RegionID != 0 || len(info.Region) != 1 {
		return nil, errors.New("mesh address does not match pinned server and DERP region")
	}
	// Tailcat strips names and region IDs in its wire encoding. Compare using
	// that encoding so only transport-relevant region fields participate.
	pinned := info
	pinned.Region = []*tailcfg.DERPRegion{cfg.DERP.Region}
	if pinned.Addr() != info.Addr() {
		return nil, errors.New("mesh address DERP region differs from local configuration")
	}
	if len(cfg.NetworkPrivateKey) != 32 {
		return nil, errors.New("admitted network private key required")
	}
	nodeKey := key.NodePrivateFromRaw32(mem.B(cfg.NetworkPrivateKey))
	if nodeKey.IsZero() {
		return nil, errors.New("invalid network identity")
	}
	n := &tailcat.Client{Key: nodeKey, Server: tailcat.Addr(cfg.ServerAddr), Logf: discardLog}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" || addr != ApplicationHost {
			return nil, errors.New("mesh client permits only the controller application address")
		}
		return n.DialTCPPort(ctx, ApplicationPort)
	}}
	h := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &client{n, h}, nil
}
func (c *client) HTTPClient() *http.Client { return c.http }
func (c *client) Close() error             { c.http.CloseIdleConnections(); return c.node.Close() }

func publicKey(text string) (key.NodePublic, error) {
	raw, err := contracts.NetworkPublicKeyV1(text)
	if err != nil {
		return key.NodePublic{}, errors.New("invalid mesh public key")
	}
	return key.NodePublicFromRaw32(mem.B(raw[:])), nil
}

func ServerPublicKey(dir string) (string, error) {
	s, release, err := loadServerState(dir)
	if err != nil {
		return "", err
	}
	defer release()
	raw := s.Node.Public().Raw32()
	return hex.EncodeToString(raw[:]), nil
}
func discardLog(string, ...any) {}
