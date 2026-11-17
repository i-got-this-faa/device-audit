// Package relay runs the scoped self-hosted DERP relay for one deployment.
//
// It wraps the pinned upstream derpserver with an operator-selected TLS
// certificate, a persisted relay key, and a fail-closed allowlist of admitted
// mesh network keys. It serves no STUN, no HTTP/ACME listener, no debug pages
// and no application routes. Relay admission is defense in depth only: the
// controller's own mesh admission and device-signature checks still apply.
package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"go4.org/mem"
	"tailscale.com/derp/derpserver"
	"tailscale.com/metrics"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// AdmissionVersion identifies the operator-supplied relay admission file.
const AdmissionVersion = "device-audit.relay-admission.v1"

const maxAdmissionBytes = 1 << 20

// Admission lists the X25519 mesh network public keys allowed to use the relay:
// the controller node key and each enrolled, non-revoked endpoint network key.
type Admission struct {
	Version           string   `json:"version"`
	NetworkPublicKeys []string `json:"network_public_keys"`
}

type Config struct {
	// Hostname is the DNS name advertised in the DERP region. The selected
	// certificate must be valid for it.
	Hostname      string
	CertFile      string // PEM chain, leaf first, selected by the operator.
	KeyFile       string // PEM private key for CertFile.
	NodeKeyFile   string // Persisted DERP server key created by InitializeNodeKey.
	AdmissionFile string // Admission JSON, reloaded on every client admission.
	Logf          func(string, ...any)
	Now           func() time.Time
}

type Relay struct {
	derp      *derpserver.Server
	server    *http.Server
	admission *http.Server
	admitLn   net.Listener
	public    key.NodePublic
	closeOnce sync.Once
}

// InitializeNodeKey exclusively creates a private relay key file with mode 0600.
func InitializeNodeKey(path string) error {
	text, err := key.NewNode().MarshalText()
	if err != nil {
		return errors.New("generate relay key")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("relay key already exists or cannot be created")
	}
	_, werr := f.Write(append(text, '\n'))
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(path)
		return errors.New("write relay key")
	}
	return nil
}

func loadNodeKey(path string) (key.NodePrivate, error) {
	var k key.NodePrivate
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return k, errors.New("relay key file must be an existing regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return k, errors.New("relay key file must not be group or world accessible")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4<<10 || k.UnmarshalText(bytes.TrimSpace(data)) != nil || k.IsZero() {
		return key.NodePrivate{}, errors.New("invalid relay key file")
	}
	return k, nil
}

// LoadAdmission reads and strictly validates the admission file.
func LoadAdmission(path string) (map[key.NodePublic]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open relay admission file")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAdmissionBytes+1))
	if err != nil || len(data) > maxAdmissionBytes {
		return nil, errors.New("relay admission file unreadable or too large")
	}
	var a Admission
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || d.More() || a.Version != AdmissionVersion || len(a.NetworkPublicKeys) == 0 {
		return nil, errors.New("invalid relay admission file")
	}
	keys := make(map[key.NodePublic]struct{}, len(a.NetworkPublicKeys))
	for _, text := range a.NetworkPublicKeys {
		raw, err := contracts.NetworkPublicKeyV1(text)
		if err != nil {
			return nil, errors.New("invalid network public key in relay admission file")
		}
		keys[key.NodePublicFromRaw32(mem.B(raw[:]))] = struct{}{}
	}
	return keys, nil
}

// LoadCertificate loads the selected certificate and checks it covers hostname
// and is currently valid. Chain trust is verified by clients, not here.
func LoadCertificate(certFile, keyFile, hostname string, now time.Time) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, errors.New("load relay TLS certificate and key")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, errors.New("parse relay TLS certificate")
	}
	if leaf.VerifyHostname(hostname) != nil {
		return tls.Certificate{}, fmt.Errorf("relay TLS certificate is not valid for %q", hostname)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return tls.Certificate{}, errors.New("relay TLS certificate is not currently valid")
	}
	cert.Leaf = leaf
	return cert, nil
}

func New(cfg Config) (*Relay, error) {
	if cfg.Hostname == "" || cfg.CertFile == "" || cfg.KeyFile == "" || cfg.NodeKeyFile == "" || cfg.AdmissionFile == "" {
		return nil, errors.New("relay requires hostname, TLS certificate, TLS key, relay key and admission file")
	}
	if net.ParseIP(cfg.Hostname) != nil {
		return nil, errors.New("relay hostname must be a DNS name")
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	cert, err := LoadCertificate(cfg.CertFile, cfg.KeyFile, cfg.Hostname, now())
	if err != nil {
		return nil, err
	}
	nodeKey, err := loadNodeKey(cfg.NodeKeyFile)
	if err != nil {
		return nil, err
	}
	if _, err := LoadAdmission(cfg.AdmissionFile); err != nil {
		return nil, err
	}

	// Pinned derpserver supports admission only through a URL. Serve it on a
	// loopback listener with an unguessable path; it denies on any error.
	admitLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("start loopback relay admission listener")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		admitLn.Close()
		return nil, errors.New("generate admission path")
	}
	path := "/admit/" + hex.EncodeToString(token[:])
	admitMux := http.NewServeMux()
	admitMux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
		var req tailcfg.DERPAdmitClientRequest
		allow := false
		if json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req) == nil {
			keys, err := LoadAdmission(cfg.AdmissionFile)
			if err != nil {
				logf("relay admission file unavailable; denying client")
			} else {
				_, allow = keys[req.NodePublic]
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: allow})
	})
	admission := &http.Server{Handler: admitMux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	go admission.Serve(admitLn)

	d := derpserver.New(nodeKey, logf)
	d.SetVerifyClientURL("http://" + admitLn.Addr().String() + path)
	d.SetVerifyClientURLFailOpen(false)

	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.Handler(d))
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	mux.HandleFunc("/derp/latency-check", derpserver.ProbeHandler)
	mux.HandleFunc("/generate_204", derpserver.ServeNoContent)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		// DERP upgrades an HTTP/1.1 connection; HTTP/2 must stay disabled.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}},
		ErrorLog:     log.New(logfWriter(logf), "", 0),
	}
	return &Relay{derp: d, server: server, admission: admission, admitLn: admitLn, public: nodeKey.Public()}, nil
}

// Serve accepts TLS DERP connections on ln until Close.
func (r *Relay) Serve(ln net.Listener) error {
	err := r.server.ServeTLS(ln, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// PublicKey is the relay's DERP server key, not a mesh or device identity.
func (r *Relay) PublicKey() string { return r.public.UntypedHexString() }

// Counters are upstream DERP protocol counters. OtherPackets counts relayed
// non-Disco frames, which carry encrypted WireGuard traffic.
type Counters struct {
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent     int64 `json:"packets_sent"`
	DiscoPackets    int64 `json:"packets_received_disco"`
	OtherPackets    int64 `json:"packets_received_other"`
}

func (r *Relay) Counters() Counters {
	var c Counters
	set, ok := r.derp.ExpVar(false).(*metrics.Set)
	if !ok {
		return c
	}
	get := func(name string) int64 {
		if v, ok := set.Get(name).(*expvar.Int); ok {
			return v.Value()
		}
		return 0
	}
	c.PacketsReceived, c.PacketsSent = get("packets_received"), get("packets_sent")
	if kinds, ok := set.Get("counter_packets_received_kind").(*metrics.LabelMap); ok {
		c.DiscoPackets, c.OtherPackets = kinds.Get("disco").Value(), kinds.Get("other").Value()
	}
	return c
}

func (r *Relay) Shutdown(ctx context.Context) error {
	err := r.server.Shutdown(ctx)
	r.Close()
	return err
}

func (r *Relay) Close() error {
	var err error
	r.closeOnce.Do(func() {
		err = r.server.Close()
		_ = r.derp.Close()
		_ = r.admission.Close()
	})
	return err
}

// Region builds the operator region file consumed by networking/mesh.
// IPv4 may pin the dial address; certName may pin "sha256-raw:<hex>".
func Region(regionID int, hostname, ipv4 string, port int, certName string) *tailcfg.DERPRegion {
	ipv6 := ""
	if ipv4 != "" {
		ipv6 = "none"
	}
	return &tailcfg.DERPRegion{RegionID: tailcfg.DERPRegionID(regionID), RegionCode: "device-audit", RegionName: "Device Audit self-hosted relay", Nodes: []*tailcfg.DERPNode{{
		Name: fmt.Sprintf("%da", regionID), RegionID: tailcfg.DERPRegionID(regionID), HostName: hostname, CertName: certName,
		IPv4: ipv4, IPv6: ipv6, DERPPort: port, STUNPort: -1,
	}}}
}

type logfWriter func(string, ...any)

func (f logfWriter) Write(p []byte) (int, error) { f("%s", bytes.TrimSpace(p)); return len(p), nil }
