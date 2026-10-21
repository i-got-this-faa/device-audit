// Package lab proves a pinned Tailcat API in a bounded, same-host experiment.
// It is independent of the unavailable production networking/mesh adapter.
package lab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type ClientState struct {
	Version int             `json:"version"`
	Node    key.NodePrivate `json:"node"`
}

type ServerState struct {
	ClientState
	PSK tailcat.PresharedKey `json:"psk"`
}

// InitializeClient and InitializeServer are explicit, exclusive provisioning.
// Start paths never generate replacement identities on a missing or bad file.
func InitializeClient(path string) error {
	return writeState(path, ClientState{Version: 1, Node: key.NewNode()})
}

func InitializeServer(path string) error {
	return writeState(path, ServerState{
		ClientState: ClientState{Version: 1, Node: key.NewNode()},
		PSK:         tailcat.NewPresharedKey(),
	})
}

func writeState(path string, state any) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("create network state: exclusive private file required")
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(state); err != nil {
		return errors.New("write network state failed; remove incomplete file explicitly")
	}
	return f.Sync()
}

func readState(path string, target any) error {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 4096 {
		return errors.New("network state requires an existing regular 0600 file, at most 4096 bytes")
	}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("open network state failed")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		// Key parsers can include their input in errors. Never log those errors.
		return errors.New("invalid network state JSON")
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("network state contains trailing data")
	}
	return nil
}

func loadClient(path string) (ClientState, error) {
	var s ClientState
	if err := readState(path, &s); err != nil {
		return s, err
	}
	if s.Version != 1 || s.Node.IsZero() {
		return s, errors.New("invalid network client identity")
	}
	return s, nil
}

func loadServer(path string) (ServerState, error) {
	var s ServerState
	if err := readState(path, &s); err != nil {
		return s, err
	}
	if s.Version != 1 || s.Node.IsZero() || s.PSK.IsZero() {
		return s, errors.New("invalid network server identity or missing PSK")
	}
	return s, nil
}

// StartServer deliberately supports one admitted network key and a loopback
// bootstrap relay. Callers own listener creation and shutdown. No forwarding.
func StartServer(ctx context.Context, path string, allowed key.NodePublic, region *tailcfg.DERPRegion) (*tailcat.Server, error) {
	if allowed.IsZero() || !localRegion(region) {
		return nil, errors.New("lab requires an admitted network key and explicit loopback relay")
	}
	state, err := loadServer(path)
	if err != nil {
		return nil, err
	}
	s := &tailcat.Server{
		Key: state.Node, PresharedKey: state.PSK, Region: region,
		AllowClient: func(peer key.NodePublic) bool { return peer == allowed },
		Logf:        discardLog,
	}
	if err := s.StartContext(ctx); err != nil {
		s.Close()
		return nil, errors.New("start lab Tailcat server failed")
	}
	return s, nil
}

// NewClient pins the expected server key before Tailcat performs any network IO.
// The address includes a PSK and must travel only through private local IPC/files.
func NewClient(path string, address tailcat.Addr, expected key.NodePublic) (*tailcat.Client, error) {
	info, err := tailcat.ParseAddr(address)
	if err != nil || expected.IsZero() || info.ServerPublic.NodePublic != expected || info.PresharedKey.IsZero() || info.ServerDiscoPublic.IsZero() || len(info.Region) != 1 || !localRegion(info.Region[0]) {
		return nil, errors.New("invalid lab bootstrap address or server key pin")
	}
	state, err := loadClient(path)
	if err != nil {
		return nil, err
	}
	return &tailcat.Client{Server: address, Key: state.Node, Logf: discardLog}, nil
}

func localRegion(r *tailcfg.DERPRegion) bool {
	if r == nil || r.RegionID != 1 || len(r.Nodes) != 1 || r.Nodes[0] == nil {
		return false
	}
	n := r.Nodes[0]
	ip, err := netip.ParseAddr(n.IPv4)
	return err == nil && ip.Is4() && ip.IsLoopback() && n.HostName == n.IPv4 && n.IPv6 == "none" && n.RegionID == 1 && n.DERPPort > 0 && n.DERPPort <= 65535 && n.STUNPort == -1 && n.InsecureForTests
}

func discardLog(string, ...any) {}

// PublicDigest emits a SHA-256 fingerprint, never a private node key or PSK.
func PublicDigest(k key.NodePublic) string {
	b, _ := k.MarshalText()
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
