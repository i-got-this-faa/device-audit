// Package mesh provides admitted Tailcat transport and a separate loopback fixture.
package mesh

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"tailscale.com/tailcfg"
)

type DERPConfig struct {
	Region            *tailcfg.DERPRegion
	AllowPublicRelays bool // false in production
}

type ServerConfig struct {
	Context  context.Context
	StateDir string
	DERP     DERPConfig
	Allow    func(peerKey string) bool
}

type ClientConfig struct {
	NetworkPrivateKey []byte // Imported from the protected, admitted endpoint identity.
	ServerAddr        string
	ServerPublicKey   string // Canonical lowercase X25519 hex, provisioned separately.
	DERP              DERPConfig
}

type Server interface {
	Addr() string
	Listen(context.Context, string, string) (net.Listener, error)
	PeerKey(net.Addr) (string, error)
	DisconnectClient(string) error
	Close() error
}

type Client interface {
	HTTPClient() *http.Client
	Close() error
}

// ListenLocal is only for an unauthenticated development fixture on loopback.
func ListenLocal(address string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("development listener requires a literal loopback IP")
	}
	return net.Listen("tcp", address)
}
