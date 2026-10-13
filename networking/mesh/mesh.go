// Package mesh preserves Shepherd's transport boundary without claiming a live mesh.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
)

var ErrNotImplemented = errors.New("Tailcat/WireGuard/DERP adapter is not implemented")

type DERPConfig struct {
	MapURL            string
	AllowPublicRelays bool // false in production
}

type ServerConfig struct {
	StateDir string
	DERP     DERPConfig
	Allow    func(peerKey string) bool
}

type ClientConfig struct {
	StateDir   string
	ServerAddr string
	DERP       DERPConfig
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

func NewServer(ServerConfig) (Server, error) { return nil, ErrNotImplemented }
func NewClient(ClientConfig) (Client, error) { return nil, ErrNotImplemented }

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
