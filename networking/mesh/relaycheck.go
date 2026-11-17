package mesh

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// ErrRelayUnavailable wraps every CheckRelay failure so callers can report it.
var ErrRelayUnavailable = errors.New("self-hosted DERP relay unavailable")

// Tailcat discovers the controller through the configured relay, so a cold
// mesh session needs it even when the data path later goes direct.
const relayCheckTimeout = 10 * time.Second

// CheckRelay connects to the configured self-hosted relay with an admitted
// network key using the same pinned DERP client and TLS verification as the
// mesh, then requires a DERP ping reply. This fails on an unreachable endpoint,
// an untrusted or mismatched certificate, or relay admission denial. It never
// weakens TLS, consults public relays, or affects peer authentication.
func CheckRelay(ctx context.Context, cfg DERPConfig, networkPrivateKey []byte) error {
	if err := validateDERP(cfg); err != nil {
		return err
	}
	if len(networkPrivateKey) != 32 {
		return errors.New("admitted network private key required")
	}
	nodeKey := key.NodePrivateFromRaw32(mem.B(networkPrivateKey))
	if nodeKey.IsZero() {
		return errors.New("invalid network identity")
	}
	return checkRelay(ctx, cfg, nodeKey)
}

// CheckServerRelay runs CheckRelay with the controller's persisted node key.
// Call it before NewServer: it briefly takes the state lock.
func CheckServerRelay(ctx context.Context, stateDir string, cfg DERPConfig) error {
	if err := validateDERP(cfg); err != nil {
		return err
	}
	state, release, err := loadServerState(stateDir)
	if err != nil {
		return err
	}
	nodeKey := state.Node
	release()
	return checkRelay(ctx, cfg, nodeKey)
}

func checkRelay(ctx context.Context, cfg DERPConfig, nodeKey key.NodePrivate) error {
	ctx, cancel := context.WithTimeout(ctx, relayCheckTimeout)
	defer cancel()
	node := cfg.Region.Nodes[0]
	where := fmt.Sprintf("region %d host %s port %d", cfg.Region.RegionID, node.HostName, node.DERPPort)
	c := derphttp.NewRegionClient(nodeKey, discardLog, netmon.NewStatic(), func() *tailcfg.DERPRegion { return cfg.Region })
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		return fmt.Errorf("%w: %s: connect: %v", ErrRelayUnavailable, where, err)
	}
	var ping [8]byte
	if _, err := rand.Read(ping[:]); err != nil {
		return errors.New("generate relay ping")
	}
	if err := c.SendPing(ping); err != nil {
		return fmt.Errorf("%w: %s: ping: %v", ErrRelayUnavailable, where, err)
	}
	result := make(chan error, 1)
	go func() {
		for {
			m, err := c.Recv()
			if err != nil {
				result <- fmt.Errorf("connection closed (relay admission denied or relay failed): %v", err)
				return
			}
			if pong, ok := m.(derp.PongMessage); ok && pong == derp.PongMessage(ping) {
				result <- nil
				return
			}
		}
	}()
	select {
	case err := <-result:
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrRelayUnavailable, where, err)
		}
		return nil
	case <-ctx.Done():
		c.Close()
		return fmt.Errorf("%w: %s: no ping reply before deadline", ErrRelayUnavailable, where)
	}
}
