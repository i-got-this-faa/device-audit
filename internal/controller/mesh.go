package controller

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type MeshRepository interface {
	NetworkPeerBinding(context.Context, string) (DeviceNetworkBinding, error)
	AcceptEvidence(context.Context, contracts.EvidenceEnvelopeV1) error
}

type meshPeerContextKey struct{}

// MeshHTTPServer exposes only device APIs. Administrator and bootstrap handlers
// belong to the separate HTTPS server and cannot be reached through this mux.
func MeshHTTPServer(node mesh.Server, repo MeshRepository) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/evidence", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		peer, _ := r.Context().Value(meshPeerContextKey{}).(string)
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		binding, err := repo.NetworkPeerBinding(ctx, peer)
		if err != nil || binding.NetworkPublicKey != peer {
			_ = node.DisconnectClient(peer)
			http.Error(w, "mesh admission unavailable or denied", http.StatusForbidden)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "queries forbidden", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 400<<10)
		defer r.Body.Close()
		var envelope contracts.EvidenceEnvelopeV1
		d := json.NewDecoder(r.Body)
		if d.Decode(&envelope) != nil || d.Decode(new(json.RawMessage)) != io.EOF || envelope.Validate() != nil {
			http.Error(w, "invalid evidence envelope", http.StatusBadRequest)
			return
		}
		if envelope.DeploymentID != binding.DeploymentID || envelope.DeviceID != binding.DeviceID || envelope.SigningKeyID != binding.SigningKeyID {
			http.Error(w, "evidence identity differs from admitted peer", http.StatusForbidden)
			return
		}
		if err := repo.AcceptEvidence(ctx, envelope); err != nil {
			// Storage and uncertain COMMIT failures never become success responses.
			status := http.StatusServiceUnavailable
			if _, ok := err.(*RepositoryRejection); ok {
				status = http.StatusConflict
			}
			http.Error(w, "evidence was not acknowledged", status)
			return
		}
		// Transport response only. CT04 signed acknowledgements remain #89.
		w.WriteHeader(http.StatusNoContent)
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			peer, err := node.PeerKey(conn.RemoteAddr())
			if err != nil {
				peer = ""
			}
			return context.WithValue(ctx, meshPeerContextKey{}, peer)
		}}
}
