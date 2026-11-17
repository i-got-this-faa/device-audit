package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
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

// MeshConfig wires the device-only server. Nil Logger and Now use the process defaults.
type MeshConfig struct {
	Node       mesh.Server
	Repository MeshRepository
	Logger     *slog.Logger
	Now        func() time.Time
}

type meshPeerContextKey struct{}

// evidenceAttempt holds what is known about one request when it is rejected.
// binding is set only after the tunnel peer is authorized; envelope only after decode.
type evidenceAttempt struct {
	peer     string
	binding  *DeviceNetworkBinding
	envelope *contracts.EvidenceEnvelopeV1
}

// MeshHTTPServer exposes only device APIs. Administrator and bootstrap handlers
// belong to the separate HTTPS server and cannot be reached through this mux.
func MeshHTTPServer(cfg MeshConfig) *http.Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/evidence", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		peer, _ := r.Context().Value(meshPeerContextKey{}).(string)
		attempt, reason := admitEvidence(w, r, cfg, peer)
		if reason == "" {
			// Transport response only. CT04 signed acknowledgements remain #89.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		logEvidenceRejection(r.Context(), cfg.Logger, attempt, reason)
		http.Error(w, "evidence was not acknowledged", evidenceRejectionStatus(reason))
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			peer, err := cfg.Node.PeerKey(conn.RemoteAddr())
			if err != nil {
				peer = ""
			}
			return context.WithValue(ctx, meshPeerContextKey{}, peer)
		}}
}

// admitEvidence returns an empty reason only after durable ingestion committed.
// Every security check runs before the repository is asked to persist anything.
func admitEvidence(w http.ResponseWriter, r *http.Request, cfg MeshConfig, peer string) (evidenceAttempt, string) {
	attempt := evidenceAttempt{peer: peer}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	binding, err := cfg.Repository.NetworkPeerBinding(ctx, peer)
	if err != nil || binding.NetworkPublicKey != peer {
		// Unavailable admission state is denied like revocation; the tunnel is dropped either way.
		_ = cfg.Node.DisconnectClient(peer)
		return attempt, contracts.EnvelopeRejectionUnauthorizedPeer
	}
	attempt.binding = &binding
	if r.URL.RawQuery != "" {
		return attempt, contracts.EnvelopeRejectionInvalidPayload
	}
	r.Body = http.MaxBytesReader(w, r.Body, 400<<10)
	defer r.Body.Close()
	var envelope contracts.EvidenceEnvelopeV1
	d := json.NewDecoder(r.Body)
	if d.Decode(&envelope) != nil || d.Decode(new(json.RawMessage)) != io.EOF {
		return attempt, contracts.EnvelopeRejectionInvalidPayload
	}
	attempt.envelope = &envelope
	if reason := verifyEvidence(binding, envelope, cfg.Now()); reason != "" {
		return attempt, reason
	}
	if err := cfg.Repository.AcceptEvidence(ctx, envelope); err != nil {
		// Storage and uncertain COMMIT failures never become success responses.
		var rejection *RepositoryRejection
		if errors.As(err, &rejection) {
			return attempt, rejection.Reason
		}
		return attempt, contracts.EnvelopeRejectionStorageUnavailable
	}
	return attempt, ""
}

// verifyEvidence authenticates an envelope against the admitted peer's binding.
// It is pure; replay and revocation under lock remain the repository's job.
func verifyEvidence(binding DeviceNetworkBinding, envelope contracts.EvidenceEnvelopeV1, now time.Time) string {
	if envelope.Validate() != nil {
		return contracts.EnvelopeRejectionInvalidPayload
	}
	switch {
	case envelope.DeploymentID != binding.DeploymentID:
		return contracts.EnvelopeRejectionDeploymentMismatch
	case envelope.DeviceID != binding.DeviceID:
		return contracts.EnvelopeRejectionUnauthorizedPeer
	case envelope.SigningKeyID != binding.SigningKeyID:
		return contracts.EnvelopeRejectionKeyMismatch
	case envelope.VerifySignature(binding.SigningPublicKey) != nil:
		return contracts.EnvelopeRejectionInvalidSignature
	}
	reason, err := envelope.TimestampRejection(now)
	if err != nil {
		return contracts.EnvelopeRejectionInvalidPayload
	}
	return reason
}

func evidenceRejectionStatus(reason string) int {
	switch reason {
	case contracts.EnvelopeRejectionUnauthorizedPeer, contracts.EnvelopeRejectionDeploymentMismatch, contracts.EnvelopeRejectionKeyMismatch:
		return http.StatusForbidden
	case contracts.EnvelopeRejectionInvalidPayload:
		return http.StatusBadRequest
	case contracts.EnvelopeRejectionStorageUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusConflict
	}
}

// logEvidenceRejection emits the one security event for a rejected request.
// The tunnel key is the attributable principal; envelope claims are labelled as
// claims. Payloads, signatures and decode errors are never logged.
func logEvidenceRejection(ctx context.Context, logger *slog.Logger, attempt evidenceAttempt, reason string) {
	level := slog.LevelWarn
	if reason == contracts.EnvelopeRejectionStorageUnavailable {
		level = slog.LevelError
	}
	attrs := []slog.Attr{slog.String("event", "evidence_rejected"), slog.String("reason", reason), slog.String("peer", attempt.peer)}
	if attempt.binding != nil {
		attrs = append(attrs, slog.String("device_id", attempt.binding.DeviceID), slog.String("deployment_id", attempt.binding.DeploymentID))
	}
	if attempt.envelope != nil {
		// Bounded to the opaque ID grammar so a request cannot flood the log.
		if repositoryIDPattern.MatchString(attempt.envelope.DeviceID) {
			attrs = append(attrs, slog.String("claimed_device_id", attempt.envelope.DeviceID))
		}
		if signing, err := attempt.envelope.SigningBytes(); err == nil {
			if digest, err := contracts.EnvelopeRequestSHA256V1(signing, attempt.envelope.Signature); err == nil {
				attrs = append(attrs, slog.String("request_sha256", digest))
			}
		}
	}
	logger.LogAttrs(ctx, level, "evidence rejected", attrs...)
}
