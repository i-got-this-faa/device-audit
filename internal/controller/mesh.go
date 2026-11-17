package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
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
	AcceptEvidence(context.Context, contracts.EvidenceEnvelopeV1) (time.Time, error)
}

// MeshConfig wires the device-only server. Nil Logger and Now use the process defaults.
type MeshConfig struct {
	Node       mesh.Server
	Repository MeshRepository
	// AcknowledgementKey signs CT04 receipts. It is a controller application
	// key, separate from the mesh key, device keys and any chain signer.
	AcknowledgementKey ed25519.PrivateKey
	Logger             *slog.Logger
	Now                func() time.Time
}

type meshPeerContextKey struct{}

// evidenceAttempt holds what is known about one request when it is answered.
// binding is set only after the tunnel peer is authorized; envelope only after decode.
type evidenceAttempt struct {
	peer     string
	binding  *DeviceNetworkBinding
	envelope *contracts.EvidenceEnvelopeV1
}

// evidenceOutcome is the answer to one request. An empty reason means the
// repository committed the sample at receivedAt. lastSequence is the durable
// mark read under the device lock, or nil when unknown or not disclosable.
type evidenceOutcome struct {
	reason       string
	lastSequence *uint64
	receivedAt   time.Time
}

// MeshHTTPServer exposes only device APIs. Administrator and bootstrap handlers
// belong to the separate HTTPS server and cannot be reached through this mux.
func MeshHTTPServer(cfg MeshConfig) (*http.Server, error) {
	if len(cfg.AcknowledgementKey) != ed25519.PrivateKeySize {
		return nil, errors.New("mesh evidence requires an Ed25519 acknowledgement signing key")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	controllerKeyID, err := contracts.SigningKeyIDV1(cfg.AcknowledgementKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/evidence", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		peer, _ := r.Context().Value(meshPeerContextKey{}).(string)
		attempt, outcome := admitEvidence(w, r, cfg, peer)
		status := http.StatusOK
		if outcome.reason != "" {
			logEvidenceRejection(r.Context(), cfg.Logger, attempt, outcome.reason)
			status = evidenceRejectionStatus(outcome.reason)
		}
		ack, ok := signEvidenceAcknowledgement(cfg.AcknowledgementKey, controllerKeyID, attempt, outcome)
		if !ok {
			if outcome.reason == "" {
				// Committed but unanswerable. A retry receives a signed replay.
				cfg.Logger.LogAttrs(r.Context(), slog.LevelError, "evidence acknowledgement failed", slog.String("peer", peer))
				status = http.StatusInternalServerError
			}
			http.Error(w, "evidence was not acknowledged; retain the signed envelope", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(ack)
	})
	return &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			peer, err := cfg.Node.PeerKey(conn.RemoteAddr())
			if err != nil {
				peer = ""
			}
			return context.WithValue(ctx, meshPeerContextKey{}, peer)
		}}, nil
}

// admitEvidence returns an empty reason only after durable ingestion committed.
// Every security check runs before the repository is asked to persist anything.
func admitEvidence(w http.ResponseWriter, r *http.Request, cfg MeshConfig, peer string) (evidenceAttempt, evidenceOutcome) {
	attempt := evidenceAttempt{peer: peer}
	reject := func(reason string) (evidenceAttempt, evidenceOutcome) {
		return attempt, evidenceOutcome{reason: reason, receivedAt: cfg.Now()}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	binding, err := cfg.Repository.NetworkPeerBinding(ctx, peer)
	if err != nil || binding.NetworkPublicKey != peer {
		// Unavailable admission state is denied like revocation; the tunnel is dropped either way.
		_ = cfg.Node.DisconnectClient(peer)
		return reject(contracts.EnvelopeRejectionUnauthorizedPeer)
	}
	attempt.binding = &binding
	if r.URL.RawQuery != "" {
		return reject(contracts.EnvelopeRejectionInvalidPayload)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 400<<10)
	defer r.Body.Close()
	var envelope contracts.EvidenceEnvelopeV1
	d := json.NewDecoder(r.Body)
	if d.Decode(&envelope) != nil || d.Decode(new(json.RawMessage)) != io.EOF {
		return reject(contracts.EnvelopeRejectionInvalidPayload)
	}
	attempt.envelope = &envelope
	if reason := verifyEvidence(binding, envelope, cfg.Now()); reason != "" {
		return reject(reason)
	}
	receivedAt, err := cfg.Repository.AcceptEvidence(ctx, envelope)
	if err != nil {
		// Storage and uncertain COMMIT failures never become success responses.
		var rejection *RepositoryRejection
		if errors.As(err, &rejection) {
			return attempt, evidenceOutcome{reason: rejection.Reason, lastSequence: rejection.LastSequence, receivedAt: cfg.Now()}
		}
		return reject(contracts.EnvelopeRejectionStorageUnavailable)
	}
	return attempt, evidenceOutcome{lastSequence: &envelope.Sequence, receivedAt: receivedAt}
}

// signEvidenceAcknowledgement signs a CT04 receipt only for a correlatable
// request that names the admitted peer's own deployment and device. It never
// signs storage_unavailable: a failed COMMIT may still have committed, so the
// controller cannot truthfully state that the request was rejected.
func signEvidenceAcknowledgement(key ed25519.PrivateKey, keyID string, attempt evidenceAttempt, outcome evidenceOutcome) (contracts.AcknowledgementV1, bool) {
	if attempt.binding == nil || attempt.envelope == nil || outcome.reason == contracts.EnvelopeRejectionStorageUnavailable {
		return contracts.AcknowledgementV1{}, false
	}
	e := *attempt.envelope
	if e.DeploymentID != attempt.binding.DeploymentID || e.DeviceID != attempt.binding.DeviceID {
		return contracts.AcknowledgementV1{}, false
	}
	signing, err := e.SigningBytes()
	if err != nil {
		return contracts.AcknowledgementV1{}, false
	}
	digest, err := contracts.EnvelopeRequestSHA256V1(signing, e.Signature)
	if err != nil {
		return contracts.AcknowledgementV1{}, false
	}
	ack := contracts.AcknowledgementV1{
		SchemaVersion: contracts.AcknowledgementV1Version, DeploymentID: e.DeploymentID, DeviceID: e.DeviceID,
		ControllerKeyID: keyID, RequestSchemaVersion: e.SchemaVersion, RequestKeyID: e.SigningKeyID,
		RequestSequence: e.Sequence, RequestSHA256: digest, ReceivedAt: outcome.receivedAt.UTC().Format(time.RFC3339),
		Status: "accepted", LastSequence: outcome.lastSequence,
	}
	if outcome.reason != "" {
		ack.Status, ack.RejectionReason = "rejected", &outcome.reason
	}
	message, err := ack.SigningBytes()
	if err != nil {
		return contracts.AcknowledgementV1{}, false
	}
	ack.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	return ack, true
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
