// Package controllerfake is a deterministic, in-memory controller fixture for
// endpoint development. It admits only public fixture keys and reports every
// response as fixture mode; it is not production admission or storage.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	// FixtureDeploymentID matches the public envelope vectors.
	FixtureDeploymentID = "deployment:fixture-01"

	// Device public key is pinned by the enrollment contract vectors.
	fixtureDevicePublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

	// Controller seed is the public RFC 8032 test seed used by the contract vectors.
	controllerSeed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)

// Config supplies the fixed fixture identity and clock.
type Config struct {
	DeploymentID  string
	ControllerKey ed25519.PrivateKey
	Now           func() time.Time
	MaxBodyBytes  int64
}

type boundDevice struct {
	publicKey ed25519.PublicKey
}

// Server is an in-memory fixture admission loop. Restarting it loses all
// admitted identities and sequence marks, as documented for the fixture.
type Server struct {
	cfg Config

	mu         sync.Mutex
	devices    map[string]boundDevice
	highWater  map[string]uint64
	challenges map[string]struct{}
}

// New builds a fixture server. A zero clock and deployment ID select fixture defaults.
func New(cfg Config) (*Server, error) {
	if cfg.DeploymentID == "" {
		cfg.DeploymentID = FixtureDeploymentID
	}
	if cfg.ControllerKey == nil {
		cfg.ControllerKey = ed25519.NewKeyFromSeed(mustHex(controllerSeed))
	}
	if len(cfg.ControllerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("fixture controller key must be 64 bytes")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 512 << 10
	}
	return &Server{
		cfg:        cfg,
		devices:    make(map[string]boundDevice),
		highWater:  make(map[string]uint64),
		challenges: make(map[string]struct{}),
	}, nil
}

// Handler exposes the fixture envelope and health routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/envelopes", s.envelopes)
	return mux
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.markFixture(w)
	writeJSON(w, http.StatusOK, map[string]string{
		"status":     "ok",
		"mode":       "fixture",
		"admission":  "fixture_keys_only",
		"storage":    "memory",
		"durability": "none",
	})
}

func (s *Server) envelopes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	s.markFixture(w)
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, fixtureError("fixture envelope exceeds byte bound"))
		return
	}
	var version struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(body, &version); err != nil {
		writeJSON(w, http.StatusBadRequest, fixtureError("malformed JSON envelope"))
		return
	}
	switch version.SchemaVersion {
	case contracts.EnrollmentV1Version:
		var enrollment contracts.EnrollmentEnvelopeV1
		if err := json.Unmarshal(body, &enrollment); err != nil {
			writeJSON(w, http.StatusBadRequest, fixtureError("invalid enrollment envelope"))
			return
		}
		s.handleEnrollment(w, enrollment)
	case contracts.EvidenceEnvelopeV1Version:
		var evidence contracts.EvidenceEnvelopeV1
		if err := json.Unmarshal(body, &evidence); err != nil {
			writeJSON(w, http.StatusBadRequest, fixtureError("invalid evidence envelope"))
			return
		}
		s.handleEvidence(w, evidence)
	default:
		writeJSON(w, http.StatusBadRequest, fixtureError("unsupported fixture envelope version"))
	}
}

func (s *Server) handleEnrollment(w http.ResponseWriter, enrollment contracts.EnrollmentEnvelopeV1) {
	request, err := enrollmentRequest(enrollment)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, fixtureError(err.Error()))
		return
	}
	if enrollment.DeploymentID != s.cfg.DeploymentID {
		s.reject(w, request, "deployment_mismatch", nil)
		return
	}
	publicKey, _ := hex.DecodeString(enrollment.PublicKey)
	if err := verifyRequestSignature(enrollment.SigningKeyID, enrollment.Signature, publicKey, request.signingBytes); err != nil {
		s.reject(w, request, err.Error(), nil)
		return
	}
	if !bytes.Equal(publicKey, mustHex(fixtureDevicePublicKey)) {
		s.reject(w, request, "key_mismatch", nil)
		return
	}
	if err := enrollment.Validate(); err != nil {
		s.reject(w, request, "invalid_payload", nil)
		return
	}

	now := s.cfg.Now().UTC()
	s.mu.Lock()
	if _, reused := s.challenges[enrollment.ChallengeID]; reused {
		s.mu.Unlock()
		s.reject(w, request, "challenge_reused", nil)
		return
	}
	if existing, ok := s.devices[enrollment.DeviceID]; ok {
		lastSequence := s.highWater[enrollment.DeviceID]
		s.mu.Unlock()
		if string(existing.publicKey) != string(publicKey) {
			s.reject(w, request, "enrollment_conflict", nil)
			return
		}
		// A repeat of a consumed sequence is a replay, not a new binding.
		s.reject(w, request, "replay", uint64Pointer(lastSequence))
		return
	}
	if reason, err := enrollment.EnvelopeHeaderV1.FreshnessRejection(now, 0); err != nil {
		s.mu.Unlock()
		s.reject(w, request, "invalid_payload", nil)
		return
	} else if reason != "" {
		s.mu.Unlock()
		s.reject(w, request, reason, nil)
		return
	}
	s.devices[enrollment.DeviceID] = boundDevice{publicKey: publicKey}
	s.highWater[enrollment.DeviceID] = enrollment.Sequence
	s.challenges[enrollment.ChallengeID] = struct{}{}
	s.mu.Unlock()
	s.accept(w, request, enrollment.Sequence)
}

func (s *Server) handleEvidence(w http.ResponseWriter, evidence contracts.EvidenceEnvelopeV1) {
	request, err := evidenceRequest(evidence)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, fixtureError(err.Error()))
		return
	}
	if evidence.DeploymentID != s.cfg.DeploymentID {
		s.reject(w, request, "deployment_mismatch", nil)
		return
	}

	s.mu.Lock()
	device, enrolled := s.devices[evidence.DeviceID]
	lastSequence := s.highWater[evidence.DeviceID]
	s.mu.Unlock()
	if !enrolled {
		s.reject(w, request, "unknown_device", uint64Pointer(0))
		return
	}
	if err := verifyRequestSignature(evidence.SigningKeyID, evidence.Signature, device.publicKey, request.signingBytes); err != nil {
		s.reject(w, request, err.Error(), nil)
		return
	}
	if err := evidence.Validate(); err != nil {
		if err.Error() == "payload_digest_mismatch" {
			s.reject(w, request, "payload_digest_mismatch", nil)
			return
		}
		s.reject(w, request, "invalid_payload", nil)
		return
	}

	now := s.cfg.Now().UTC()
	reason, err := evidence.EnvelopeHeaderV1.FreshnessRejection(now, lastSequence)
	if err != nil {
		s.reject(w, request, "invalid_payload", nil)
		return
	}
	if reason != "" {
		s.reject(w, request, reason, uint64Pointer(lastSequence))
		return
	}

	s.mu.Lock()
	if current := s.highWater[evidence.DeviceID]; evidence.Sequence <= current {
		s.mu.Unlock()
		s.reject(w, request, "replay", uint64Pointer(current))
		return
	}
	s.highWater[evidence.DeviceID] = evidence.Sequence
	s.mu.Unlock()
	s.accept(w, request, evidence.Sequence)
}

type requestInfo struct {
	version      string
	deviceID     string
	keyID        string
	sequence     uint64
	signingBytes []byte
	digest       string
}

func enrollmentRequest(enrollment contracts.EnrollmentEnvelopeV1) (requestInfo, error) {
	signingBytes, err := enrollment.SigningBytes()
	if err != nil {
		return requestInfo{}, fmt.Errorf("uncorrelatable enrollment envelope")
	}
	digest, err := contracts.EnvelopeRequestSHA256V1(signingBytes, enrollment.Signature)
	if err != nil {
		return requestInfo{}, fmt.Errorf("uncorrelatable enrollment signature")
	}
	return requestInfo{
		version:      contracts.EnrollmentV1Version,
		deviceID:     enrollment.DeviceID,
		keyID:        enrollment.SigningKeyID,
		sequence:     enrollment.Sequence,
		signingBytes: signingBytes,
		digest:       digest,
	}, nil
}

func evidenceRequest(evidence contracts.EvidenceEnvelopeV1) (requestInfo, error) {
	signingBytes, err := evidence.SigningBytes()
	if err != nil {
		return requestInfo{}, fmt.Errorf("uncorrelatable evidence envelope")
	}
	digest, err := contracts.EnvelopeRequestSHA256V1(signingBytes, evidence.Signature)
	if err != nil {
		return requestInfo{}, fmt.Errorf("uncorrelatable evidence signature")
	}
	return requestInfo{
		version:      contracts.EvidenceEnvelopeV1Version,
		deviceID:     evidence.DeviceID,
		keyID:        evidence.SigningKeyID,
		sequence:     evidence.Sequence,
		signingBytes: signingBytes,
		digest:       digest,
	}, nil
}

func verifyRequestSignature(keyID, signature string, publicKey ed25519.PublicKey, signingBytes []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("key_mismatch")
	}
	fingerprint, err := contracts.SigningKeyIDV1(publicKey)
	if err != nil || fingerprint != keyID {
		return fmt.Errorf("key_mismatch")
	}
	rawSignature, err := hex.DecodeString(signature)
	if err != nil || len(rawSignature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, signingBytes, rawSignature) {
		return fmt.Errorf("invalid_signature")
	}
	return nil
}

func (s *Server) accept(w http.ResponseWriter, request requestInfo, sequence uint64) {
	s.writeAcknowledgement(w, request, "accepted", nil, &sequence)
}

func (s *Server) reject(w http.ResponseWriter, request requestInfo, reason string, lastSequence *uint64) {
	s.writeAcknowledgement(w, request, "rejected", &reason, lastSequence)
}

func (s *Server) writeAcknowledgement(w http.ResponseWriter, request requestInfo, status string, reason *string, lastSequence *uint64) {
	acknowledgement := contracts.AcknowledgementV1{
		SchemaVersion:        contracts.AcknowledgementV1Version,
		DeploymentID:         s.cfg.DeploymentID,
		DeviceID:             request.deviceID,
		ControllerKeyID:      controllerKeyID(s.cfg.ControllerKey),
		RequestSchemaVersion: request.version,
		RequestKeyID:         request.keyID,
		RequestSequence:      request.sequence,
		RequestSHA256:        request.digest,
		ReceivedAt:           s.cfg.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Status:               status,
		RejectionReason:      reason,
		LastSequence:         lastSequence,
	}
	message, err := acknowledgement.SigningBytes()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, fixtureError("fixture acknowledgement construction failed"))
		return
	}
	acknowledgement.Signature = hex.EncodeToString(ed25519.Sign(s.cfg.ControllerKey, message))
	if err := acknowledgement.Validate(); err != nil {
		writeJSON(w, http.StatusInternalServerError, fixtureError("fixture acknowledgement validation failed"))
		return
	}
	writeJSON(w, http.StatusOK, acknowledgement)
}

func controllerKeyID(key ed25519.PrivateKey) string {
	public := key.Public().(ed25519.PublicKey)
	fingerprint, _ := contracts.SigningKeyIDV1(public)
	return fingerprint
}

func mustHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func uint64Pointer(value uint64) *uint64 { return &value }

func (s *Server) markFixture(w http.ResponseWriter) {
	w.Header().Set("X-Device-Audit-Fixture", "true")
	w.Header().Set("X-Device-Audit-Durability", "none")
}

func fixtureError(message string) map[string]any {
	return map[string]any{"error": message, "fixture": true}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
