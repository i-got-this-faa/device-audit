package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	sequenceFile         = "sequence.state"
	sequenceTempFile     = "sequence.state.tmp"
	sequenceStateVersion = "device-audit.endpoint-sequence.v1"
	// Evidence is signed at submission time; one hour stays inside the v1
	// 24-hour bound while leaving room for a bounded retry.
	evidenceLifetime = time.Hour
)

// sequenceStage is a test seam for forced-restart checks. Production leaves it
// as a no-op; it never receives key material, payloads or sequence values.
var sequenceStage = func(string) {}

// sequenceState is the endpoint's durable reservation high-water mark. Every
// value at or below LastReserved may already have been signed and is never
// issued again. It is local integrity state, not a secret or a receipt.
type sequenceState struct {
	SchemaVersion string `json:"schema_version"`
	DeploymentID  string `json:"deployment_id"`
	DeviceID      string `json:"device_id"`
	SigningKeyID  string `json:"signing_key_id"`
	LastReserved  uint64 `json:"last_reserved"`
}

func encodeSequence(state sequenceState) []byte {
	body, _ := json.Marshal(state)
	sum := sha256.Sum256(body)
	return append(sum[:], body...)
}

func decodeSequence(data []byte, receipt contracts.EnrollmentAcceptedV1) (sequenceState, error) {
	var state sequenceState
	if len(data) <= sha256.Size {
		return state, errors.New("invalid sequence state")
	}
	sum := sha256.Sum256(data[sha256.Size:])
	if !bytes.Equal(sum[:], data[:sha256.Size]) {
		return state, errors.New("sequence state checksum failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(data[sha256.Size:]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.More() {
		return state, errors.New("invalid sequence state")
	}
	if state.SchemaVersion != sequenceStateVersion || state.DeploymentID != receipt.DeploymentID || state.DeviceID != receipt.DeviceID || state.SigningKeyID != receipt.SigningKeyID {
		return state, errors.New("sequence state does not match admitted identity")
	}
	if state.LastReserved < receipt.LastSequence || state.LastReserved > contracts.MaxEnvelopeSequence {
		return state, errors.New("sequence state is below admission or out of range")
	}
	return state, nil
}

// initSequence records the admitted enrollment sequence before the receipt is
// saved, so a receipt never exists without sequence state in the normal path.
func (s *identityStore) initSequence(receipt contracts.EnrollmentAcceptedV1) error {
	data := encodeSequence(sequenceState{SchemaVersion: sequenceStateVersion, DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID, LastReserved: receipt.LastSequence})
	existing, err := s.read(sequenceFile)
	if errors.Is(err, os.ErrNotExist) {
		return s.write(sequenceFile, data)
	}
	if err != nil || !bytes.Equal(existing, data) {
		return errors.New("sequence state already advanced or damaged; reconcile with operator")
	}
	return nil
}

// reserveSequence durably commits the next mark before returning it. A crash
// before the rename leaves the old mark, and that value was never signed. A
// crash after it leaves a gap, which the v1 contract allows. Missing, damaged
// or exhausted state fails closed instead of restarting from admission.
func (s *identityStore) reserveSequence(receipt contracts.EnrollmentAcceptedV1) (uint64, error) {
	data, err := s.read(sequenceFile)
	if errors.Is(err, os.ErrNotExist) {
		return 0, errors.New("sequence state missing beside admission; refusing to reset; reconcile with operator")
	}
	if err != nil {
		return 0, err
	}
	state, err := decodeSequence(data, receipt)
	if err != nil {
		return 0, err
	}
	if state.LastReserved >= contracts.MaxEnvelopeSequence {
		return 0, errors.New("evidence sequence exhausted; re-enrollment requires an authorized recovery contract")
	}
	next := max(state.LastReserved+1, contracts.FirstEvidenceSequenceV1)
	state.LastReserved = next
	if err := s.replace(sequenceFile, sequenceTempFile, encodeSequence(state)); err != nil {
		return 0, err
	}
	return next, nil
}

// replace writes a private temporary file, flushes it, renames it over the
// target and flushes the result. Unix also flushes the directory entry.
func (s *identityStore) replace(name, temp string, data []byte) error {
	if info, err := s.root.Lstat(temp); err == nil {
		// A leftover temporary file is an uncommitted reservation from a crash.
		if !info.Mode().IsRegular() || s.root.Remove(temp) != nil {
			return errors.New("unsafe or unremovable sequence temporary file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect sequence temporary file")
	}
	f, err := s.root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("create sequence temporary file")
	}
	if err := checkPrivateFile(f, s.principal); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return errors.New("write sequence state")
	}
	if f.Sync() != nil || f.Close() != nil {
		return errors.New("sync sequence state")
	}
	sequenceStage("before-commit")
	if s.root.Rename(temp, name) != nil {
		return errors.New("commit sequence state")
	}
	committed, err := s.root.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return errors.New("reopen sequence state")
	}
	defer committed.Close()
	if err := checkPrivateFile(committed, s.principal); err != nil {
		return err
	}
	// On NTFS, flushing the renamed file forces the metadata journal through
	// the rename. Unix additionally flushes the directory.
	if committed.Sync() != nil || syncDirectory(s.root) != nil {
		return errors.New("sync committed sequence state")
	}
	sequenceStage("after-commit")
	return nil
}

func (s *identityStore) admitted() (*identity, contracts.EnrollmentAcceptedV1, error) {
	var receipt contracts.EnrollmentAcceptedV1
	i, err := s.load(false)
	if err != nil {
		return nil, receipt, err
	}
	data, err := s.read(receiptFile)
	if err != nil {
		return nil, receipt, errors.New("admission receipt unavailable")
	}
	if json.Unmarshal(data, &receipt) != nil {
		return nil, receipt, errors.New("invalid admission state")
	}
	receipt, err = s.receipt(i, receipt.DeploymentID, receipt.DeviceID)
	if err != nil {
		return nil, receipt, err
	}
	return i, receipt, nil
}

func readEvidencePayload(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, contracts.MaxEvidencePayloadBytes+1))
	if err != nil || len(data) == 0 || len(data) > contracts.MaxEvidencePayloadBytes {
		return nil, errors.New("read bounded evidence payload")
	}
	return data, nil
}

// signEvidence binds an exact telemetry v2 payload to the admitted identity
// and a freshly reserved sequence. The payload is validated before a sequence
// is consumed. Errors are generic so payload content never reaches logs.
func (s *identityStore) signEvidence(payload []byte, now time.Time) (contracts.EvidenceEnvelopeV1, error) {
	i, receipt, err := s.admitted()
	if err != nil {
		return contracts.EvidenceEnvelopeV1{}, err
	}
	now = now.UTC().Truncate(time.Second)
	envelope := contracts.EvidenceEnvelopeV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{SchemaVersion: contracts.EvidenceEnvelopeV1Version, DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID,
			Sequence: contracts.FirstEvidenceSequenceV1, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(evidenceLifetime).Format(time.RFC3339)},
		PayloadSchemaVersion: contracts.TelemetryV2Version,
		PayloadBase64:        base64.StdEncoding.EncodeToString(payload),
	}
	digest := sha256.Sum256(payload)
	envelope.PayloadSHA256 = hex.EncodeToString(digest[:])
	envelope.Signature = strings.Repeat("00", ed25519.SignatureSize)
	if envelope.Validate() != nil {
		return contracts.EvidenceEnvelopeV1{}, errors.New("payload is not valid telemetry v2 for the admitted device")
	}
	envelope.Signature = ""
	if envelope.Sequence, err = s.reserveSequence(receipt); err != nil {
		return contracts.EvidenceEnvelopeV1{}, err
	}
	return signEvidenceEnvelope(i.signing, envelope)
}

// signEvidenceEnvelope signs CT04 canonical bytes and verifies the result with
// the matching public key before release.
func signEvidenceEnvelope(key ed25519.PrivateKey, envelope contracts.EvidenceEnvelopeV1) (contracts.EvidenceEnvelopeV1, error) {
	message, err := envelope.SigningBytes()
	if err != nil {
		return contracts.EvidenceEnvelopeV1{}, errors.New("build evidence signing bytes")
	}
	envelope.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	if envelope.VerifySignature(key.Public().(ed25519.PublicKey)) != nil {
		return contracts.EvidenceEnvelopeV1{}, errors.New("signed evidence failed self-verification")
	}
	return envelope, nil
}
