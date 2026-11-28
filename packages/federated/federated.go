// Package federated owns coordinated local training and model promotion.
//
// FED01 #40 defines the durable round lifecycle and participant admission.
// FED09 #114 validates and persists signed participant updates before
// aggregation. FED03 #43 aggregates persisted updates into a reproducible
// candidate artifact. Promotion (FED10 #115) remains separate.
package federated

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// RoundStatus is the lifecycle state of one round. A round is opened once and
// leaves open only to closed or cancelled; neither state ever reopens.
type RoundStatus string

const (
	// RoundOpen admits participants until the round deadline.
	RoundOpen RoundStatus = "open"
	// RoundClosed means the deadline passed. No participant can be admitted.
	RoundClosed RoundStatus = "closed"
	// RoundCancelled means an administrator stopped the round before its deadline.
	RoundCancelled RoundStatus = "cancelled"
)

// Refusals a caller can match with errors.Is. Wrapped errors carry detail.
var (
	// ErrRoundConflict: the round ID or candidate ID is already used by a
	// different round. Repeating an identical request is not a conflict.
	ErrRoundConflict = errors.New("round or candidate already recorded with different content")
	// ErrRoundNotFound: no round has this ID in this deployment.
	ErrRoundNotFound = errors.New("round not found")
	// ErrRoundNotOpen: the round is closed or cancelled.
	ErrRoundNotOpen = errors.New("round is not open")
	// ErrBaseNotRegistered: the base is not a stored training artifact that
	// matches the round's digest, feature version and parameter count.
	ErrBaseNotRegistered = errors.New("base model is not a compatible registered training artifact")
	// ErrParticipantNotEligible: the device is not an eligible participant of
	// the round, uses another key, or is revoked now.
	ErrParticipantNotEligible = errors.New("participant is not eligible for this round")
	// ErrUpdateInvalid: the signed update failed structural, digest, bound, or
	// binary64 finiteness validation.
	ErrUpdateInvalid = errors.New("federated update is invalid")
	// ErrUpdateIncompatible: the update targets a different round, base model,
	// candidate, feature version, or parameter count.
	ErrUpdateIncompatible = errors.New("federated update does not match round or base artifact")
	// ErrUpdateConflict: the participant already committed a different update
	// in this round. Repeating an identical request is not a conflict.
	ErrUpdateConflict = errors.New("federated update conflicts with stored update")
	// ErrUpdateExpired: the update expired, fell outside the round window, or
	// arrived for a non-open or past-deadline round.
	ErrUpdateExpired = errors.New("federated update is expired or outside round window")
	// ErrUpdateReplay: the envelope sequence is not strictly greater than the
	// device's durable high-water mark.
	ErrUpdateReplay = errors.New("federated update sequence is stale or replayed")
	// ErrUpdateUnauthorized: the device is unknown, uses a mismatched key,
	// failed Ed25519 signature verification, belongs to another deployment, or
	// is revoked.
	ErrUpdateUnauthorized = errors.New("federated update signature or device key is unauthorized")
	// ErrUpdateCorrupt: persisted update bytes or digests failed integrity
	// verification on read.
	ErrUpdateCorrupt = errors.New("stored federated update failed integrity verification")
	// ErrNoUpdates: round closed with zero accepted updates.
	ErrNoUpdates = errors.New("round has no accepted updates to aggregate")
	// ErrInsufficientParticipants: accepted updates did not reach min_participants.
	ErrInsufficientParticipants = errors.New("round has fewer accepted updates than min_participants")
	// ErrAggregationFailed: aggregation could not produce a valid candidate artifact.
	ErrAggregationFailed = errors.New("federated aggregation failed")
	// ErrAggregationCorrupt: persisted aggregation record failed integrity checks.
	ErrAggregationCorrupt = errors.New("stored federated aggregation failed integrity verification")
	// ErrAggregationInvalid: invalid aggregation parameters or signing key.
	ErrAggregationInvalid = errors.New("invalid federated aggregation request")
)

// Actor is the authenticated console session that caused a transition.
type Actor = contracts.ModelActorV1

// Transition is one recorded change of round status. From is empty for the
// opening. By is nil when the controller closed the round at its deadline.
type Transition struct {
	From   RoundStatus
	To     RoundStatus
	Reason string
	At     time.Time
	By     *Actor
}

// Acceptance records that an eligible participant was admitted to the round's
// training work. It is not an accepted model update.
type Acceptance struct {
	DeviceID     string
	SigningKeyID string
	AcceptedAt   time.Time
}

// RoundRecord is the stored round with its current status and history.
type RoundRecord struct {
	Round       contracts.FederatedRoundV1
	Status      RoundStatus
	Accepted    []Acceptance
	Transitions []Transition
}

// AcceptedUpdate records one validated signed device update persisted for a round.
type AcceptedUpdate struct {
	DeploymentID     string
	RoundID          string
	DeviceID         string
	SigningKeyID     string
	Sequence         uint64
	CandidateID      string
	BaseModelVersion string
	BaseModelSHA256  string
	FeatureVersion   string
	ParameterCount   uint32
	SampleCount      uint32
	Weights          []float64
	UpdateSHA256     string
	RequestSHA256    string
	IssuedAt         time.Time
	ExpiresAt        time.Time
	AcceptedAt       time.Time
	Envelope         contracts.FederatedUpdateV1
}

// AggregationStatus is the terminal state of a round's aggregation attempt.
type AggregationStatus string

const (
	AggregationSucceeded AggregationStatus = "succeeded"
	AggregationFailed    AggregationStatus = "failed"
)

// AggregatedParticipant records the immutable provenance of one update
// included in an aggregation attempt.
type AggregatedParticipant struct {
	DeviceID      string `json:"device_id"`
	SigningKeyID  string `json:"signing_key_id"`
	Sequence      uint64 `json:"sequence"`
	SampleCount   uint32 `json:"sample_count"`
	UpdateSHA256  string `json:"update_sha256"`
	RequestSHA256 string `json:"request_sha256"`
}

// AggregationRecord captures one durable federated aggregation outcome with
// full participant, input, and reproducible candidate digests.
type AggregationRecord struct {
	DeploymentID          string
	RoundID               string
	CandidateID           string
	BaseModelVersion      string
	BaseModelSHA256       string
	FeatureVersion        string
	ParameterCount        uint32
	WeightingPolicy       string
	Status                AggregationStatus
	FailureReason         string
	Participants          []AggregatedParticipant
	TotalSamples          uint64
	InputSHA256           string
	Weights               []float64
	WeightsSHA256         string
	CandidateModelVersion string
	CandidateModelSHA256  string
	CreatedAt             time.Time
	By                    Actor
}

// Coordinator is the durable round lifecycle. Callers authorize the actor
// first. Every method is safe to repeat after an uncertain outcome.
type Coordinator interface {
	// OpenRound records a round against a registered base artifact. created is
	// false when an identical round is already stored; the stored record is
	// returned whatever its current status.
	OpenRound(ctx context.Context, round contracts.FederatedRoundV1, by Actor) (record RoundRecord, created bool, err error)
	// Round returns one round, closing it first when its deadline has passed.
	Round(ctx context.Context, roundID string) (RoundRecord, error)
	// AcceptParticipant admits one eligible, enrolled, unrevoked device with
	// the key named in the round snapshot. created is false for a repeat.
	AcceptParticipant(ctx context.Context, roundID, deviceID, signingKeyID string) (record RoundRecord, created bool, err error)
	// CancelRound stops an open round. Cancelling a cancelled round repeats;
	// a closed round cannot be cancelled.
	CancelRound(ctx context.Context, roundID string, by Actor) (RoundRecord, error)
	// CloseExpiredRounds closes every open round past its deadline and
	// returns how many it closed.
	CloseExpiredRounds(ctx context.Context) (int, error)
	// AcceptUpdate validates, authenticates, and durably records one signed
	// participant update for an open round, advancing device_enrollments.last_sequence.
	AcceptUpdate(ctx context.Context, update contracts.FederatedUpdateV1) (accepted AcceptedUpdate, created bool, err error)
	// AcceptedUpdates reads and integrity-verifies all durably accepted updates
	// for one round, ordered by device_id.
	AcceptedUpdates(ctx context.Context, roundID string) ([]AcceptedUpdate, error)
	// AggregateRound aggregates persisted accepted updates for a closed round
	// under the declared weighting policy and stores a reproducible candidate
	// artifact without modifying the active model.
	AggregateRound(ctx context.Context, roundID string, signer ed25519.PrivateKey, by Actor) (record AggregationRecord, created bool, err error)
	// Aggregation reads one round's persisted aggregation record and verifies its
	// stored weights digest.
	Aggregation(ctx context.Context, roundID string) (AggregationRecord, error)
}
