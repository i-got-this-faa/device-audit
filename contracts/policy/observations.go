package policy

// Receipt and anchor vocabulary matches CT09. Empty strings mean this
// observation assigns no new receipt or anchor state.
const (
	AnchorUnverified = "unverified"
	AnchorPending    = "pending"
	AnchorFinalized  = "finalized"
	AnchorReverted   = "reverted"

	ReasonTransactionFailed = "transaction_failed"
	ReasonReorganized       = "reorganized"
	ReasonCommitmentAbsent  = "commitment_absent"
)

// ObservationRule is the recorded result of one chain observation.
// It is policy data. Applying it does not query a chain.
type ObservationRule struct {
	Name             string `json:"name"`
	AnchorState      string `json:"anchor_state"`
	ReceiptState     string `json:"receipt_state"`
	Reason           string `json:"reason"`
	ClaimsFinality   bool   `json:"claims_finality"`
	RetryAllowed     bool   `json:"retry_allowed"`
	PreservesHistory bool   `json:"preserves_history"`
	Action           string `json:"action"`
}

// Observations returns the CHAIN01 confirmation, revert, and outage rules.
func Observations() []ObservationRule {
	return []ObservationRule{
		{
			Name:             "not_submitted_or_outage",
			AnchorState:      AnchorUnverified,
			ClaimsFinality:   false,
			RetryAllowed:     true,
			PreservesHistory: true,
			Action:           "retain_off_chain_and_retry",
		},
		{
			Name:             "unknown_result_or_unfinalized_inclusion",
			AnchorState:      AnchorPending,
			ReceiptState:     AnchorPending,
			ClaimsFinality:   false,
			RetryAllowed:     true,
			PreservesHistory: true,
			Action:           "reconcile_before_retry",
		},
		{
			Name:             "verified_finalized_inclusion",
			AnchorState:      AnchorFinalized,
			ReceiptState:     AnchorFinalized,
			ClaimsFinality:   true,
			RetryAllowed:     false,
			PreservesHistory: true,
			Action:           "append_finalized_receipt",
		},
		{
			Name:             "failed_execution",
			AnchorState:      AnchorReverted,
			ReceiptState:     AnchorReverted,
			Reason:           ReasonTransactionFailed,
			ClaimsFinality:   false,
			RetryAllowed:     true,
			PreservesHistory: true,
			Action:           "review_before_new_transaction",
		},
		{
			Name:             "lost_canonical_inclusion",
			AnchorState:      AnchorReverted,
			ReceiptState:     AnchorReverted,
			Reason:           ReasonReorganized,
			ClaimsFinality:   false,
			RetryAllowed:     true,
			PreservesHistory: true,
			Action:           "clear_finality_and_reconcile",
		},
		{
			Name:             "commitment_absent_after_invalidation",
			AnchorState:      AnchorReverted,
			ReceiptState:     AnchorReverted,
			Reason:           ReasonCommitmentAbsent,
			ClaimsFinality:   false,
			RetryAllowed:     true,
			PreservesHistory: true,
			Action:           "retry_original_commitment",
		},
		{
			Name:             "source_disagreement_or_unverified_deployment",
			AnchorState:      AnchorUnverified,
			ClaimsFinality:   false,
			RetryAllowed:     false,
			PreservesHistory: true,
			Action:           "stop_submission_and_alert",
		},
		{
			Name:             "digest_conflict",
			ClaimsFinality:   false,
			RetryAllowed:     false,
			PreservesHistory: true,
			Action:           "stop_and_retain_both_records",
		},
	}
}
