// Package audit defines the boundary between off-chain reports and contract receipts.
package audit

import "context"

type Commitment struct {
	ID            string // opaque identifier; never a raw hostname or serial number
	Digest        string
	PolicyVersion string
}

type Receipt struct {
	ChainID       string
	ContractID    string
	TransactionID string
	Finalized     bool
}

type Anchorer interface {
	Commit(context.Context, Commitment) (Receipt, error)
	Verify(context.Context, Commitment, Receipt) error
}
