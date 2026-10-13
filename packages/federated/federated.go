// Package federated owns coordinated local training and model promotion.
package federated

import (
	"context"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type Round struct {
	ID               string
	BaseModelVersion string
	ParticipantIDs   []string
}

type Coordinator interface {
	StartRound(context.Context, Round) error
	SubmitUpdate(context.Context, contracts.ModelUpdate) error
	Aggregate(context.Context, string) (modelVersion string, err error)
}
