//go:build !windows

package main

import (
	"context"
	"errors"
)

var errTrainingPlatform = errors.New("budgeted federated training requires Windows")

func checkTrainingPower() error { return errTrainingPlatform }

func runTrainingProcess(context.Context, string, []byte) ([]byte, inferenceUsage, error) {
	return nil, inferenceUsage{}, errTrainingPlatform
}
