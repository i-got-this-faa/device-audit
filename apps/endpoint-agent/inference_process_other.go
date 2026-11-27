//go:build !windows

package main

import (
	"bytes"
	"context"
	"os/exec"
)

func runInferenceChild(_ context.Context, cmd *exec.Cmd, data []byte) (inferenceUsage, error) {
	cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
	cmd.Stdin = bytes.NewReader(data)
	err := cmd.Run()
	return inferenceUsage{}, err
}
