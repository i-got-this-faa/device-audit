//go:build !windows

package main

import "os/exec"

func configureInferenceProcess(cmd *exec.Cmd) {
	cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
}
