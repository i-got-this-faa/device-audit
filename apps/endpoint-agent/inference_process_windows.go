package main

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func configureInferenceProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW | windows.BELOW_NORMAL_PRIORITY_CLASS}
	cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
}
