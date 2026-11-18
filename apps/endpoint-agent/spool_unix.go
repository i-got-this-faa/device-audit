//go:build linux || darwin

package main

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func validateSpoolDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("evidence spool requires a private directory owned by the endpoint")
	}
	return nil
}

func validateSpoolFile(f *os.File) error { return checkPrivateFile(f, "") }

func commitSpoolRename(root *os.Root, from, to string) error {
	if err := root.Rename(from, to); err != nil {
		return err
	}
	return syncDirectory(root)
}

func lockSpoolFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
