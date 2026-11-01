//go:build linux || darwin

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openIdentityStore(path string, create bool) (*identityStore, error) {
	if create {
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errors.New("create private identity directory")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("identity directory requires current owner, mode 0700, and no symlink")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("open private identity directory")
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errors.New("inspect opened identity directory")
	}
	opened, err := dir.Stat()
	dir.Close()
	if err != nil || !os.SameFile(info, opened) {
		root.Close()
		return nil, errors.New("identity directory changed while opening")
	}
	s := &identityStore{root: root}
	lock, err := root.OpenFile("identity.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		root.Close()
		return nil, errors.New("open identity lock")
	}
	if err := checkPrivateFile(lock, ""); err != nil {
		lock.Close()
		root.Close()
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		return nil, errors.New("identity storage is in use")
	}
	s.unlock = func() { lock.Close() }
	return s, nil
}

func checkPrivateFile(f *os.File, _ string) error {
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("identity file requires mode 0600")
	}
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("identity file requires current owner and one link")
	}
	return nil
}

func syncDirectory(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return errors.New("open identity directory for sync")
	}
	defer f.Close()
	if f.Sync() != nil {
		return errors.New("sync identity directory")
	}
	return nil
}

// Unix development storage is access-controlled, not encrypted at rest.
func protectKeys(plain []byte) ([]byte, error) {
	sum := sha256.Sum256(plain)
	return append(sum[:], plain...), nil
}

func unprotectKeys(data []byte) ([]byte, error) {
	if len(data) < sha256.Size {
		return nil, errors.New("invalid key checksum")
	}
	sum := sha256.Sum256(data[sha256.Size:])
	if !bytes.Equal(sum[:], data[:sha256.Size]) {
		return nil, errors.New("invalid key checksum")
	}
	return bytes.Clone(data[sha256.Size:]), nil
}
