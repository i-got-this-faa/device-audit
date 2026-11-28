//go:build !windows

package main

import "errors"

// runService fails explicitly: the service host exists only for Windows, the
// selected endpoint platform.
func runService(string, string) error {
	return errors.New("--service is supported only on Windows")
}
