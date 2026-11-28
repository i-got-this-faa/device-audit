//go:build !windows

package main

import "errors"

func diagnosticBootID() (string, error) {
	return "", errors.New("isolated diagnostic probes require Windows")
}
