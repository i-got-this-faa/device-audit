//go:build linux || darwin

package main

import (
	"os"
	"testing"
)

func makeTestEvidencePrivate(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
}
