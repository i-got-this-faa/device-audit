//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixIdentityPermissionsAndLinks(t *testing.T) {
	for _, damage := range []string{"directory-mode", "file-mode", "unreadable", "symlink", "hardlink", "directory-symlink", "lock-symlink"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private")
			s, err := openIdentityStore(path, true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.load(true); err != nil {
				t.Fatal(err)
			}
			s.close()
			key := filepath.Join(path, keyFile)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch damage {
			case "directory-mode":
				must(os.Chmod(path, 0755))
				defer os.Chmod(path, 0700)
			case "file-mode":
				must(os.Chmod(key, 0644))
			case "unreadable":
				must(os.Chmod(key, 0000))
				defer os.Chmod(key, 0600)
			case "symlink":
				must(os.Rename(key, key+".original"))
				must(os.Symlink(key+".original", key))
			case "hardlink":
				must(os.Link(key, key+".linked"))
			case "directory-symlink":
				link := path + ".link"
				must(os.Symlink(path, link))
				path = link
			case "lock-symlink":
				lock := filepath.Join(path, "identity.lock")
				must(os.Remove(lock))
				must(os.Symlink(key, lock))
			}
			s, err = openIdentityStore(path, false)
			if err == nil {
				defer s.close()
				if _, err = s.load(false); err == nil {
					t.Fatal("unsafe permissions/link accepted")
				}
			}
		})
	}
}
