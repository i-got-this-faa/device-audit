package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func setTestACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsIdentityDACLAndDPAPI(t *testing.T) {
	for _, damage := range []string{"directory", "file", "deny-read"} {
		t.Run(damage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private")
			s, err := openIdentityStore(path, true)
			if err != nil {
				t.Fatal(err)
			}
			i, err := s.load(true)
			if err != nil {
				s.close()
				t.Fatal(err)
			}
			data, err := s.read(keyFile)
			if err != nil {
				s.close()
				t.Fatal(err)
			}
			if bytes.Contains(data, i.signing.Seed()) || bytes.Contains(data, i.network.Bytes()) {
				s.close()
				t.Fatal("DPAPI storage contains plaintext key material")
			}
			principal := s.principal
			s.close()
			target := filepath.Join(path, keyFile)
			if damage == "directory" {
				target = path
			}
			// Restore access for test cleanup without changing the production behavior.
			defer setTestACL(t, target, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+principal+")")
			if damage == "deny-read" {
				setTestACL(t, target, "D:P(D;;FR;;;"+principal+")(A;;FA;;;"+principal+")")
			} else {
				setTestACL(t, target, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+principal+")(A;OICI;FR;;;WD)")
			}
			s, err = openIdentityStore(path, false)
			if err == nil {
				defer s.close()
				if _, err = s.load(false); err == nil {
					t.Fatal("broad or unreadable ACL accepted")
				}
			}
		})
	}
}
