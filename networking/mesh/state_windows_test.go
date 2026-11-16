package mesh

import (
	"os"
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

func TestWindowsMeshStateRejectsUnprotectedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plain")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := InitializeServer(dir); err == nil {
		t.Fatal("existing directory without the mesh ACL was accepted")
	}
}

func TestWindowsMeshStateRejectsBroadACL(t *testing.T) {
	principal, err := meshPrincipal()
	if err != nil {
		t.Fatal(err)
	}
	for _, damage := range []string{"directory", "file", "deny-read"} {
		t.Run(damage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "server")
			if err := InitializeServer(dir); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "server.json")
			if damage == "directory" {
				target = dir
			}
			defer setTestACL(t, target, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+principal+")")
			if damage == "deny-read" {
				setTestACL(t, target, "D:P(D;;FR;;;"+principal+")(A;;FA;;;"+principal+")")
			} else {
				setTestACL(t, target, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+principal+")(A;OICI;FR;;;WD)")
			}
			if _, _, err := loadServerState(dir); err == nil {
				t.Fatal("broad or unreadable ACL accepted")
			}
		})
	}
}
