package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func validateSpoolDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("evidence spool requires a normal directory")
	}
	return checkEvidenceACL(dir)
}

func validateSpoolFile(f *os.File) error {
	var info windows.ByHandleFileInformation
	h := windows.Handle(f.Fd())
	if windows.GetFileInformationByHandle(h, &info) != nil || info.NumberOfLinks != 1 ||
		info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errors.New("unsafe evidence spool file")
	}
	principal, err := storagePrincipal()
	if err != nil {
		return err
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("read spool file ACL")
	}
	return validateEvidenceDACL(sd, principal)
}

// The installer protects the evidence parent against replacement and the
// identity lock serializes participants. MoveFileEx publishes a synced record
// within this same private directory with write-through semantics.
func commitSpoolRename(root *os.Root, from, to string) error {
	a, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), from))
	if err != nil {
		return err
	}
	b, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), to))
	if err != nil {
		return err
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_WRITE_THROUGH|windows.MOVEFILE_REPLACE_EXISTING)
}

func lockSpoolFile(f *os.File) error {
	var position windows.Overlapped
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &position)
}
