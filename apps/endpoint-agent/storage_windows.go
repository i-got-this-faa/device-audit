package main

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func storagePrincipal() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", errors.New("read storage owner")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return "", errors.New("read service identity")
	}
	for _, group := range groups.AllGroups() {
		if strings.HasPrefix(group.Sid.String(), "S-1-5-80-") && group.Sid.String() != "S-1-5-80-0" && group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			return group.Sid.String(), nil
		}
	}
	// Interactive development uses the user SID. LocalService must have a service SID.
	if user.User.Sid.String() == "S-1-5-19" {
		return "", errors.New("LocalService requires an enabled per-service SID")
	}
	return user.User.Sid.String(), nil
}

func privateDescriptor(principal string) (*windows.SECURITY_DESCRIPTOR, error) {
	// OWNER RIGHTS suppresses the owner's implicit WRITE_DAC right, including
	// other services sharing LocalService but lacking this service SID.
	return windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + principal + ")(A;OICI;RC;;;OW)")
}

func openIdentityStore(path string, create bool) (*identityStore, error) {
	principal, err := storagePrincipal()
	if err != nil {
		return nil, err
	}
	if create {
		sd, err := privateDescriptor(principal)
		if err != nil {
			return nil, errors.New("create storage ACL")
		}
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, errors.New("invalid identity path")
		}
		err = windows.CreateDirectory(name, &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd})
		if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, errors.New("create private identity directory")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("identity directory is missing or is a reparse point")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.New("open identity directory")
	}
	dir, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errors.New("open identity directory ACL")
	}
	opened, statErr := dir.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		dir.Close()
		root.Close()
		return nil, errors.New("identity directory changed while opening")
	}
	err = checkWindowsACL(dir, principal, true)
	dir.Close()
	if err != nil {
		root.Close()
		return nil, err
	}
	if info, err := root.Lstat("identity.lock"); err == nil && !info.Mode().IsRegular() {
		root.Close()
		return nil, errors.New("unsafe identity lock")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		root.Close()
		return nil, errors.New("inspect identity lock")
	}
	lock, err := root.OpenFile("identity.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		root.Close()
		return nil, errors.New("open identity lock")
	}
	if err := checkPrivateFile(lock, principal); err != nil {
		lock.Close()
		root.Close()
		return nil, err
	}
	var overlapped windows.Overlapped
	if windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) != nil {
		lock.Close()
		root.Close()
		return nil, errors.New("identity storage is in use")
	}
	return &identityStore{root: root, principal: principal, unlock: func() { lock.Close() }}, nil
}

func checkPrivateFile(f *os.File, principal string) error {
	return checkWindowsACL(f, principal, false)
}

func checkWindowsACL(f *os.File, principal string, directory bool) error {
	handle := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!directory && (info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0)) {
		return errors.New("unsafe identity file type or link")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("read identity ACL")
	}
	owner, _, err := sd.Owner()
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || userErr != nil || (!owner.Equals(user.User.Sid) && owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		return errors.New("unexpected identity owner")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("identity requires a restrictive DACL")
	}
	// Compare canonical ACL bytes, allowing inherited ACE flags on children only.
	expected, err := privateDescriptor(principal)
	if err != nil {
		return errors.New("build expected identity ACL")
	}
	want, _, _ := expected.DACL()
	actual := aclBytes(dacl)
	allowed := aclBytes(want)
	// ACE_HEADER flags are at offset 1 of each ACE following the eight-byte ACL header.
	for pos := 8; pos+4 <= len(actual); {
		if !directory {
			actual[pos+1] &^= windows.INHERITED_ACE | windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		}
		size := int(actual[pos+2]) | int(actual[pos+3])<<8
		if size < 4 {
			return errors.New("invalid identity ACL")
		}
		pos += size
	}
	if !directory {
		for pos := 8; pos+4 <= len(allowed); {
			allowed[pos+1] = 0
			pos += int(allowed[pos+2]) | int(allowed[pos+3])<<8
		}
	}
	if !bytes.Equal(actual, allowed) {
		return errors.New("identity ACL grants unexpected access")
	}
	control, _, err := sd.Control()
	if err != nil || (directory && control&windows.SE_DACL_PROTECTED == 0) {
		return errors.New("identity directory must disable inherited permissions")
	}
	return nil
}

func aclBytes(acl *windows.ACL) []byte {
	header := unsafe.Slice((*byte)(unsafe.Pointer(acl)), 8)
	size := int(header[2]) | int(header[3])<<8
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(acl)), size))
}

func syncDirectory(_ *os.Root) error { return nil } // Windows flushes each file; no Unix directory-fsync equivalent.

func protectKeys(plain []byte) ([]byte, error)  { return dpapi(plain, false) }
func unprotectKeys(data []byte) ([]byte, error) { return dpapi(data, true) }

func dpapi(data []byte, decrypt bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty protected identity")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, errors.New("Windows identity protection failed")
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	result := unsafe.Slice(out.Data, int(out.Size))
	defer clear(result)
	return bytes.Clone(result), nil
}
