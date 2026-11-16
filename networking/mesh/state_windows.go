package mesh

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/tailscale/tailcat"
	"golang.org/x/sys/windows"
	"tailscale.com/types/key"
)

type serverState struct {
	Version int
	Node    key.NodePrivate
	PSK     tailcat.PresharedKey
}

// meshPrincipal matches the endpoint store: an enabled per-service SID when
// present, otherwise the user SID. LocalService without a service SID fails
// closed. This is not LocalService qualification.
func meshPrincipal() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", errors.New("read mesh state owner")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return "", errors.New("read mesh service identity")
	}
	for _, group := range groups.AllGroups() {
		if strings.HasPrefix(group.Sid.String(), "S-1-5-80-") && group.Sid.String() != "S-1-5-80-0" && group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			return group.Sid.String(), nil
		}
	}
	if user.User.Sid.String() == "S-1-5-19" {
		return "", errors.New("LocalService requires an enabled per-service SID")
	}
	return user.User.Sid.String(), nil
}

func privateDescriptor(principal string) (*windows.SECURITY_DESCRIPTOR, error) {
	// OWNER RIGHTS suppresses the owner's implicit WRITE_DAC right.
	return windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + principal + ")(A;OICI;RC;;;OW)")
}

func createPrivateDirectory(path, principal string) error {
	sd, err := privateDescriptor(principal)
	if err != nil {
		return errors.New("create mesh ACL")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("invalid mesh state path")
	}
	err = windows.CreateDirectory(name, &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd})
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return errors.New("create mesh state directory")
	}
	return nil
}

func openState(dir string) (*os.Root, func(), error) {
	principal, err := meshPrincipal()
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("mesh server directory requires current owner, protected ACL, and no symlink")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, errors.New("open mesh server directory")
	}
	dirFile, err := r.Open(".")
	if err != nil {
		r.Close()
		return nil, nil, errors.New("open mesh server directory ACL")
	}
	opened, statErr := dirFile.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		dirFile.Close()
		r.Close()
		return nil, nil, errors.New("mesh server directory changed while opening")
	}
	aclErr := checkWindowsACL(dirFile, principal, true)
	dirFile.Close()
	if aclErr != nil {
		r.Close()
		return nil, nil, aclErr
	}
	if info, err := r.Lstat("mesh.lock"); err == nil && !info.Mode().IsRegular() {
		r.Close()
		return nil, nil, errors.New("unsafe mesh server lock")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		r.Close()
		return nil, nil, errors.New("inspect mesh server lock")
	}
	lock, err := r.OpenFile("mesh.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		r.Close()
		return nil, nil, errors.New("open mesh server lock")
	}
	if err := checkPrivateFile(lock, principal); err != nil {
		lock.Close()
		r.Close()
		return nil, nil, err
	}
	var overlapped windows.Overlapped
	if windows.LockFileEx(windows.Handle(lock.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped) != nil {
		lock.Close()
		r.Close()
		return nil, nil, errors.New("mesh state is unsafe or in use")
	}
	return r, sync.OnceFunc(func() { lock.Close(); r.Close() }), nil
}

func checkPrivateFile(f *os.File, principal string) error {
	return checkWindowsACL(f, principal, false)
}

func checkWindowsACL(f *os.File, principal string, directory bool) error {
	handle := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!directory && (info.NumberOfLinks != 1 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0)) {
		return errors.New("unsafe mesh state file type or link")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("read mesh state ACL")
	}
	owner, _, err := sd.Owner()
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || userErr != nil || (!owner.Equals(user.User.Sid) && owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544") {
		return errors.New("unexpected mesh state owner")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("mesh state requires a restrictive DACL")
	}
	expected, err := privateDescriptor(principal)
	if err != nil {
		return errors.New("build expected mesh ACL")
	}
	want, _, _ := expected.DACL()
	actual := aclBytes(dacl)
	allowed := aclBytes(want)
	for pos := 8; pos+4 <= len(actual); {
		if !directory {
			actual[pos+1] &^= windows.INHERITED_ACE | windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		}
		size := int(actual[pos+2]) | int(actual[pos+3])<<8
		if size < 4 {
			return errors.New("invalid mesh state ACL")
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
		return errors.New("mesh state ACL grants unexpected access")
	}
	control, _, err := sd.Control()
	if err != nil || (directory && control&windows.SE_DACL_PROTECTED == 0) {
		return errors.New("mesh state directory must disable inherited permissions")
	}
	return nil
}

func aclBytes(acl *windows.ACL) []byte {
	header := unsafe.Slice((*byte)(unsafe.Pointer(acl)), 8)
	size := int(header[2]) | int(header[3])<<8
	return bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(acl)), size))
}

func WriteAddress(dir, address string) error {
	principal, err := meshPrincipal()
	if err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("mesh server directory requires current owner, protected ACL, and no symlink")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("open private mesh address directory")
	}
	defer r.Close()
	dirFile, err := r.Open(".")
	if err != nil {
		return errors.New("open mesh server directory ACL")
	}
	opened, statErr := dirFile.Stat()
	aclErr := checkWindowsACL(dirFile, principal, true)
	dirFile.Close()
	if statErr != nil || !os.SameFile(info, opened) || aclErr != nil {
		if aclErr != nil {
			return aclErr
		}
		return errors.New("mesh server directory changed while opening")
	}
	// Read/write so the new handle can be checked for its DACL before the secret is kept.
	f, err := r.OpenFile("mesh-address", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = r.OpenFile("mesh-address", os.O_RDONLY, 0)
		if err != nil {
			return errors.New("open existing private mesh address")
		}
		defer f.Close()
		data, readErr := io.ReadAll(io.LimitReader(f, 64<<10))
		if checkPrivateFile(f, principal) != nil || readErr != nil || string(data) != address {
			return errors.New("mesh address differs or is unsafe; explicit reprovisioning required")
		}
		return nil
	}
	if err != nil {
		return errors.New("create private mesh address")
	}
	defer f.Close()
	if checkPrivateFile(f, principal) != nil {
		return errors.New("unsafe mesh address file")
	}
	if _, err := f.WriteString(address); err != nil {
		return errors.New("write private mesh address")
	}
	if f.Sync() != nil || f.Close() != nil {
		return errors.New("sync private mesh address")
	}
	return nil
}

// InitializeServer is exclusive provisioning; startup never repairs missing keys.
func InitializeServer(dir string) error {
	principal, err := meshPrincipal()
	if err != nil {
		return err
	}
	if err := createPrivateDirectory(dir, principal); err != nil {
		return err
	}
	r, release, err := openState(dir)
	if err != nil {
		return err
	}
	defer release()
	f, err := r.OpenFile("server.json", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("mesh server state already exists or cannot be created")
	}
	defer f.Close()
	s := serverState{Version: 1, Node: key.NewNode(), PSK: tailcat.NewPresharedKey()}
	if checkPrivateFile(f, principal) != nil || json.NewEncoder(f).Encode(s) != nil || f.Sync() != nil || f.Close() != nil {
		return errors.New("persist mesh server state failed; explicit recovery required")
	}
	return nil
}

func loadServerState(dir string) (serverState, func(), error) {
	var s serverState
	principal, err := meshPrincipal()
	if err != nil {
		return s, nil, err
	}
	r, release, err := openState(dir)
	if err != nil {
		return s, nil, err
	}
	f, err := r.OpenFile("server.json", os.O_RDONLY, 0)
	if err != nil {
		release()
		return s, nil, errors.New("mesh state missing; explicit provisioning required")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	info, statErr := f.Stat()
	if statErr != nil || info.Size() > 4096 || checkPrivateFile(f, principal) != nil || d.Decode(&s) != nil || d.Decode(new(json.RawMessage)) != io.EOF || s.Version != 1 || s.Node.IsZero() || s.PSK.IsZero() {
		release()
		return serverState{}, nil, errors.New("invalid private mesh server state")
	}
	return s, release, nil
}
