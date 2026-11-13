//go:build linux || darwin

package mesh

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/tailscale/tailcat"
	"golang.org/x/sys/unix"
	"tailscale.com/types/key"
)

type serverState struct {
	Version int
	Node    key.NodePrivate
	PSK     tailcat.PresharedKey
}

func openState(dir string) (*os.Root, func(), error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, nil, errors.New("mesh server directory requires current owner, mode 0700, and no symlink")
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, errors.New("open mesh server directory")
	}
	lock, err := r.OpenFile("mesh.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		r.Close()
		return nil, nil, errors.New("open mesh server lock")
	}
	if privateFile(lock) != nil || unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		lock.Close()
		r.Close()
		return nil, nil, errors.New("mesh state is unsafe or in use")
	}
	return r, sync.OnceFunc(func() { lock.Close(); r.Close() }), nil
}

func privateFile(f *os.File) error {
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0600 {
		return errors.New("mesh state requires a regular 0600 file")
	}
	s := i.Sys().(*syscall.Stat_t)
	if s.Uid != uint32(os.Geteuid()) || s.Nlink != 1 {
		return errors.New("mesh state requires current owner and one link")
	}
	return nil
}

// WriteAddress publishes the PSK-bearing address only inside private server state.
// Existing addresses must match; configuration changes require explicit removal.
func WriteAddress(dir, address string) error {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("open private mesh address directory")
	}
	defer r.Close()
	f, err := r.OpenFile("mesh-address", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		f, err = r.OpenFile("mesh-address", os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return errors.New("open existing private mesh address")
		}
		defer f.Close()
		data, readErr := io.ReadAll(io.LimitReader(f, 64<<10))
		if privateFile(f) != nil || readErr != nil || string(data) != address {
			return errors.New("mesh address differs or is unsafe; explicit reprovisioning required")
		}
		return nil
	}
	if err != nil {
		return errors.New("create private mesh address")
	}
	defer f.Close()
	if privateFile(f) != nil {
		return errors.New("unsafe mesh address file")
	}
	if _, err := f.WriteString(address); err != nil {
		return errors.New("write private mesh address")
	}
	if f.Sync() != nil || f.Close() != nil {
		return errors.New("sync private mesh address")
	}
	d, err := r.Open(".")
	if err != nil {
		return errors.New("open mesh directory for sync")
	}
	defer d.Close()
	return d.Sync()
}

// InitializeServer is exclusive provisioning; startup never repairs missing keys.
func InitializeServer(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("create mesh state directory")
	}
	r, release, err := openState(dir)
	if err != nil {
		return err
	}
	defer release()
	f, err := r.OpenFile("server.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("mesh server state already exists or cannot be created")
	}
	defer f.Close()
	s := serverState{Version: 1, Node: key.NewNode(), PSK: tailcat.NewPresharedKey()}
	if privateFile(f) != nil || json.NewEncoder(f).Encode(s) != nil || f.Sync() != nil || f.Close() != nil {
		return errors.New("persist mesh server state failed; explicit recovery required")
	}
	d, err := r.Open(".")
	if err != nil {
		return errors.New("open mesh directory for sync")
	}
	defer d.Close()
	if d.Sync() != nil {
		return errors.New("sync mesh directory")
	}
	return nil
}

func loadServerState(dir string) (serverState, func(), error) {
	var s serverState
	r, release, err := openState(dir)
	if err != nil {
		return s, nil, err
	}
	f, err := r.OpenFile("server.json", os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		release()
		return s, nil, errors.New("mesh state missing; explicit provisioning required")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	info, statErr := f.Stat()
	if statErr != nil || info.Size() > 4096 || privateFile(f) != nil || d.Decode(&s) != nil || d.Decode(new(json.RawMessage)) != io.EOF || s.Version != 1 || s.Node.IsZero() || s.PSK.IsZero() {
		release()
		return serverState{}, nil, errors.New("invalid private mesh server state")
	}
	return s, release, nil
}
