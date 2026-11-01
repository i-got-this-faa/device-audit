package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const keyFile = "identity.keys"
const receiptFile = "admission.json"

// Private material stays out of JSON and routine diagnostic formatting.
type identity struct {
	signing ed25519.PrivateKey
	network *ecdh.PrivateKey
}

func (*identity) String() string   { return "[endpoint identity redacted]" }
func (*identity) GoString() string { return "[endpoint identity redacted]" }

func newIdentity() (*identity, error) {
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate signing identity")
	}
	network, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate network identity")
	}
	return &identity{signing: signing, network: network}, nil
}

func (i *identity) start(deployment, device string) contracts.EnrollmentStartV1 {
	return contracts.EnrollmentStartV1{SchemaVersion: contracts.EnrollmentStartV1Version, DeploymentID: deployment, DeviceID: device,
		PublicKey: hex.EncodeToString(i.signing.Public().(ed25519.PublicKey)), NetworkPublicKey: hex.EncodeToString(i.network.PublicKey().Bytes())}
}

type identityStore struct {
	root      *os.Root
	unlock    func()
	principal string
}

func (s *identityStore) close() { s.unlock(); s.root.Close() }

// Existing files are immutable. Partial creation is deliberately unrecoverable
// without operator intervention, rather than silently creating a new identity.
func (s *identityStore) write(name string, data []byte) error {
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("identity state already exists or cannot be created")
	}
	defer f.Close()
	if err := checkPrivateFile(f, s.principal); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return errors.New("write identity state")
	}
	if err := f.Sync(); err != nil {
		return errors.New("sync identity state")
	}
	if err := f.Close(); err != nil {
		return errors.New("close identity state")
	}
	return syncDirectory(s.root)
}

func (s *identityStore) read(name string) ([]byte, error) {
	info, err := s.root.Lstat(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("inspect identity state")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("identity state must be a regular file")
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, errors.New("open identity state")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("identity state changed while opening")
	}
	if err := checkPrivateFile(f, s.principal); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(data) > 16384 {
		return nil, errors.New("read identity state")
	}
	return data, nil
}

func (s *identityStore) load(create bool) (*identity, error) {
	data, err := s.read(keyFile)
	if errors.Is(err, os.ErrNotExist) && create {
		// A receipt without keys is damage, not first provisioning.
		for _, name := range []string{receiptFile, "scope.json"} {
			if _, err := s.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("identity missing beside admission state")
			}
		}
		i, err := newIdentity()
		if err != nil {
			return nil, err
		}
		plain := append([]byte("device-audit.keys.v1\x00"), i.signing.Seed()...)
		plain = append(plain, i.network.Bytes()...)
		defer clear(plain)
		sealed, err := protectKeys(plain)
		if err != nil {
			return nil, err
		}
		if err := s.write(keyFile, sealed); err != nil {
			return nil, err
		}
		return i, nil
	}
	if err != nil {
		return nil, errors.New("identity unavailable; explicit enrollment required for first provisioning")
	}
	plain, err := unprotectKeys(data)
	if err != nil {
		return nil, errors.New("identity decryption failed")
	}
	defer clear(plain)
	prefix := []byte("device-audit.keys.v1\x00")
	if len(plain) != len(prefix)+64 || !bytes.Equal(plain[:len(prefix)], prefix) {
		return nil, errors.New("invalid identity storage")
	}
	network, err := ecdh.X25519().NewPrivateKey(plain[len(prefix)+32:])
	if err != nil {
		return nil, errors.New("invalid network identity")
	}
	i := &identity{signing: ed25519.NewKeyFromSeed(plain[len(prefix) : len(prefix)+32]), network: network}
	if i.start("", "").PublicKey == i.start("", "").NetworkPublicKey {
		return nil, errors.New("identity keys are not distinct")
	}
	return i, nil
}

func (s *identityStore) receipt(i *identity, deployment, device string) (contracts.EnrollmentAcceptedV1, error) {
	var receipt contracts.EnrollmentAcceptedV1
	data, err := s.read(receiptFile)
	if err != nil {
		return receipt, err
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return receipt, errors.New("invalid admission state")
	}
	if err := verifyAcceptance(receipt, i.start(deployment, device)); err != nil {
		return receipt, err
	}
	scope, err := s.read("scope.json")
	expected, _ := json.Marshal(i.start(deployment, device))
	if err != nil || !bytes.Equal(scope, expected) {
		return receipt, errors.New("invalid stored identity scope")
	}
	return receipt, nil
}

func (s *identityStore) status() (contracts.EnrollmentAcceptedV1, error) {
	var receipt contracts.EnrollmentAcceptedV1
	i, err := s.load(false)
	if err != nil {
		return receipt, err
	}
	data, err := s.read(receiptFile)
	if err != nil {
		return receipt, errors.New("admission receipt unavailable")
	}
	if json.Unmarshal(data, &receipt) != nil {
		return receipt, errors.New("invalid admission state")
	}
	return s.receipt(i, receipt.DeploymentID, receipt.DeviceID)
}

func verifyAcceptance(v contracts.EnrollmentAcceptedV1, start contracts.EnrollmentStartV1) error {
	key, _ := hex.DecodeString(start.PublicKey)
	id, _ := contracts.SigningKeyIDV1(ed25519.PublicKey(key))
	if v.Validate() != nil || v.DeploymentID != start.DeploymentID || v.DeviceID != start.DeviceID || v.SigningKeyID != id || v.NetworkPublicKey != start.NetworkPublicKey {
		return fmt.Errorf("admission does not match local identity and scope")
	}
	return nil
}
