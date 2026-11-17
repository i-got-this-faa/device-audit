// Package relaytest issues throwaway test certificates and relay files.
// Never use these helpers outside tests.
package relaytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/networking/relay"
)

const Hostname = "relay.device-audit.test"

type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	File string // PEM root, usable as SSL_CERT_FILE.
}

func NewCA(t testing.TB, dir string) *CA {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "device-audit relay test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	file := filepath.Join(dir, "ca.pem")
	writePEM(t, file, "CERTIFICATE", der)
	return &CA{cert: cert, key: k, File: file}
}

// Issue writes a leaf certificate for hosts and returns cert/key paths.
func (ca *CA) Issue(t testing.TB, dir string, notBefore, notAfter time.Time, hosts ...string) (string, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts,
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, hosts[0]+".pem"), filepath.Join(dir, hosts[0]+"-key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	writePEM(t, keyFile, "PRIVATE KEY", keyDER)
	return certFile, keyFile
}

// Valid issues a currently valid leaf for hosts.
func (ca *CA) Valid(t testing.TB, dir string, hosts ...string) (string, string) {
	return ca.Issue(t, dir, time.Now().Add(-time.Hour), time.Now().Add(12*time.Hour), hosts...)
}

func WriteAdmission(t testing.TB, path string, keys ...string) {
	t.Helper()
	data, err := json.Marshal(relay.Admission{Version: relay.AdmissionVersion, NetworkPublicKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func writePEM(t testing.TB, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}
