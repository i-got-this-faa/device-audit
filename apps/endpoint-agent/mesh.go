package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// The application tunnel imports the enrolled identity; it never enrolls or
// creates keys. Mesh address secrets use the same protected directory ACLs.
// It returns the verified controller acknowledgement; a rejected one is also an error.
func sendMeshEvidence(ctx context.Context, stateDir, serverKey string, controllerKey ed25519.PublicKey, regionFile string, input io.Reader) (contracts.AcknowledgementV1, error) {
	s, err := openIdentityStore(stateDir, false)
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	defer s.close()
	receipt, err := s.status()
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	i, err := s.load(false)
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	address, err := s.read("mesh-address")
	if err != nil {
		return contracts.AcknowledgementV1{}, errors.New("private mesh address unavailable")
	}
	regionJSON, err := os.ReadFile(regionFile)
	if err != nil {
		return contracts.AcknowledgementV1{}, errors.New("read self-hosted DERP region")
	}
	region, err := mesh.DecodeRegion(regionJSON)
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	var envelope contracts.EvidenceEnvelopeV1
	data, err := io.ReadAll(io.LimitReader(input, (400<<10)+1))
	if err != nil || len(data) > 400<<10 || json.Unmarshal(data, &envelope) != nil || envelope.VerifySignature(i.signing.Public().(ed25519.PublicKey)) != nil {
		return contracts.AcknowledgementV1{}, errors.New("valid locally signed CT04 evidence required on stdin")
	}
	if envelope.DeploymentID != receipt.DeploymentID || envelope.DeviceID != receipt.DeviceID || envelope.SigningKeyID != receipt.SigningKeyID {
		return contracts.AcknowledgementV1{}, errors.New("evidence does not match stored admission")
	}
	private := i.network.Bytes()
	defer clear(private)
	// A cold Tailcat session discovers the controller through the relay.
	// Report a bad relay explicitly instead of an opaque delivery timeout.
	if err := mesh.CheckRelay(ctx, mesh.DERPConfig{Region: region}, private); err != nil {
		return contracts.AcknowledgementV1{}, fmt.Errorf("%v; evidence not sent, retain the signed envelope", err)
	}
	client, err := mesh.NewClient(mesh.ClientConfig{NetworkPrivateKey: private, ServerAddr: string(address), ServerPublicKey: serverKey, DERP: mesh.DERPConfig{Region: region}})
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	defer client.Close()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+mesh.ApplicationHost+"/v1/evidence", bytes.NewReader(data))
	if err != nil {
		return contracts.AcknowledgementV1{}, errors.New("create mesh evidence request")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.HTTPClient().Do(r)
	if err != nil {
		return contracts.AcknowledgementV1{}, errors.New("mesh evidence delivery failed; commit outcome may be uncertain")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return contracts.AcknowledgementV1{}, errors.New("mesh evidence response was interrupted; commit outcome may be uncertain")
	}
	var ack contracts.AcknowledgementV1
	if json.Unmarshal(body, &ack) != nil || ack.VerifyForEvidence(controllerKey, envelope) != nil {
		return contracts.AcknowledgementV1{}, fmt.Errorf("mesh evidence was not acknowledged (HTTP %d); retain the original signed envelope", response.StatusCode)
	}
	if ack.Status != "accepted" {
		// A replay can follow a lost accepted response; it does not prove this payload was stored.
		return ack, fmt.Errorf("controller rejected evidence: %s; retain the original signed envelope", *ack.RejectionReason)
	}
	return ack, nil
}

// loadControllerPublicKey reads a pinned Ed25519 key in PKIX PEM format.
func loadControllerPublicKey(path string) (ed25519.PublicKey, error) {
	const maxKey = 16 << 10
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("controller key file is unreadable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxKey+1))
	if err != nil || len(data) > maxKey {
		return nil, errors.New("controller key file is unreadable or too large")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("controller key file must be a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("controller key file must hold an Ed25519 public key")
	}
	return key, nil
}
