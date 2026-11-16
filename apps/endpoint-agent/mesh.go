package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// The application tunnel imports the enrolled identity; it never enrolls or
// creates keys. Mesh address secrets use the same protected directory ACLs.
func sendMeshEvidence(ctx context.Context, stateDir, serverKey, regionFile string, input io.Reader) error {
	s, err := openIdentityStore(stateDir, false)
	if err != nil {
		return err
	}
	defer s.close()
	receipt, err := s.status()
	if err != nil {
		return err
	}
	i, err := s.load(false)
	if err != nil {
		return err
	}
	address, err := s.read("mesh-address")
	if err != nil {
		return errors.New("private mesh address unavailable")
	}
	regionJSON, err := os.ReadFile(regionFile)
	if err != nil {
		return errors.New("read self-hosted DERP region")
	}
	region, err := mesh.DecodeRegion(regionJSON)
	if err != nil {
		return err
	}
	var envelope contracts.EvidenceEnvelopeV1
	data, err := io.ReadAll(io.LimitReader(input, (400<<10)+1))
	if err != nil || len(data) > 400<<10 || json.Unmarshal(data, &envelope) != nil || envelope.VerifySignature(i.signing.Public().(ed25519.PublicKey)) != nil {
		return errors.New("valid locally signed CT04 evidence required on stdin")
	}
	if envelope.DeploymentID != receipt.DeploymentID || envelope.DeviceID != receipt.DeviceID || envelope.SigningKeyID != receipt.SigningKeyID {
		return errors.New("evidence does not match stored admission")
	}
	private := i.network.Bytes()
	defer clear(private)
	client, err := mesh.NewClient(mesh.ClientConfig{NetworkPrivateKey: private, ServerAddr: string(address), ServerPublicKey: serverKey, DERP: mesh.DERPConfig{Region: region}})
	if err != nil {
		return err
	}
	defer client.Close()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+mesh.ApplicationHost+"/v1/evidence", bytes.NewReader(data))
	if err != nil {
		return errors.New("create mesh evidence request")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.HTTPClient().Do(r)
	if err != nil {
		return errors.New("mesh evidence delivery failed; commit outcome may be uncertain")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return errors.New("mesh evidence was not acknowledged; retain the original signed envelope")
	}
	return nil
}
