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
	if err := s.requireNoDiagnosticJob(); err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	i, receipt, err := s.admitted()
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	var envelope contracts.EvidenceEnvelopeV1
	data, readErr := io.ReadAll(io.LimitReader(input, maxSpoolRecordBytes+1))
	if readErr != nil || len(data) > maxSpoolRecordBytes || json.Unmarshal(data, &envelope) != nil || envelope.VerifySignature(i.signing.Public().(ed25519.PublicKey)) != nil {
		return contracts.AcknowledgementV1{}, errors.New("valid locally signed CT04 evidence required on stdin")
	}
	if envelope.DeploymentID != receipt.DeploymentID || envelope.DeviceID != receipt.DeviceID || envelope.SigningKeyID != receipt.SigningKeyID {
		return contracts.AcknowledgementV1{}, errors.New("evidence does not match stored admission")
	}
	sender, err := newMeshEvidenceSender(s, i, serverKey, regionFile, controllerKey)
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	defer sender.close()
	return sender.send(ctx, data, envelope)
}

var (
	errDeliveryRetry   = errors.New("temporary evidence delivery failure")
	errDeliveryBlocked = errors.New("evidence delivery blocked")
)

// The sender owns a single Tailcat session. A failed request drops that
// session so retry can rediscover the peer after a controller restart.
type meshEvidenceSender struct {
	config        mesh.ClientConfig
	controllerKey ed25519.PublicKey
	client        mesh.Client
	preflight     bool
}

func newMeshEvidenceSender(store *identityStore, id *identity, serverKey, regionFile string, controllerKey ed25519.PublicKey) (*meshEvidenceSender, error) {
	cfg, err := admittedMeshConfig(store, id, serverKey, regionFile)
	if err != nil {
		return nil, err
	}
	client, err := mesh.NewClient(cfg)
	if err != nil {
		clear(cfg.NetworkPrivateKey)
		return nil, err
	}
	return &meshEvidenceSender{config: cfg, client: client, controllerKey: controllerKey, preflight: true}, nil
}

func admittedMeshConfig(store *identityStore, id *identity, serverKey, regionFile string) (mesh.ClientConfig, error) {
	address, err := store.read("mesh-address")
	if err != nil {
		return mesh.ClientConfig{}, errors.New("private mesh address unavailable")
	}
	f, err := os.Open(regionFile)
	if err != nil {
		return mesh.ClientConfig{}, errors.New("read self-hosted DERP region")
	}
	defer f.Close()
	regionJSON, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return mesh.ClientConfig{}, errors.New("read self-hosted DERP region")
	}
	region, err := mesh.DecodeRegion(regionJSON)
	if err != nil {
		return mesh.ClientConfig{}, err
	}
	return mesh.ClientConfig{NetworkPrivateKey: id.network.Bytes(), ServerAddr: string(address), ServerPublicKey: serverKey, DERP: mesh.DERPConfig{Region: region}}, nil
}

func (s *meshEvidenceSender) close() {
	if s.client != nil {
		s.client.Close()
	}
	clear(s.config.NetworkPrivateKey)
}

func (s *meshEvidenceSender) send(ctx context.Context, data []byte, envelope contracts.EvidenceEnvelopeV1) (contracts.AcknowledgementV1, error) {
	if err := s.connect(ctx); err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	ack, err := postMeshEvidence(ctx, s.client.HTTPClient(), s.controllerKey, data, envelope)
	s.resetOnRetry(err)
	return ack, err
}

func (s *meshEvidenceSender) connect(ctx context.Context) error {
	if s.preflight {
		if err := mesh.CheckRelay(ctx, s.config.DERP, s.config.NetworkPrivateKey); err != nil {
			return fmt.Errorf("%w: %v", errDeliveryRetry, err)
		}
		s.preflight = false
	}
	if s.client == nil {
		client, err := mesh.NewClient(s.config)
		if err != nil {
			return err
		}
		s.client = client
	}
	return nil
}

func (s *meshEvidenceSender) resetOnRetry(err error) {
	if errors.Is(err, errDeliveryRetry) && s.client != nil {
		s.client.Close()
		s.client = nil
		s.preflight = true
	}
}

func postMeshEvidence(ctx context.Context, client *http.Client, key ed25519.PublicKey, data []byte, envelope contracts.EvidenceEnvelopeV1) (contracts.AcknowledgementV1, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+mesh.ApplicationHost+"/v1/evidence", bytes.NewReader(data))
	if err != nil {
		return contracts.AcknowledgementV1{}, errors.New("create mesh evidence request")
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return contracts.AcknowledgementV1{}, fmt.Errorf("%w: mesh request failed; commit outcome may be uncertain", errDeliveryRetry)
	}
	defer response.Body.Close()
	status := response.StatusCode
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500 {
		return contracts.AcknowledgementV1{}, fmt.Errorf("%w: controller returned HTTP %d", errDeliveryRetry, status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSpoolAckBytes+1))
	if err != nil {
		return contracts.AcknowledgementV1{}, fmt.Errorf("%w: mesh response was interrupted; commit outcome may be uncertain", errDeliveryRetry)
	}
	var ack contracts.AcknowledgementV1
	if parseSpoolAck(body, &ack) != nil || ack.VerifyForEvidence(key, envelope) != nil {
		if status == http.StatusForbidden {
			return contracts.AcknowledgementV1{}, fmt.Errorf("%w: mesh admission denied (HTTP 403); check device admission or revocation", errDeliveryBlocked)
		}
		return contracts.AcknowledgementV1{}, fmt.Errorf("%w: missing or invalid controller acknowledgement (HTTP %d)", errDeliveryBlocked, status)
	}
	if ack.Status != "accepted" {
		return ack, fmt.Errorf("%w: controller rejected evidence (%s)", errDeliveryBlocked, *ack.RejectionReason)
	}
	if status != http.StatusOK {
		return contracts.AcknowledgementV1{}, fmt.Errorf("%w: accepted acknowledgement with unexpected HTTP %d", errDeliveryBlocked, status)
	}
	return ack, nil
}

func loadControllerPublicKey(path string) (ed25519.PublicKey, error) {
	key, err := loadPinnedEd25519Key(path)
	if err != nil {
		return nil, fmt.Errorf("controller %w", err)
	}
	return key, nil
}

// loadPinnedEd25519Key reads a configured Ed25519 trust root in PKIX PEM format.
func loadPinnedEd25519Key(path string) (ed25519.PublicKey, error) {
	const maxKey = 16 << 10
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("key file is unreadable")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxKey+1))
	if err != nil || len(data) > maxKey {
		return nil, errors.New("key file is unreadable or too large")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("key file must be a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok {
		return nil, errors.New("key file must hold an Ed25519 public key")
	}
	return key, nil
}
