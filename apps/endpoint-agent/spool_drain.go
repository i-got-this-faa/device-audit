package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	initialDeliveryBackoff = time.Second
	maxDeliveryBackoff     = time.Minute
)

// Delivery is optional so existing offline services keep sampling and spooling.
type deliveryConfig struct {
	MeshServerKey        string `json:"mesh_server_key"`
	DERPRegionFile       string `json:"derp_region_file"`
	ControllerAckKeyFile string `json:"controller_ack_key_file"`
}

func (c deliveryConfig) sender(store *identityStore, id *identity) (*meshEvidenceSender, error) {
	key, err := loadControllerPublicKey(c.ControllerAckKeyFile)
	if err != nil {
		return nil, err
	}
	return newMeshEvidenceSender(store, id, c.MeshServerKey, c.DERPRegionFile, key)
}

type sendEvidence func(context.Context, []byte, contracts.EvidenceEnvelopeV1) (contracts.AcknowledgementV1, error)

// Only this worker retires heads. The service may append while an attempt is
// in flight. A nil wake channel drains the current backlog and exits.
func drainEvidence(ctx context.Context, spool *evidenceSpool, key ed25519.PublicKey, send sendEvidence, wake <-chan struct{}, logf func(string, ...any)) error {
	backoff := initialDeliveryBackoff
	for ctx.Err() == nil {
		data, envelope, err := spool.head()
		if errors.Is(err, io.EOF) {
			if wake == nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-wake:
				continue
			}
		}
		if err != nil {
			return err
		}
		ack, err := send(ctx, data, envelope)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errDeliveryRetry) {
			delay := backoff/2 + rand.N(backoff/2)
			logf("spool sequence %d retained, retry in %s: %v", envelope.Sequence, delay.Round(time.Millisecond), err)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			backoff = min(backoff*2, maxDeliveryBackoff)
			continue
		}
		if err != nil {
			return fmt.Errorf("spool sequence %d retained: %w", envelope.Sequence, err)
		}
		if err := spool.acknowledge(key, ack); err != nil {
			return err
		}
		backoff = initialDeliveryBackoff
	}
	return nil
}
