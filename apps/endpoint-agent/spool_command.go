package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func runSpoolCommand(configPath, controllerKeyPath string, acknowledge bool, input io.Reader, output io.Writer) error {
	cfg, err := loadServiceConfig(configPath)
	if err != nil {
		return err
	}
	store, err := openIdentityStore(cfg.StateDir, false)
	if err != nil {
		return err
	}
	defer store.close()
	i, receipt, err := store.admitted()
	if err != nil {
		return err
	}
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, i.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		return err
	}
	defer spool.close()
	if acknowledge {
		key, err := loadControllerPublicKey(controllerKeyPath)
		if err != nil {
			return err
		}
		const maxAck = 16 << 10
		data, err := io.ReadAll(io.LimitReader(input, maxAck+1))
		var ack contracts.AcknowledgementV1
		if err != nil || len(data) > maxAck || json.Unmarshal(data, &ack) != nil {
			return errors.New("read bounded signed acknowledgement")
		}
		return spool.acknowledge(key, ack)
	}
	data, _, err := spool.head()
	if errors.Is(err, io.EOF) {
		return errors.New("evidence spool is empty")
	}
	if err != nil {
		return err
	}
	_, err = output.Write(data)
	return err
}
