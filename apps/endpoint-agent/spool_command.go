package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const maxSpoolAckBytes = 16 << 10

type spoolOperation string

const (
	spoolShowHead    spoolOperation = "next"
	spoolAcceptHead  spoolOperation = "ack"
	spoolArchiveHead spoolOperation = "archive-expired"
	spoolSession     spoolOperation = "session"
	spoolDrain       spoolOperation = "drain"
)

var errEmptySpool = errors.New("evidence spool is empty")

func runSpoolCommand(ctx context.Context, configPath, controllerKeyPath string, operation spoolOperation, input io.Reader, output, warnings io.Writer) error {
	var key ed25519.PublicKey
	var err error
	if operation == spoolAcceptHead || operation == spoolSession {
		key, err = loadControllerPublicKey(controllerKeyPath)
		if err != nil {
			return err
		}
	}
	var ack contracts.AcknowledgementV1
	if operation == spoolAcceptHead {
		data, err := io.ReadAll(io.LimitReader(input, maxSpoolAckBytes+1))
		if err != nil || parseSpoolAck(data, &ack) != nil {
			return errors.New("read bounded signed acknowledgement")
		}
	}
	var outputAfterUnlock []byte
	err = withEvidenceSpool(configPath, warnings, func(cfg serviceConfig, store *identityStore, id *identity, spool *evidenceSpool) error {
		switch operation {
		case spoolAcceptHead:
			return spool.acknowledge(key, ack)
		case spoolArchiveHead:
			name, err := spool.archiveExpired(time.Now())
			outputAfterUnlock = []byte(name + "\n")
			return err
		case spoolSession:
			return drainSpoolSession(spool, key, input, output)
		case spoolDrain:
			if cfg.Delivery == nil {
				return errors.New("--spool-drain requires delivery settings in the service config")
			}
			sender, err := cfg.Delivery.sender(store, id)
			if err != nil {
				return err
			}
			defer sender.close()
			logf := func(format string, args ...any) { fmt.Fprintf(warnings, format+"\n", args...) }
			return drainEvidence(ctx, spool, sender.controllerKey, sender.send, nil, logf)
		case spoolShowHead:
			data, _, err := spool.head()
			outputAfterUnlock = data
			return err
		default:
			return errors.New("unknown spool operation")
		}
	})
	if errors.Is(err, io.EOF) {
		return errEmptySpool
	}
	if err != nil || len(outputAfterUnlock) == 0 {
		return err
	}
	_, err = output.Write(outputAfterUnlock)
	return err
}

func withEvidenceSpool(configPath string, warnings io.Writer, run func(serviceConfig, *identityStore, *identity, *evidenceSpool) error) error {
	cfg, err := loadServiceConfig(configPath)
	if err != nil {
		return err
	}
	store, err := openIdentityStore(cfg.StateDir, false)
	if err != nil {
		return err
	}
	i, receipt, err := store.admitted()
	if err != nil {
		store.close()
		return err
	}
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, i.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		store.close()
		return err
	}
	err = run(cfg, store, i, spool)
	recoveredTail := spool.recoveredTail
	spool.close()
	store.close()
	if recoveredTail {
		fmt.Fprintf(warnings, "preserved torn legacy evidence in %s\n", spoolLegacyTail)
	}
	return err
}

// Each line written to output is the exact queue head. The peer returns a
// newline-terminated signed acknowledgement. EOF leaves the current head queued.
func drainSpoolSession(spool *evidenceSpool, key ed25519.PublicKey, input io.Reader, output io.Writer) error {
	reader := bufio.NewReaderSize(input, maxSpoolAckBytes+1)
	for {
		data, _, err := spool.head()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := output.Write(data); err != nil {
			return err
		}
		line, err := reader.ReadSlice('\n')
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil
		}
		var ack contracts.AcknowledgementV1
		if err != nil || parseSpoolAck(line, &ack) != nil {
			return errors.New("read bounded newline-terminated acknowledgement")
		}
		if err := spool.acknowledge(key, ack); err != nil {
			return err
		}
	}
}

func parseSpoolAck(data []byte, ack *contracts.AcknowledgementV1) error {
	if len(data) > maxSpoolAckBytes || json.Unmarshal(data, ack) != nil {
		return errors.New("invalid signed acknowledgement")
	}
	return nil
}
