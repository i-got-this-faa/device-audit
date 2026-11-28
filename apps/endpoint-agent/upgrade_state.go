package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

const endpointStateFile = "endpoint-state.version"

// The package builder reads the same file from the source revision it builds.
//
//go:embed endpoint-state-version.txt
var endpointStateVersion string

func checkEndpointState(configPath string, required bool) error {
	f, err := os.Open(filepath.Join(filepath.Dir(configPath), endpointStateFile))
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil // Unmarked PKG01 and development installs use the same layout.
	}
	if err != nil {
		return errors.New("open endpoint state version")
	}
	defer f.Close()
	expected := []byte(strings.TrimSpace(endpointStateVersion) + "\n")
	version, err := io.ReadAll(io.LimitReader(f, int64(len(expected)+1)))
	if err != nil || !bytes.Equal(version, expected) {
		return errors.New("unsupported endpoint state version")
	}
	return nil
}

func checkUpgradeState(ctx context.Context, cfg serviceConfig, store *identityStore, receipt contracts.EnrollmentAcceptedV1, spool *evidenceSpool, run inferenceRunner) error {
	data, err := store.read(sequenceFile)
	if err != nil {
		return fmt.Errorf("read upgrade sequence state: %w", err)
	}
	state, err := decodeSequence(data, receipt)
	if err != nil {
		return err
	}
	if state.LastReserved < max(spool.settledThrough(), spool.lastSequence()) || state.LastReserved == contracts.MaxEnvelopeSequence {
		return errors.New("upgrade sequence state is behind durable evidence or exhausted")
	}

	journal, err := loadModelActivation(store)
	if err != nil {
		return err
	}
	if cfg.Inference == nil {
		if journal != (modelActivation{}) {
			return errors.New("stored model activation requires service inference configuration")
		}
		return nil
	}
	checkModel := func(config inferenceConfig, digest string) error {
		manifest, artifact, _, err := loadInferenceBundle(config)
		if err != nil {
			return err
		}
		if digest != "" && manifest.ArtifactSHA256 != digest {
			return errors.New("stored model slot differs from its activation journal")
		}
		if err := health.ValidateLogisticArtifact(manifest, artifact); err != nil {
			return err
		}
		if !probeInference(ctx, config, manifest, run) {
			return errors.New("stored model failed the inference worker health check")
		}
		return nil
	}
	if err := checkModel(*cfg.Inference, ""); err != nil {
		return fmt.Errorf("upgrade cannot load the provisioned model: %w", err)
	}
	for _, slot := range []modelSlot{journal.Active, journal.LastWorking} {
		if slot.Number != 0 {
			if err := checkModel(slot.config(store.root.Name(), cfg.Inference.PublisherKeyFile), slot.ArtifactSHA256); err != nil {
				return fmt.Errorf("upgrade cannot load model slot %d: %w", slot.Number, err)
			}
		}
	}
	return nil
}
