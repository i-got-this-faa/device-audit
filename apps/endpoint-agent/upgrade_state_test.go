package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndpointStateVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.json")
	if err := checkEndpointState(path, false); err != nil {
		t.Fatal(err)
	}
	if err := checkEndpointState(path, true); err == nil {
		t.Fatal("installer trial accepted unmarked state")
	}
	for _, version := range []string{"1\n", "2\n", "1\n2\n", ""} {
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), endpointStateFile), []byte(version), 0600); err != nil {
			t.Fatal(err)
		}
		if err := checkEndpointState(path, true); (err == nil) != (version == "1\n") {
			t.Fatalf("version %q: %v", version, err)
		}
	}
}

func TestUpgradeValidatesLiveStateWithoutRewritingIt(t *testing.T) {
	store, stateDir, identity, receipt := admittedStore(t)
	defer store.close()
	cfg := testServiceConfig(t, stateDir)
	req, base, key, report := activationFixture(t)
	cfg.Inference = &req.Config
	activationStage(t, store, req, base, key, report, receipt.DeploymentID, "upgrade.fixture")
	activateStagedModel(t.Context(), req.Config, store, receipt.DeploymentID, runActivationInference, t.Logf)
	activation, err := loadModelActivation(store)
	if err != nil || activation.Active.Number == 0 || activation.LastWorking.Number == 0 {
		t.Fatalf("initialize active and last-working model: %+v, %v", activation, err)
	}
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, identity.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.close()
	initial, err := store.read(sequenceFile)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.append(envelope); err != nil {
		t.Fatal(err)
	}

	before := map[string][]byte{}
	names := []string{keyFile, receiptFile, sequenceFile, modelActivationFile}
	for _, slot := range []modelSlot{activation.Active, activation.LastWorking} {
		for _, part := range []string{"manifest", "artifact", "evaluation"} {
			names = append(names, slot.file(part))
		}
	}
	for _, name := range names {
		before[name], err = store.read(name)
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func() error {
		return checkUpgradeState(t.Context(), cfg, store, receipt, spool, runActivationInference)
	}
	if err := check(); err != nil {
		t.Fatal(err)
	}
	for name, expected := range before {
		if data, err := store.read(name); err != nil || !bytes.Equal(data, expected) {
			t.Fatalf("trial changed %s: %v", name, err)
		}
	}
	if data, head, err := spool.head(); err != nil || head.Sequence != envelope.Sequence || len(data) == 0 {
		t.Fatalf("trial lost the queued envelope: %v", err)
	}
	if err := store.replace(sequenceFile, sequenceTempFile, initial); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), "behind durable evidence") {
		t.Fatalf("accepted a stale counter: %v", err)
	}
	if err := store.replace(sequenceFile, sequenceTempFile, before[sequenceFile]); err != nil {
		t.Fatal(err)
	}
	bad := activation.LastWorking.file("artifact")
	if err := store.replace(bad, bad+".tmp", []byte("invalid")); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), "cannot load model slot") {
		t.Fatalf("accepted a corrupt last-working model: %v", err)
	}
}
