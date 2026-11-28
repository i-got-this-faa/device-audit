package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
)

func signFederatedUpdate(t *testing.T, deploymentID string, dev meshTestDevice, round contracts.FederatedRoundV1, seq uint64, issued, expires time.Time, weights []float64, samples uint32) contracts.FederatedUpdateV1 {
	t.Helper()
	rawWeights := make([]byte, len(weights)*8)
	for i, w := range weights {
		binary.BigEndian.PutUint64(rawWeights[i*8:], math.Float64bits(w))
	}
	sum := sha256.Sum256(rawWeights)
	u := contracts.FederatedUpdateV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.FederatedUpdateV1Version,
			DeploymentID:  deploymentID,
			DeviceID:      dev.id,
			SigningKeyID:  dev.keyID,
			Sequence:      seq,
			IssuedAt:      issued.UTC().Format(time.RFC3339),
			ExpiresAt:     expires.UTC().Format(time.RFC3339),
		},
		RoundID:          round.RoundID,
		BaseModelVersion: round.BaseModelVersion,
		BaseModelSHA256:  round.BaseModelSHA256,
		CandidateID:      round.CandidateID,
		FeatureVersion:   round.FeatureVersion,
		SampleCount:      samples,
		WeightsBase64:    base64.StdEncoding.EncodeToString(rawWeights),
		UpdateSHA256:     hex.EncodeToString(sum[:]),
	}
	signing, err := u.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	u.Signature = hex.EncodeToString(ed25519.Sign(dev.signing, signing))
	return u
}

func TestFederatedUpdatesValidRestartAndSequenceProtection(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round1 := b.round("round:1")
	if _, _, err := b.repo.OpenRound(ctx, round1, b.actor); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", b.devices[0].id, b.devices[0].keyID); err != nil {
		t.Fatal(err)
	}
	otherBase := b.storeModel(t, "baseline.2", []string{contracts.ModelPurposeTraining})

	meshSrv := newMeshTestServer(t, MeshConfig{
		Node:       &meshTestNode{},
		Repository: b.repo,
		Now:        b.clock.Now,
	})
	postMeshUpdate := func(peer string, target string, payload []byte) (int, federatedUpdateResponse) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, peer))
		w := httptest.NewRecorder()
		meshSrv.Handler.ServeHTTP(w, r)
		var resp federatedUpdateResponse
		if w.Header().Get("Content-Type") == "application/json" {
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
		}
		return w.Code, resp
	}

	now := b.clock.Now()
	wA := []float64{0.1, -0.2, 0.3, -0.4, 0.5, -0.6}
	uA := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round1, 2, now, now.Add(time.Hour), wA, 48)
	gotA, created, err := b.repo.AcceptUpdate(ctx, uA)
	if err != nil || !created || !equalFloat64Slice(gotA.Weights, wA) || gotA.SampleCount != 48 || gotA.Sequence != 2 {
		t.Fatalf("accept uA failed: got=%+v created=%v err=%v", gotA, created, err)
	}

	// Device B posts directly to /v1/federated/updates without calling AcceptParticipant first.
	wB := []float64{-0.1, 0.25, -0.35, 0.45, -0.55, 0.65}
	uB := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], round1, 2, now, now.Add(time.Hour), wB, 64)
	rawB, _ := json.Marshal(uB)
	codeB, respB := postMeshUpdate(b.devices[1].peer, "/v1/federated/updates", rawB)
	if codeB != http.StatusCreated || respB.Status != "accepted" || !respB.Created || respB.Sequence != 2 {
		t.Fatalf("mesh accept uB: code=%d resp=%+v", codeB, respB)
	}

	// Idempotent retries succeed with created=false without changing state.
	repeatA, createdRepeat, err := b.repo.AcceptUpdate(ctx, uA)
	if err != nil || createdRepeat || !reflect.DeepEqual(repeatA, gotA) {
		t.Fatalf("repeat A = %+v created=%v err=%v", repeatA, createdRepeat, err)
	}
	codeBRepeat, respBRepeat := postMeshUpdate(b.devices[1].peer, "/v1/federated/updates", rawB)
	if codeBRepeat != http.StatusOK || respBRepeat.Status != "accepted" || respBRepeat.Created {
		t.Fatalf("repeat B HTTP: code=%d resp=%+v", codeBRepeat, respBRepeat)
	}

	// Different update for same device in same round conflicts (repository and HTTP).
	wAConflict := []float64{0.9, -0.2, 0.3, -0.4, 0.5, -0.6}
	uAConflict := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round1, 3, now, now.Add(time.Hour), wAConflict, 48)
	if _, _, err := b.repo.AcceptUpdate(ctx, uAConflict); !errors.Is(err, federated.ErrUpdateConflict) {
		t.Fatalf("conflicting update err=%v want ErrUpdateConflict", err)
	}
	rawAConflict, _ := json.Marshal(uAConflict)
	if code, _ := postMeshUpdate(b.devices[0].peer, "/v1/federated/updates", rawAConflict); code != http.StatusConflict {
		t.Fatalf("conflicting HTTP status=%d want 409", code)
	}

	// Telemetry sequence 2 on devA fails as replay because federated update advanced last_sequence to 2;
	// sequence 3 telemetry succeeds, then round 2 update with sequence 3 fails as ErrUpdateReplay while sequence 4 succeeds.
	tel2 := contracts.EvidenceEnvelopeV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.EvidenceEnvelopeV1Version, DeploymentID: b.repo.deploymentID, DeviceID: b.devices[0].id,
			SigningKeyID: b.devices[0].keyID, Sequence: 2, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		},
		PayloadSchemaVersion: contracts.TelemetryV2Version,
		PayloadBase64:        base64.StdEncoding.EncodeToString(meshTestTelemetry(t, b.devices[0].id, now)),
	}
	telSum := sha256.Sum256(meshTestTelemetry(t, b.devices[0].id, now))
	tel2.PayloadSHA256 = hex.EncodeToString(telSum[:])
	telSign2, _ := tel2.SigningBytes()
	tel2.Signature = hex.EncodeToString(ed25519.Sign(b.devices[0].signing, telSign2))
	if _, err := b.repo.AcceptEvidence(ctx, tel2); err == nil {
		t.Fatal("telemetry reused sequence accepted after federated update")
	}
	tel3 := tel2
	tel3.Sequence = 3
	telSign3, _ := tel3.SigningBytes()
	tel3.Signature = hex.EncodeToString(ed25519.Sign(b.devices[0].signing, telSign3))
	if _, err := b.repo.AcceptEvidence(ctx, tel3); err != nil {
		t.Fatalf("telemetry sequence 3 failed: %v", err)
	}

	b.clock.Advance(2 * time.Minute)
	round2 := b.round("round:2")
	round2.BaseModelVersion = otherBase.ModelVersion
	round2.BaseModelSHA256 = otherBase.ArtifactSHA256
	if _, _, err := b.repo.OpenRound(ctx, round2, b.actor); err != nil {
		t.Fatal(err)
	}
	uReplay := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round2, 3, b.clock.Now(), b.clock.Now().Add(30*time.Minute), wA, 16)
	if _, _, err := b.repo.AcceptUpdate(ctx, uReplay); !errors.Is(err, federated.ErrUpdateReplay) {
		t.Fatalf("update reusing telemetry sequence 3 err=%v want ErrUpdateReplay", err)
	}
	uSeq4 := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round2, 4, b.clock.Now(), b.clock.Now().Add(30*time.Minute), wA, 16)
	if _, created, err := b.repo.AcceptUpdate(ctx, uSeq4); err != nil || !created {
		t.Fatalf("update seq 4 failed: created=%v err=%v", created, err)
	}

	// Controller restart retains accepted updates deterministically, even after round1 deadline passes.
	b.clock.Advance(time.Hour)
	repeatAfterClose, createdAfterClose, err := b.repo.AcceptUpdate(ctx, uA)
	if err != nil || createdAfterClose || !reflect.DeepEqual(repeatAfterClose, gotA) {
		t.Fatalf("repeat after deadline = %+v created=%v err=%v", repeatAfterClose, createdAfterClose, err)
	}
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	updates1, err := restarted.AcceptedUpdates(ctx, "round:1")
	if err != nil || len(updates1) != 2 || updates1[0].DeviceID != b.devices[0].id || updates1[1].DeviceID != b.devices[1].id {
		t.Fatalf("restarted round:1 updates = %+v err=%v", updates1, err)
	}
	updates2, err := restarted.AcceptedUpdates(ctx, "round:2")
	if err != nil || len(updates2) != 1 || updates2[0].Sequence != 4 {
		t.Fatalf("restarted round:2 updates = %+v err=%v", updates2, err)
	}
	round1Rec, err := restarted.Round(ctx, "round:1")
	if err != nil || round1Rec.Status != federated.RoundClosed || len(round1Rec.Accepted) != 2 {
		t.Fatalf("round1 after restart = %+v err=%v", round1Rec, err)
	}
}

func TestFederatedUpdatesRejectsWrongBaseIneligibleRevokedBadSigExpiredAndNonfinite(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:1")
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}
	otherBase := b.storeModel(t, "baseline.other", []string{contracts.ModelPurposeTraining})

	now := b.clock.Now()
	validWeights := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6}
	baseUpdate := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now, now.Add(time.Hour), validWeights, 32)

	resign := func(dev meshTestDevice, u contracts.FederatedUpdateV1) contracts.FederatedUpdateV1 {
		signing, err := u.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		u.Signature = hex.EncodeToString(ed25519.Sign(dev.signing, signing))
		return u
	}

	assertReject := func(name string, u contracts.FederatedUpdateV1, want error) {
		t.Helper()
		if _, _, err := b.repo.AcceptUpdate(ctx, u); !errors.Is(err, want) {
			t.Fatalf("%s: got err=%v want %v", name, err, want)
		}
	}

	// Wrong base version, wrong base digest, wrong candidate, wrong feature version, wrong parameter count.
	wrongBaseVer := baseUpdate
	wrongBaseVer.BaseModelVersion = otherBase.ModelVersion
	assertReject("wrong base version", resign(b.devices[0], wrongBaseVer), federated.ErrUpdateIncompatible)

	wrongBaseSHA := baseUpdate
	wrongBaseSHA.BaseModelSHA256 = otherBase.ArtifactSHA256
	assertReject("wrong base sha", resign(b.devices[0], wrongBaseSHA), federated.ErrUpdateIncompatible)

	wrongCandidate := baseUpdate
	wrongCandidate.CandidateID = "candidate:other"
	assertReject("wrong candidate", resign(b.devices[0], wrongCandidate), federated.ErrUpdateIncompatible)

	wrongFeature := baseUpdate
	wrongFeature.FeatureVersion = "features.other.v1"
	assertReject("wrong feature", resign(b.devices[0], wrongFeature), federated.ErrUpdateIncompatible)

	wrongParams := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now, now.Add(time.Hour), []float64{0.1, 0.2, 0.3, 0.4, 0.5}, 32)
	assertReject("wrong param count", wrongParams, federated.ErrUpdateIncompatible)

	// Unknown round.
	unknownRound := baseUpdate
	unknownRound.RoundID = "round:missing"
	assertReject("unknown round", resign(b.devices[0], unknownRound), federated.ErrRoundNotFound)

	// Nonfinite weights (NaN, +Inf), tampered digest, and oversized weight count (>4096).
	nanBytes := make([]byte, 6*8)
	binary.BigEndian.PutUint64(nanBytes, math.Float64bits(math.NaN()))
	nanSum := sha256.Sum256(nanBytes)
	nanUpdate := baseUpdate
	nanUpdate.WeightsBase64 = base64.StdEncoding.EncodeToString(nanBytes)
	nanUpdate.UpdateSHA256 = hex.EncodeToString(nanSum[:])
	assertReject("nan weights", nanUpdate, federated.ErrUpdateInvalid)

	infBytes := make([]byte, 6*8)
	binary.BigEndian.PutUint64(infBytes, math.Float64bits(math.Inf(1)))
	infSum := sha256.Sum256(infBytes)
	infUpdate := baseUpdate
	infUpdate.WeightsBase64 = base64.StdEncoding.EncodeToString(infBytes)
	infUpdate.UpdateSHA256 = hex.EncodeToString(infSum[:])
	assertReject("inf weights", infUpdate, federated.ErrUpdateInvalid)

	badDigest := baseUpdate
	badDigest.UpdateSHA256 = strings.Repeat("f", 64)
	assertReject("bad update sha", badDigest, federated.ErrUpdateInvalid)

	tooMany := make([]byte, 4097*8)
	tooManySum := sha256.Sum256(tooMany)
	oversizedUpdate := baseUpdate
	oversizedUpdate.WeightsBase64 = base64.StdEncoding.EncodeToString(tooMany)
	oversizedUpdate.UpdateSHA256 = hex.EncodeToString(tooManySum[:])
	assertReject("oversized weights", oversizedUpdate, federated.ErrUpdateInvalid)

	// Wrong deployment, unknown device, swapped key, forged signature.
	wrongDeploy := baseUpdate
	wrongDeploy.DeploymentID = "deployment:other"
	assertReject("wrong deployment", resign(b.devices[0], wrongDeploy), federated.ErrUpdateUnauthorized)

	unknownDev := baseUpdate
	unknownDev.DeviceID = "device:unknown"
	assertReject("unknown device", resign(b.devices[0], unknownDev), federated.ErrUpdateUnauthorized)

	wrongKey := baseUpdate
	wrongKey.SigningKeyID = b.devices[1].keyID
	assertReject("wrong key", resign(b.devices[1], wrongKey), federated.ErrUpdateUnauthorized)

	badSig := baseUpdate
	badSig.Signature = strings.Repeat("00", ed25519.SignatureSize)
	assertReject("bad sig", badSig, federated.ErrUpdateUnauthorized)

	// Unlisted device c and ineligible device d.
	unlisted := signFederatedUpdate(t, b.repo.deploymentID, b.devices[2], round, 2, now, now.Add(time.Hour), validWeights, 32)
	assertReject("unlisted participant", unlisted, federated.ErrParticipantNotEligible)
	ineligible := signFederatedUpdate(t, b.repo.deploymentID, b.devices[3], round, 2, now, now.Add(time.Hour), validWeights, 32)
	assertReject("ineligible participant", ineligible, federated.ErrParticipantNotEligible)

	// Future issued, issued before open, expires after deadline.
	future := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now.Add(2*time.Minute), now.Add(time.Hour), validWeights, 32)
	assertReject("future issued", future, federated.ErrUpdateExpired)
	beforeOpen := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now.Add(-time.Minute), now.Add(time.Hour), validWeights, 32)
	assertReject("before open", beforeOpen, federated.ErrUpdateExpired)
	pastDeadline := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now, now.Add(2*time.Hour), validWeights, 32)
	assertReject("expires past deadline", pastDeadline, federated.ErrUpdateExpired)

	// Revoke device b after admitting it to the round -> update still rejected.
	if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", b.devices[1].id, b.devices[1].keyID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.RevokeDevice(ctx, contracts.DeviceRevocationRequestV1{
		SchemaVersion: contracts.DeviceRevocationRequestV1Version, DeviceID: b.devices[1].id, ReasonReference: "incident:revoked",
	}, "https://id.example.test", "admin:test"); err != nil {
		t.Fatal(err)
	}
	revokedB := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], round, 2, now, now.Add(time.Hour), validWeights, 32)
	assertReject("revoked after admission", revokedB, federated.ErrUpdateUnauthorized)
	assertReject("revoked also ErrParticipantNotEligible", revokedB, federated.ErrParticipantNotEligible)

	// Deadline crossed while waiting on the device enrollment lock refuses update and closes the round.
	deadline := mustParseRoundTime(round.Deadline)
	lockTx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var locked int
	if err := lockTx.QueryRowContext(ctx, `SELECT 1 FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`,
		b.repo.deploymentID, b.devices[0].id).Scan(&locked); err != nil {
		lockTx.Rollback()
		t.Fatal(err)
	}
	b.clock.Advance(deadline.Sub(b.clock.Now()) - time.Second)
	raceDone := make(chan error, 1)
	go func() {
		_, _, err := b.repo.AcceptUpdate(ctx, baseUpdate)
		raceDone <- err
	}()
	time.Sleep(40 * time.Millisecond)
	b.clock.Advance(time.Second)
	if err := lockTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if raceErr := <-raceDone; !errors.Is(raceErr, federated.ErrUpdateExpired) || !errors.Is(raceErr, federated.ErrRoundNotOpen) {
		t.Fatalf("deadline crossed after lock wait err=%v want ErrUpdateExpired + ErrRoundNotOpen", raceErr)
	}

	updates, err := b.repo.AcceptedUpdates(ctx, "round:1")
	if err != nil || len(updates) != 0 {
		t.Fatalf("refused updates leaked into accepted set: %+v err=%v", updates, err)
	}
	for _, dev := range b.devices {
		stored, err := b.repo.Device(ctx, dev.id)
		if err != nil || stored.LastSequence != contracts.EnrollmentSequenceV1 {
			t.Fatalf("device %s sequence mutated by refused update: last=%d err=%v", dev.id, stored.LastSequence, err)
		}
	}
}

func TestFederatedUpdatesConcurrentDuplicateAndConflicting(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:concurrent")
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}
	now := b.clock.Now()
	sameWeights := []float64{0.2, 0.4, 0.6, 0.8, 1.0, 1.2}
	dupUpdate := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now, now.Add(time.Hour), sameWeights, 20)

	const workers = 8
	var createdDup atomic.Int32
	var dupErrors atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, created, err := b.repo.AcceptUpdate(ctx, dupUpdate)
			if err != nil {
				dupErrors.Add(1)
				return
			}
			if created {
				createdDup.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if dupErrors.Load() != 0 || createdDup.Load() != 1 {
		t.Fatalf("concurrent duplicate created=%d errors=%d want 1/0", createdDup.Load(), dupErrors.Load())
	}

	// Now 8 goroutines concurrently submit distinct updates for device B in the same round.
	var createdConflict atomic.Int32
	var conflicts atomic.Int32
	var otherErrors atomic.Int32
	var wg2 sync.WaitGroup
	start2 := make(chan struct{})
	for i := range workers {
		u := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], round, 2, now, now.Add(time.Hour), []float64{float64(i), 0.1, 0.2, 0.3, 0.4, 0.5}, uint32(10+i))
		wg2.Add(1)
		go func(u contracts.FederatedUpdateV1) {
			defer wg2.Done()
			<-start2
			_, created, err := b.repo.AcceptUpdate(ctx, u)
			switch {
			case err == nil && created:
				createdConflict.Add(1)
			case errors.Is(err, federated.ErrUpdateConflict):
				conflicts.Add(1)
			default:
				otherErrors.Add(1)
			}
		}(u)
	}
	close(start2)
	wg2.Wait()
	if createdConflict.Load() != 1 || conflicts.Load() != workers-1 || otherErrors.Load() != 0 {
		t.Fatalf("concurrent conflict created=%d conflicts=%d other=%d", createdConflict.Load(), conflicts.Load(), otherErrors.Load())
	}

	updates, err := b.repo.AcceptedUpdates(ctx, "round:concurrent")
	if err != nil || len(updates) != 2 {
		t.Fatalf("concurrent round accepted count=%d err=%v", len(updates), err)
	}
}

func TestFederatedUpdatesDatabaseGuardsAndAtRestCorruption(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:db")
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}
	now := b.clock.Now()
	u := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now, now.Add(time.Hour), []float64{1, 2, 3, 4, 5, 6}, 12)
	if _, created, err := b.repo.AcceptUpdate(ctx, u); err != nil || !created {
		t.Fatal(err)
	}

	// Database triggers refuse update/delete and bad direct inserts.
	for name, stmt := range map[string]string{
		"update row": `UPDATE federated_updates SET sample_count = 999`,
		"delete row": `DELETE FROM federated_updates`,
		"bad digest": fmt.Sprintf(`INSERT INTO federated_updates
			SELECT deployment_id, round_id, '%s', '%s', 2, candidate_id, base_model_version, base_model_sha256,
				feature_version, parameter_count, sample_count, weights_bytes, decode(repeat('00',32),'hex'), request_sha256,
				issued_at, expires_at, accepted_at, envelope FROM federated_updates LIMIT 1`, b.devices[1].id, b.devices[1].keyID),
		"unadmitted participant": fmt.Sprintf(`INSERT INTO federated_updates
			SELECT deployment_id, round_id, '%s', '%s', 2, candidate_id, base_model_version, base_model_sha256,
				feature_version, parameter_count, sample_count, weights_bytes, update_sha256, decode(repeat('11',32),'hex'),
				issued_at, expires_at, accepted_at, envelope FROM federated_updates LIMIT 1`, b.devices[1].id, b.devices[1].keyID),
		"ineligible participant": fmt.Sprintf(`INSERT INTO federated_updates
			SELECT deployment_id, round_id, '%s', '%s', 2, candidate_id, base_model_version, base_model_sha256,
				feature_version, parameter_count, sample_count, weights_bytes, update_sha256, decode(repeat('22',32),'hex'),
				issued_at, expires_at, accepted_at, envelope FROM federated_updates LIMIT 1`, b.devices[3].id, b.devices[3].keyID),
		"wrong param count": fmt.Sprintf(`INSERT INTO federated_updates
			SELECT deployment_id, round_id, '%s', '%s', 2, candidate_id, base_model_version, base_model_sha256,
				feature_version, 5, sample_count, substring(weights_bytes from 1 for 40),
				sha256(substring(weights_bytes from 1 for 40)), decode(repeat('33',32),'hex'),
				issued_at, expires_at, accepted_at, envelope FROM federated_updates LIMIT 1`, b.devices[1].id, b.devices[1].keyID),
	} {
		if _, err := b.db.Exec(stmt); err == nil {
			t.Fatalf("database allowed %s", name)
		}
	}

	// Corrupt stored envelope inside transaction bypassed trigger via superuser disable?
	// Temporarily drop immutability trigger as test owner to simulate storage corruption at rest.
	if _, err := b.db.Exec(`ALTER TABLE federated_updates DISABLE TRIGGER federated_updates_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE federated_updates SET envelope = envelope || '{"sample_count":999}'::jsonb`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`ALTER TABLE federated_updates ENABLE TRIGGER federated_updates_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.AcceptedUpdates(ctx, "round:db"); !errors.Is(err, federated.ErrUpdateCorrupt) {
		t.Fatalf("corrupted stored envelope err=%v want ErrUpdateCorrupt", err)
	}
}
