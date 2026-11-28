package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func TestFederatedAggregationReproducibleLogisticCandidateAndRetry(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()

	// Seed an active baseline model (using controller inference runtime + passing ML05 approval)
	// and verify aggregation NEVER modifies the active slot.
	activeArt := artifactWithVersion(t, loadBaselineModelBytes(t), "baseline.active.v1")
	activeMan := buildSignedControllerManifest(t, b.publisher, activeArt, health.ControllerInferenceRuntime())
	activeEvalBytes, activeEvalSHA := buildPassingML05Report(t, activeMan, 0.0, 2.0)
	_ = activeEvalBytes
	registerAndActivateModel(t, b.repo, b.publisher, activeArt, health.ControllerInferenceRuntime(), activeEvalSHA, health.ML05PolicyVersion)
	refsBefore, err := b.repo.ModelReferences(ctx)
	if err != nil || refsBefore.Active == nil {
		t.Fatalf("expected active model before aggregation: %+v err=%v", refsBefore, err)
	}

	// Register a logistic-baseline.v1 training+inference base model and open a round against it.
	baseArt, err := os.ReadFile(filepath.Join("..", "..", "models", "baseline", "backblaze-2013", "artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	baseMan := b.manifest(t, b.publisher, "logistic-baseline.backblaze-2013.v1", baseArt,
		contracts.ModelPurposeTraining, contracts.ModelPurposeInference)
	baseMan.Architecture = "logistic-baseline.v1"
	baseMan.RuntimeName = health.ControllerInferenceRuntime().Name
	baseMan.RuntimeVersion = health.ControllerInferenceRuntime().Version
	baseMan.ParameterCount = 7
	signMsg, err := baseMan.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	baseMan.Signature = fmt.Sprintf("%x", ed25519.Sign(b.publisher, signMsg))
	baseUpload := upload(baseMan, baseArt)
	if _, _, err := b.repo.PutModelArtifact(ctx, baseUpload, b.publisher.Public().(ed25519.PublicKey), contracts.ModelActorV1(b.actor)); err != nil {
		t.Fatal(err)
	}

	now := b.clock.Now()
	round := b.round("round:logistic:1")
	round.BaseModelVersion = baseMan.ModelVersion
	round.BaseModelSHA256 = baseMan.ArtifactSHA256
	round.FeatureVersion = baseMan.FeatureVersion
	round.ParameterCount = baseMan.ParameterCount
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}

	// While open before deadline, aggregation refuses cleanly without touching active or candidate.
	if _, _, err := b.repo.AggregateRound(ctx, round.RoundID, b.publisher, b.actor); !errors.Is(err, federated.ErrRoundNotOpen) {
		t.Fatalf("open round aggregate err=%v want ErrRoundNotOpen", err)
	}

	// Submit valid signed updates from devices A (10 samples) and B (30 samples).
	uA := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now, now.Add(time.Hour), []float64{2, 4, 6, 8, 10, 12, 14}, 10)
	uB := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], round, 2, now, now.Add(time.Hour), []float64{6, 8, 10, 12, 14, 16, 18}, 30)
	if _, created, err := b.repo.AcceptUpdate(ctx, uA); err != nil || !created {
		t.Fatalf("accept A: created=%v err=%v", created, err)
	}
	if _, created, err := b.repo.AcceptUpdate(ctx, uB); err != nil || !created {
		t.Fatalf("accept B: created=%v err=%v", created, err)
	}

	// Advance clock to round deadline so AggregateRound closes the round and aggregates deterministically.
	b.clock.Advance(time.Hour)
	rec, created, err := b.repo.AggregateRound(ctx, round.RoundID, b.publisher, b.actor)
	if err != nil || !created || rec.Status != federated.AggregationSucceeded {
		t.Fatalf("aggregate failed: rec=%+v created=%v err=%v", rec, created, err)
	}
	wantWeights := []float64{5, 7, 9, 11, 13, 15, 17}
	if !equalFloat64Slice(rec.Weights, wantWeights) || rec.TotalSamples != 40 || len(rec.Participants) != 2 {
		t.Fatalf("unexpected weights/totals: %+v", rec)
	}
	if rec.CandidateModelVersion != round.CandidateID || rec.WeightingPolicy != federated.WeightingPolicySampleCountV1 {
		t.Fatalf("unexpected candidate identity/policy: %+v", rec)
	}

	// Active model must stay unchanged; candidate slot points at new reproducible unapproved candidate.
	refsAfter, err := b.repo.ModelReferences(ctx)
	if err != nil || refsAfter.Active == nil || *refsAfter.Active != *refsBefore.Active {
		t.Fatalf("aggregation mutated active slot: before=%+v after=%+v err=%v", refsBefore.Active, refsAfter.Active, err)
	}
	if refsAfter.Candidate == nil || refsAfter.Candidate.ModelVersion != rec.CandidateModelVersion || refsAfter.Candidate.ArtifactSHA256 != rec.CandidateModelSHA256 {
		t.Fatalf("candidate slot mismatch: %+v rec=%+v", refsAfter.Candidate, rec)
	}
	storedCand, err := b.repo.ModelArtifact(ctx, rec.CandidateModelVersion)
	if err != nil || storedCand.Approval != nil {
		t.Fatalf("candidate should be unapproved before #115 evaluation: %+v err=%v", storedCand, err)
	}
	storedMan, storedBytes, err := b.repo.ModelArtifactBytes(ctx, rec.CandidateModelVersion)
	if err != nil {
		t.Fatal(err)
	}
	// Candidate logistic artifact must load cleanly in packages/health against a matching ML05 report!
	candEvalBytes, candEvalSHA := buildPassingML05Report(t, storedMan, 0.0, 2.0)
	if _, err := health.LoadControllerModel(storedMan, storedBytes, b.publisher.Public().(ed25519.PublicKey), candEvalBytes, candEvalSHA); err != nil {
		t.Fatalf("aggregated logistic candidate failed controller model load: %v", err)
	}

	// Exact retry preserves candidate identity and input digest (with same or another actor/restart).
	otherActor := federated.Actor{Issuer: "https://id.example.test", Subject: "admin:retry"}
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	retryRec, retryCreated, err := restarted.AggregateRound(ctx, round.RoundID, b.publisher, otherActor)
	if err != nil || retryCreated || !reflect.DeepEqual(retryRec, rec) {
		t.Fatalf("retry changed identity: retry=%+v created=%v err=%v", retryRec, retryCreated, err)
	}
	fetched, err := restarted.Aggregation(ctx, round.RoundID)
	if err != nil || !reflect.DeepEqual(fetched, rec) {
		t.Fatalf("Aggregation mismatch: got=%+v err=%v", fetched, err)
	}

	// Rebuilding candidate in a second round with identical parameters/inputs matches input formula cleanly.
	b.clock.Advance(time.Minute)
	now2 := b.clock.Now()
	round2 := b.round("round:logistic:2")
	round2.BaseModelVersion = baseMan.ModelVersion
	round2.BaseModelSHA256 = baseMan.ArtifactSHA256
	round2.FeatureVersion = baseMan.FeatureVersion
	round2.ParameterCount = baseMan.ParameterCount
	if _, _, err := b.repo.OpenRound(ctx, round2, b.actor); err != nil {
		t.Fatal(err)
	}
	uA2 := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round2, 3, now2, now2.Add(time.Hour), []float64{2, 4, 6, 8, 10, 12, 14}, 10)
	uB2 := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], round2, 3, now2, now2.Add(time.Hour), []float64{6, 8, 10, 12, 14, 16, 18}, 30)
	if _, _, err := b.repo.AcceptUpdate(ctx, uA2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.AcceptUpdate(ctx, uB2); err != nil {
		t.Fatal(err)
	}
	b.clock.Advance(time.Hour)
	rec2, _, err := b.repo.AggregateRound(ctx, round2.RoundID, b.publisher, b.actor)
	if err != nil || !equalFloat64Slice(rec2.Weights, rec.Weights) || rec2.WeightsSHA256 != rec.WeightsSHA256 {
		t.Fatalf("second round weights diverged: %+v vs %+v (err=%v)", rec2.WeightsSHA256, rec.WeightsSHA256, err)
	}
}

func TestFederatedAggregationFailuresLeaveActiveUnchangedAndRetrySafely(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()

	// Seed active model and candidate reference before running failing rounds.
	activeArt := artifactWithVersion(t, loadBaselineModelBytes(t), "baseline.active.safe")
	activeMan := buildSignedControllerManifest(t, b.publisher, activeArt, health.ControllerInferenceRuntime())
	_, activeEvalSHA := buildPassingML05Report(t, activeMan, 0.0, 2.0)
	registerAndActivateModel(t, b.repo, b.publisher, activeArt, health.ControllerInferenceRuntime(), activeEvalSHA, health.ML05PolicyVersion)
	refsBefore, err := b.repo.ModelReferences(ctx)
	if err != nil || refsBefore.Active == nil {
		t.Fatal(err)
	}

	// 1. Zero-update closed round -> ErrNoUpdates + active unchanged, candidate unchanged.
	rNoUpdates := b.round("round:empty")
	if _, _, err := b.repo.OpenRound(ctx, rNoUpdates, b.actor); err != nil {
		t.Fatal(err)
	}
	b.clock.Advance(time.Hour)
	recNoUpdates, created, err := b.repo.AggregateRound(ctx, rNoUpdates.RoundID, b.publisher, b.actor)
	if !errors.Is(err, federated.ErrNoUpdates) || !errors.Is(err, federated.ErrAggregationFailed) || !created || recNoUpdates.Status != federated.AggregationFailed || recNoUpdates.FailureReason != "no_updates" {
		t.Fatalf("no-updates outcome: rec=%+v created=%v err=%v", recNoUpdates, created, err)
	}
	if retryRec, retryCreated, retryErr := b.repo.AggregateRound(ctx, rNoUpdates.RoundID, b.publisher, b.actor); !errors.Is(retryErr, federated.ErrNoUpdates) || retryCreated || !reflect.DeepEqual(retryRec, recNoUpdates) {
		t.Fatalf("no-updates retry mismatch: rec=%+v created=%v err=%v", retryRec, retryCreated, retryErr)
	}

	// 2. Insufficient-participant closed round (1 < 2) -> ErrInsufficientParticipants + active unchanged.
	b.clock.Advance(time.Minute)
	rInsufficient := b.round("round:short")
	if _, _, err := b.repo.OpenRound(ctx, rInsufficient, b.actor); err != nil {
		t.Fatal(err)
	}
	now := b.clock.Now()
	uOne := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], rInsufficient, 2, now, now.Add(time.Hour), []float64{1, 2, 3, 4, 5, 6}, 20)
	if _, _, err := b.repo.AcceptUpdate(ctx, uOne); err != nil {
		t.Fatal(err)
	}
	b.clock.Advance(time.Hour)
	recShort, created, err := b.repo.AggregateRound(ctx, rInsufficient.RoundID, b.publisher, b.actor)
	if !errors.Is(err, federated.ErrInsufficientParticipants) || !created || recShort.Status != federated.AggregationFailed || recShort.FailureReason != "insufficient_participants" || len(recShort.Participants) != 1 {
		t.Fatalf("insufficient outcome: rec=%+v created=%v err=%v", recShort, created, err)
	}

	// 3. Cancelled round with updates -> ErrRoundNotOpen + ErrAggregationFailed + active unchanged.
	b.clock.Advance(time.Minute)
	rCancelled := b.round("round:cancelled")
	if _, _, err := b.repo.OpenRound(ctx, rCancelled, b.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.CancelRound(ctx, rCancelled.RoundID, b.actor); err != nil {
		t.Fatal(err)
	}
	recCancelled, created, err := b.repo.AggregateRound(ctx, rCancelled.RoundID, b.publisher, b.actor)
	if !errors.Is(err, federated.ErrRoundNotOpen) || !errors.Is(err, federated.ErrAggregationFailed) || !created || recCancelled.FailureReason != "cancelled" {
		t.Fatalf("cancelled outcome: rec=%+v created=%v err=%v", recCancelled, created, err)
	}

	// 4. Corrupt stored update / aggregation failure -> aggregation_failed + active unchanged.
	b.clock.Advance(time.Minute)
	rCorrupt := b.round("round:corrupt")
	if _, _, err := b.repo.OpenRound(ctx, rCorrupt, b.actor); err != nil {
		t.Fatal(err)
	}
	now = b.clock.Now()
	for i := range 2 {
		u := signFederatedUpdate(t, b.repo.deploymentID, b.devices[i], rCorrupt, 3, now, now.Add(time.Hour), []float64{1, 2, 3, 4, 5, 6}, 25)
		if _, _, err := b.repo.AcceptUpdate(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	b.clock.Advance(time.Hour)
	if _, err := b.db.Exec(`ALTER TABLE federated_updates DISABLE TRIGGER federated_updates_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE federated_updates SET envelope = envelope || '{"sample_count":999}'::jsonb WHERE round_id=$1 AND device_id=$2`, rCorrupt.RoundID, b.devices[0].id); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`ALTER TABLE federated_updates ENABLE TRIGGER federated_updates_immutable`); err != nil {
		t.Fatal(err)
	}
	recCorrupt, created, err := b.repo.AggregateRound(ctx, rCorrupt.RoundID, b.publisher, b.actor)
	if !errors.Is(err, federated.ErrAggregationFailed) || !errors.Is(err, federated.ErrUpdateCorrupt) || !created || recCorrupt.FailureReason != "aggregation_failed" {
		t.Fatalf("corrupt update outcome: rec=%+v created=%v err=%v", recCorrupt, created, err)
	}

	// Verify active & candidate slots remained completely untouched and none of the failed candidates stored artifacts.
	refsAfter, err := b.repo.ModelReferences(ctx)
	if err != nil || refsAfter.Active == nil || *refsAfter.Active != *refsBefore.Active || refsAfter.Candidate != nil {
		t.Fatalf("failures altered registry references: before=%+v after=%+v err=%v", refsBefore, refsAfter, err)
	}
	for _, rID := range []string{rNoUpdates.RoundID, rInsufficient.RoundID, rCancelled.RoundID, rCorrupt.RoundID} {
		if _, err := b.repo.ModelArtifact(ctx, "candidate:"+rID); !errors.Is(err, ErrRepositoryNotFound) {
			t.Fatalf("failed round %s created candidate artifact: %v", rID, err)
		}
	}
}

func TestFederatedAggregationConcurrencyDatabaseGuardsAndSyntheticCandidate(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:concurrent:agg")
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}
	now := b.clock.Now()
	for i := range 2 {
		u := signFederatedUpdate(t, b.repo.deploymentID, b.devices[i], round, 2, now, now.Add(time.Hour), []float64{float64(i + 1), 2, 3, 4, 5, 6}, 15)
		if _, _, err := b.repo.AcceptUpdate(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	b.clock.Advance(time.Hour)

	const workers = 8
	var createdCount atomic.Int32
	var errs atomic.Int32
	results := make([]federated.AggregationRecord, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			rec, created, err := b.repo.AggregateRound(ctx, round.RoundID, b.publisher, b.actor)
			if err != nil {
				errs.Add(1)
				return
			}
			results[idx] = rec
			if created {
				createdCount.Add(1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if errs.Load() != 0 || createdCount.Load() != 1 {
		t.Fatalf("concurrent aggregate created=%d errors=%d want 1/0", createdCount.Load(), errs.Load())
	}
	for i := 1; i < workers; i++ {
		if !reflect.DeepEqual(results[i], results[0]) {
			t.Fatalf("worker %d returned different aggregation identity: %+v vs %+v", i, results[i], results[0])
		}
	}

	// Database triggers prevent mutations and forged aggregation inserts.
	for name, stmt := range map[string]string{
		"update aggregation": `UPDATE federated_aggregations SET total_samples = 999`,
		"delete aggregation": `DELETE FROM federated_aggregations`,
		"open round aggregate insert": func() string {
			openR := b.round("round:still:open")
			_, _, _ = b.repo.OpenRound(ctx, openR, b.actor)
			return fmt.Sprintf(`INSERT INTO federated_aggregations
				SELECT deployment_id, '%s', '%s', base_model_version, base_model_sha256,
					feature_version, parameter_count, weighting_policy, 'failed', 'no_updates',
					0, 0, input_sha256, '[]'::jsonb, NULL, NULL, NULL, NULL, created_at, actor_issuer, actor_subject
				FROM federated_aggregations LIMIT 1`, openR.RoundID, openR.CandidateID)
		}(),
		"forged succeeded aggregation without stored updates": func() string {
			forgedR := b.round("round:forged:closed")
			_, _, _ = b.repo.OpenRound(ctx, forgedR, b.actor)
			_, _ = b.db.Exec(`UPDATE federated_rounds SET status='closed' WHERE round_id=$1`, forgedR.RoundID)
			return fmt.Sprintf(`INSERT INTO federated_aggregations
				SELECT deployment_id, '%s', '%s', base_model_version, base_model_sha256,
					feature_version, parameter_count, weighting_policy, 'succeeded', NULL,
					participant_count, total_samples, input_sha256, participants,
					weights_bytes, weights_sha256, candidate_model_version, candidate_model_sha256,
					created_at, actor_issuer, actor_subject
				FROM federated_aggregations WHERE round_id='%s'`, forgedR.RoundID, forgedR.CandidateID, round.RoundID)
		}(),
	} {
		if _, err := b.db.Exec(stmt); err == nil {
			t.Fatalf("database allowed %s", name)
		}
	}

	// Tamper stored participant sample_count without changing array length -> ErrAggregationCorrupt.
	if _, err := b.db.Exec(`ALTER TABLE federated_aggregations DISABLE TRIGGER federated_aggregations_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE federated_aggregations
		SET participants = jsonb_set(participants, '{0,sample_count}', '99'::jsonb)
		WHERE round_id=$1`, round.RoundID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`ALTER TABLE federated_aggregations ENABLE TRIGGER federated_aggregations_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.Aggregation(ctx, round.RoundID); !errors.Is(err, federated.ErrAggregationCorrupt) {
		t.Fatalf("tampered participant sample_count err=%v want ErrAggregationCorrupt", err)
	}

	// Canceled context during lookup must preserve cancellation rather than reporting ErrAggregationCorrupt.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.repo.Aggregation(canceledCtx, round.RoundID); !errors.Is(err, context.Canceled) || errors.Is(err, federated.ErrAggregationCorrupt) {
		t.Fatalf("canceled Aggregation err=%v want context.Canceled without ErrAggregationCorrupt", err)
	}

	// Already-approved candidate version matching aggregated bytes cannot be reused as an unapproved candidate.
	b.clock.Advance(time.Minute)
	rApproved := b.round("round:approved:collision")
	if _, _, err := b.repo.OpenRound(ctx, rApproved, b.actor); err != nil {
		t.Fatal(err)
	}
	now = b.clock.Now()
	uApp1 := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], rApproved, 3, now, now.Add(time.Hour), []float64{1, 2, 3, 4, 5, 6}, 15)
	uApp2 := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], rApproved, 3, now, now.Add(time.Hour), []float64{2, 2, 3, 4, 5, 6}, 15)
	if _, _, err := b.repo.AcceptUpdate(ctx, uApp1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.AcceptUpdate(ctx, uApp2); err != nil {
		t.Fatal(err)
	}
	b.clock.Advance(time.Hour)
	baseMan, baseBytes, err := b.repo.ModelArtifactBytes(ctx, rApproved.BaseModelVersion)
	if err != nil {
		t.Fatal(err)
	}
	updatesApp, err := b.repo.AcceptedUpdates(ctx, rApproved.RoundID)
	if err != nil {
		t.Fatal(err)
	}
	pApp := []federated.AggregatedParticipant{
		{DeviceID: updatesApp[0].DeviceID, SigningKeyID: updatesApp[0].SigningKeyID, Sequence: updatesApp[0].Sequence, SampleCount: updatesApp[0].SampleCount, UpdateSHA256: updatesApp[0].UpdateSHA256, RequestSHA256: updatesApp[0].RequestSHA256},
		{DeviceID: updatesApp[1].DeviceID, SigningKeyID: updatesApp[1].SigningKeyID, Sequence: updatesApp[1].Sequence, SampleCount: updatesApp[1].SampleCount, UpdateSHA256: updatesApp[1].UpdateSHA256, RequestSHA256: updatesApp[1].RequestSHA256},
	}
	inAppSHA, totApp, err := federated.AggregationInputSHA256(rApproved, federated.WeightingPolicySampleCountV1, pApp)
	if err != nil {
		t.Fatal(err)
	}
	wApp, _, err := federated.WeightedAverage(rApproved, updatesApp)
	if err != nil {
		t.Fatal(err)
	}
	wbApp, err := federated.EncodeBinary64Weights(wApp)
	if err != nil {
		t.Fatal(err)
	}
	wAppSum := sha256.Sum256(wbApp)
	candBytesApp, err := federated.BuildCandidateArtifact(rApproved, baseMan, baseBytes, wApp, hex.EncodeToString(wAppSum[:]), inAppSHA, len(pApp), totApp)
	if err != nil {
		t.Fatal(err)
	}
	preMan := b.manifest(t, b.publisher, rApproved.CandidateID, candBytesApp, contracts.ModelPurposeInference)
	preMan.FeatureVersion = rApproved.FeatureVersion
	preMan.ParameterCount = rApproved.ParameterCount
	msg, _ := preMan.SigningBytes()
	preMan.Signature = hex.EncodeToString(ed25519.Sign(b.publisher, msg))
	if _, _, err := b.repo.PutModelArtifact(ctx, upload(preMan, candBytesApp), b.publisher.Public().(ed25519.PublicKey), contracts.ModelActorV1(b.actor)); err != nil {
		t.Fatal(err)
	}
	approveWithoutEvaluationGate(t, b.repo, rApproved.CandidateID, preMan.ArtifactSHA256, strings.Repeat("e", 64), health.ML05PolicyVersion)
	if recApp, _, err := b.repo.AggregateRound(ctx, rApproved.RoundID, b.publisher, b.actor); !errors.Is(err, federated.ErrAggregationFailed) || recApp.FailureReason != "aggregation_failed" {
		t.Fatalf("pre-approved candidate reuse rec=%+v err=%v want ErrAggregationFailed", recApp, err)
	}

	// Stored round record ID mismatch is rejected on read/lock cleanly.
	rMismatch := b.round("round:mismatch:target")
	if _, _, err := b.repo.OpenRound(ctx, rMismatch, b.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`ALTER TABLE federated_rounds DISABLE TRIGGER federated_rounds_status_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE federated_rounds SET record = (SELECT record FROM federated_rounds WHERE round_id=$1) WHERE round_id=$2`, round.RoundID, rMismatch.RoundID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`ALTER TABLE federated_rounds ENABLE TRIGGER federated_rounds_status_guard`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.AcceptedUpdates(ctx, rMismatch.RoundID); !errors.Is(err, federated.ErrUpdateCorrupt) {
		t.Fatalf("mismatched round record AcceptedUpdates err=%v want ErrUpdateCorrupt", err)
	}
	if _, _, err := b.repo.AggregateRound(ctx, rMismatch.RoundID, b.publisher, b.actor); !errors.Is(err, federated.ErrUpdateCorrupt) {
		t.Fatalf("mismatched round record AggregateRound err=%v want ErrUpdateCorrupt", err)
	}

	// Corrupt stored candidate artifact bytes with matching manifest cannot be reused on aggregation.
	b.clock.Advance(time.Minute)
	rCorruptCand := b.round("round:corrupt:reuse")
	if _, _, err := b.repo.OpenRound(ctx, rCorruptCand, b.actor); err != nil {
		t.Fatal(err)
	}
	now = b.clock.Now()
	uCC1 := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], rCorruptCand, 4, now, now.Add(time.Hour), []float64{1, 2, 3, 4, 5, 6}, 15)
	uCC2 := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], rCorruptCand, 4, now, now.Add(time.Hour), []float64{2, 2, 3, 4, 5, 6}, 15)
	if _, _, err := b.repo.AcceptUpdate(ctx, uCC1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.AcceptUpdate(ctx, uCC2); err != nil {
		t.Fatal(err)
	}
	b.clock.Advance(time.Hour)
	updatesCC, err := b.repo.AcceptedUpdates(ctx, rCorruptCand.RoundID)
	if err != nil {
		t.Fatal(err)
	}
	pCC := []federated.AggregatedParticipant{
		{DeviceID: updatesCC[0].DeviceID, SigningKeyID: updatesCC[0].SigningKeyID, Sequence: updatesCC[0].Sequence, SampleCount: updatesCC[0].SampleCount, UpdateSHA256: updatesCC[0].UpdateSHA256, RequestSHA256: updatesCC[0].RequestSHA256},
		{DeviceID: updatesCC[1].DeviceID, SigningKeyID: updatesCC[1].SigningKeyID, Sequence: updatesCC[1].Sequence, SampleCount: updatesCC[1].SampleCount, UpdateSHA256: updatesCC[1].UpdateSHA256, RequestSHA256: updatesCC[1].RequestSHA256},
	}
	inCCSHA, totCC, err := federated.AggregationInputSHA256(rCorruptCand, federated.WeightingPolicySampleCountV1, pCC)
	if err != nil {
		t.Fatal(err)
	}
	wCC, _, err := federated.WeightedAverage(rCorruptCand, updatesCC)
	if err != nil {
		t.Fatal(err)
	}
	wbCC, err := federated.EncodeBinary64Weights(wCC)
	if err != nil {
		t.Fatal(err)
	}
	wCCSum := sha256.Sum256(wbCC)
	candBytesCC, err := federated.BuildCandidateArtifact(rCorruptCand, baseMan, baseBytes, wCC, hex.EncodeToString(wCCSum[:]), inCCSHA, len(pCC), totCC)
	if err != nil {
		t.Fatal(err)
	}
	badCandMan := b.manifest(t, b.publisher, rCorruptCand.CandidateID, candBytesCC, contracts.ModelPurposeInference)
	badCandMan.FeatureVersion = rCorruptCand.FeatureVersion
	badCandMan.ParameterCount = rCorruptCand.ParameterCount
	badMsg, _ := badCandMan.SigningBytes()
	badCandMan.Signature = hex.EncodeToString(ed25519.Sign(b.publisher, badMsg))
	if _, _, err := b.repo.PutModelArtifact(ctx, upload(badCandMan, candBytesCC), b.publisher.Public().(ed25519.PublicKey), contracts.ModelActorV1(b.actor)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`ALTER TABLE model_artifacts DISABLE TRIGGER model_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE model_artifacts SET artifact = '{"corrupt":true}'::bytea WHERE model_version=$1`, rCorruptCand.CandidateID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`ALTER TABLE model_artifacts ENABLE TRIGGER model_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	if recCC, _, err := b.repo.AggregateRound(ctx, rCorruptCand.RoundID, b.publisher, b.actor); !errors.Is(err, federated.ErrAggregationFailed) || recCC.FailureReason != "aggregation_failed" {
		t.Fatalf("corrupt reuse candidate rec=%+v err=%v want ErrAggregationFailed", recCC, err)
	}
}
