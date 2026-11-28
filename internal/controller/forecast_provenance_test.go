package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func requireSource(t *testing.T, source contracts.ForecastSourceV1, err error, status contracts.ForecastStatusV1, reason contracts.ForecastReasonV1) contracts.ForecastSourceV1 {
	t.Helper()
	if err != nil || source.Status != status || source.Reason != reason {
		t.Fatalf("source: status=%q reason=%q err=%v want %q/%q: %+v", source.Status, source.Reason, err, status, reason, source)
	}
	return source
}

func TestForecastSourceRefusesFailedRoundsRejectedAndUnevaluatedCandidates(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()

	if _, err := b.repo.ForecastSourceForModel(ctx, "no.such.model"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown model: %v", err)
	}
	if _, err := b.repo.ForecastSourceForRound(ctx, "round:missing"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown round: %v", err)
	}

	// An open round has produced nothing; a round with no updates failed.
	open := b.round("round:open")
	if _, _, err := b.repo.OpenRound(ctx, open, b.actor); err != nil {
		t.Fatal(err)
	}
	source, err := b.repo.ForecastSourceForRound(ctx, open.RoundID)
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonRoundNotAggregated)
	b.clock.Advance(time.Hour)
	if _, _, err := b.repo.AggregateRound(ctx, open.RoundID, b.publisher, b.actor); !errors.Is(err, federated.ErrNoUpdates) {
		t.Fatalf("aggregate empty round: %v", err)
	}
	source, err = b.repo.ForecastSourceForRound(ctx, open.RoundID)
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonRoundFailed)
	if source.FailureReason != "no_updates" || source.Model != nil {
		t.Fatalf("failed round source: %+v", source)
	}

	// A successful aggregate is only an unevaluated candidate.
	baseArt, err := os.ReadFile(filepath.Join("..", "..", "models", "baseline", "backblaze-2013", "artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := b.manifest(t, b.publisher, "logistic-baseline.backblaze-2013.v1", baseArt, contracts.ModelPurposeTraining, contracts.ModelPurposeInference)
	base.Architecture, base.RuntimeName, base.RuntimeVersion, base.ParameterCount = "logistic-baseline.v1", health.ControllerInferenceRuntime().Name, health.ControllerInferenceRuntime().Version, 7
	signed, err := base.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	base.Signature = fmt.Sprintf("%x", ed25519.Sign(b.publisher, signed))
	if _, _, err := b.repo.PutModelArtifact(ctx, upload(base, baseArt), b.publisher.Public().(ed25519.PublicKey), contracts.ModelActorV1(b.actor)); err != nil {
		t.Fatal(err)
	}
	sequence := uint64(1)
	aggregate := func(id string, samples []uint32) federated.AggregationRecord {
		sequence++
		round := b.round(id)
		round.BaseModelVersion, round.BaseModelSHA256, round.FeatureVersion, round.ParameterCount = base.ModelVersion, base.ArtifactSHA256, base.FeatureVersion, base.ParameterCount
		if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
			t.Fatal(err)
		}
		now := b.clock.Now()
		for i, n := range samples {
			weights := []float64{1, 2, 3, 4, 5, 6, float64(7 + i)}
			if _, _, err := b.repo.AcceptUpdate(ctx, signFederatedUpdate(t, b.repo.deploymentID, b.devices[i], round, sequence, now, now.Add(time.Hour), weights, n)); err != nil {
				t.Fatal(err)
			}
		}
		b.clock.Advance(time.Hour)
		b.session, b.csrf = b.addSession(t, "admin:test", auth.RoleAdmin, 0)
		rec, _, err := b.repo.AggregateRound(ctx, round.RoundID, b.publisher, b.actor)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	good := aggregate("round:forecast:good", []uint32{10, 30})
	source, err = b.repo.ForecastSourceForRound(ctx, "round:forecast:good")
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonCandidateUnevaluated)
	// A restart reads the same rows and cannot promote the aggregate.
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	source, err = restarted.ForecastSourceForModel(ctx, good.CandidateModelVersion)
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonCandidateUnevaluated)

	// An approval written around the evaluation gate does not make it eligible.
	storedMan, _, err := b.repo.ModelArtifactBytes(ctx, good.CandidateModelVersion)
	if err != nil {
		t.Fatal(err)
	}
	_, evalSHA := buildPassingML05Report(t, storedMan, 0.0, 2.0)
	approveWithoutEvaluationGate(t, b.repo, good.CandidateModelVersion, storedMan.ArtifactSHA256, evalSHA, health.ML05PolicyVersion)
	source, err = restarted.ForecastSourceForModel(ctx, good.CandidateModelVersion)
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonCandidateUnevaluated)

	// A failing evaluation is not a forecast source, with or without a decision.
	second := aggregate("round:forecast:poor", []uint32{20, 20})
	poorMan, _, err := b.repo.ModelArtifactBytes(ctx, second.CandidateModelVersion)
	if err != nil {
		t.Fatal(err)
	}
	poor, poorSHA := reportWith(t, poorMan, func(_ map[string]any, metrics map[string]any) {
		metrics["brier_skill_vs_prevalence"] = metric(-0.4, -0.6, -0.2)
		metrics["calibration_slope"] = metric(0.4, 0.3, 0.5)
	})
	b.submit(t, poorMan, poor, http.StatusCreated, `"verdict":"fail"`)
	source, err = b.repo.ForecastSourceForRound(ctx, "round:forecast:poor")
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonEvaluationNotPassing)
	b.promote(t, poorMan, poorSHA, http.StatusCreated, `"outcome":"rejected"`)
	source, err = b.repo.ForecastSourceForRound(ctx, "round:forecast:poor")
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonCandidateRejected)
	if source.Model == nil || source.Model.PromotedAt != nil {
		t.Fatalf("rejected candidate carries a promotion time: %+v", source.Model)
	}

	// A candidate that passes held-out evaluation and promotion becomes a
	// source, with the federated round that produced it.
	ok := aggregate("round:forecast:ok", []uint32{15, 45})
	okMan, _, err := b.repo.ModelArtifactBytes(ctx, ok.CandidateModelVersion)
	if err != nil {
		t.Fatal(err)
	}
	report, reportSHA := passingReport(t, okMan)
	b.submit(t, okMan, report, http.StatusCreated, `"verdict":"pass"`)
	source, err = b.repo.ForecastSourceForRound(ctx, "round:forecast:ok")
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonNotPromoted)
	promotion := b.promote(t, okMan, reportSHA, http.StatusCreated, `"outcome":"promoted"`)
	source, err = b.repo.ForecastSourceForRound(ctx, "round:forecast:ok")
	requireSource(t, source, err, contracts.ForecastAvailable, contracts.ForecastReasonNone)
	m := source.Model
	if m == nil || !m.Active || m.EvaluationSHA256 != reportSHA || m.FeatureVersion != base.FeatureVersion || m.PromotedAt == nil ||
		!m.PromotedAt.Equal(promotion.DecidedAt) || m.Origin == nil || m.Origin.RoundID != "round:forecast:ok" ||
		m.Origin.ParticipantCount != 2 || m.Origin.TotalSamples != 60 || m.Origin.WeightsSHA256 != ok.WeightsSHA256 || m.Origin.InputSHA256 != ok.InputSHA256 {
		t.Fatalf("available source provenance: %+v origin=%+v", m, m.Origin)
	}
	// The earlier unapproved aggregate is still not a source.
	source, err = b.repo.ForecastSourceForModel(ctx, good.CandidateModelVersion)
	requireSource(t, source, err, contracts.ForecastUnavailable, contracts.ForecastReasonCandidateUnevaluated)
}

func TestDeviceForecastFreshnessAndModelEligibility(t *testing.T) {
	b := newRegistryBed(t)
	ctx := context.Background()
	pub := b.publisher.Public().(ed25519.PublicKey)
	actor := contracts.ModelActorV1(federated.Actor{Issuer: "https://id.example.test", Subject: "admin:test"})
	evalDir := t.TempDir()
	cfg := HealthConfig{PublisherKey: pub, EvaluationReports: EvaluationReportDir(evalDir)}
	device := "device:forecast-a"
	keys := enrollTestDevice(t, b.enrollmentTestBed, device)

	if _, err := b.repo.DeviceForecast(ctx, "device:unknown"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
	forecast, err := b.repo.DeviceForecast(ctx, device)
	if err != nil || forecast.Status != contracts.ForecastUnavailable || forecast.Reason != contracts.ForecastReasonNoPrediction || len(forecast.Forecasts) != 0 {
		t.Fatalf("no prediction: %+v err=%v", forecast, err)
	}
	if _, err := b.repo.EvaluateAndRecordDeviceHealth(ctx, cfg, device, b.clock.Now()); err != nil {
		t.Fatal(err)
	}
	forecast, err = b.repo.DeviceForecast(ctx, device)
	if err != nil || forecast.Status != contracts.ForecastUnavailable || forecast.Reason != contracts.ForecastReasonModelUnavailable ||
		forecast.Health == nil || forecast.Health.Probability != nil || forecast.HorizonHours != nil {
		t.Fatalf("no model: %+v err=%v", forecast, err)
	}

	// Promote an evaluated model through the stored evaluation and decision.
	artifact := artifactWithVersion(t, loadBaselineModelBytes(t), "baseline.forecast-device.v1")
	manifest := buildSignedControllerManifest(t, b.publisher, artifact, health.ControllerInferenceRuntime())
	if _, _, err := b.repo.PutModelArtifact(ctx, upload(manifest, artifact), pub, actor); err != nil {
		t.Fatal(err)
	}
	report, digest := buildPassingML05Report(t, manifest, 0.0, 2.0)
	writeEvalReportFile(t, evalDir, digest, report)
	if _, _, err := b.repo.PutModelEvaluation(ctx, signEvaluation(manifest, report, b.publisher), pub, actor); err != nil {
		t.Fatal(err)
	}
	request := contracts.ModelReferenceRequestV1{SchemaVersion: contracts.ModelReferenceRequestV1Version, ModelVersion: manifest.ModelVersion, ArtifactSHA256: manifest.ArtifactSHA256}
	if _, err := b.repo.SetModelReference(ctx, contracts.ModelSlotCandidate, request, actor); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.PromoteModel(ctx, promotionRequestFor(manifest, digest), actor); err != nil {
		t.Fatal(err)
	}

	startDay := b.clock.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 2).Add(12 * time.Hour)
	smart := map[uint64][3]int64{
		23: {0, 11000, 0}, 24: {0, 11024, 0}, 25: {0, 11048, 0}, 26: {0, 11072, 0},
		27: {0, 11096, 0}, 28: {0, 11120, 0}, 29: {0, 11144, 0},
	}
	for i := range 28 {
		acceptTelemetrySample(t, b.enrollmentTestBed, device, keys, uint64(2+i), startDay.AddDate(0, 0, i), nil)
	}
	asOf := startDay.AddDate(0, 0, 27).Add(20 * time.Minute)
	b.clock.Advance(asOf.Sub(b.clock.Now()))
	if _, err := b.repo.evaluateAndRecordDeviceHealth(ctx, cfg, device, asOf, makeSMARTMapReader(smart)); err != nil {
		t.Fatal(err)
	}

	forecast, err = b.repo.DeviceForecast(ctx, device)
	if err != nil || forecast.Status != contracts.ForecastAvailable || forecast.Reason != contracts.ForecastReasonNone {
		t.Fatalf("available: %+v err=%v", forecast, err)
	}
	m := forecast.Model
	if m == nil || !m.Active || m.Version != manifest.ModelVersion || m.EvaluationSHA256 != digest || m.FeatureVersion != manifest.FeatureVersion ||
		m.PromotedAt == nil || m.Origin != nil || forecast.Health == nil || forecast.Health.Status != health.HealthStatusHealthy ||
		forecast.Health.Probability == nil || forecast.HorizonHours == nil || *forecast.HorizonHours != 168 ||
		forecast.Window == nil || forecast.Window.Status != contracts.FeatureStatusComplete || forecast.Window.FeatureVersion != manifest.FeatureVersion ||
		forecast.Evidence == nil || forecast.Evidence.Sequence != 29 || forecast.AsOf == nil || forecast.ExpiresAt == nil {
		t.Fatalf("available provenance: %+v model=%+v", forecast, m)
	}

	// The route serves the same record to a viewer.
	service, err := NewDeviceStateService(b.repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: service}).Handler()
	viewer, _ := b.addSession(t, "viewer:forecast", auth.RoleViewer, 0)
	get := func(device string, query string, session string, want int) []byte {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/console/api/devices/"+device+"/forecast?"+query, nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("GET forecast %s: %d want %d: %s", device, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	get(device, "deployment_id="+b.repo.deploymentID, "", http.StatusUnauthorized)
	get(device, "", viewer, http.StatusBadRequest)
	get(device, "deployment_id=deployment:other", viewer, http.StatusForbidden)
	get("device:unknown", "deployment_id="+b.repo.deploymentID, viewer, http.StatusNotFound)
	var served contracts.DeviceForecastV1
	if err := json.Unmarshal(get(device, "deployment_id="+b.repo.deploymentID, viewer, http.StatusOK), &served); err != nil || served.Status != contracts.ForecastAvailable ||
		served.Model == nil || served.Model.EvaluationSHA256 != digest {
		t.Fatalf("served forecast: %+v err=%v", served, err)
	}

	// Another model becoming active makes the forecast stale, not current.
	other := artifactWithVersion(t, loadBaselineModelBytes(t), "baseline.forecast-other.v1")
	registerAndActivateModel(t, b.repo, b.publisher, other, health.ControllerInferenceRuntime(), digest, health.ML05PolicyVersion)
	forecast, err = b.repo.DeviceForecast(ctx, device)
	if err != nil || forecast.Status != contracts.ForecastStale || forecast.Reason != contracts.ForecastReasonModelSuperseded || len(forecast.Forecasts) != 0 || forecast.Model == nil || forecast.Model.Active {
		t.Fatalf("superseded: %+v err=%v", forecast, err)
	}

	// Past its expiry the same record is stale; a restart changes nothing.
	b.clock.Advance(2 * time.Hour)
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	forecast, err = restarted.DeviceForecast(ctx, device)
	if err != nil || forecast.Status != contracts.ForecastStale || forecast.Reason != contracts.ForecastReasonPredictionExpired ||
		len(forecast.Forecasts) != 0 || forecast.Health == nil || forecast.Health.Probability != nil {
		t.Fatalf("expired: %+v err=%v", forecast, err)
	}
}
