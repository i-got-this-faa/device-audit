package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func TestPredictionHistoryPersistencePaginationRestartAndStaleness(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	publisher := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	pubKey := publisher.Public().(ed25519.PublicKey)
	artifact := loadBaselineModelBytes(t)
	evalDir := t.TempDir()
	cfg := HealthConfig{PublisherKey: pubKey, EvaluationReports: EvaluationReportDir(evalDir)}

	devA := "device:pred-a"
	devB := "device:pred-b"
	emptyDev := "device:pred-empty"
	keysA := enrollTestDevice(t, b, devA)
	keysB := enrollTestDevice(t, b, devB)
	_ = enrollTestDevice(t, b, emptyDev)

	// 1. Evaluate and record before any active model or telemetry exists -> unknown (model_unavailable, no prediction).
	t0 := b.clock.Now().UTC()
	recNoModel, err := b.repo.EvaluateAndRecordDeviceHealth(ctx, cfg, devA, t0)
	if err != nil {
		t.Fatalf("record without model: %v", err)
	}
	if recNoModel.Health.Status != health.HealthStatusUnknown ||
		recNoModel.Health.UnknownReason != health.UnknownReasonModelUnavailable ||
		recNoModel.Health.Probability != nil || recNoModel.Health.HorizonHours != nil ||
		recNoModel.ModelProvenance != nil || recNoModel.Evidence != nil || recNoModel.Prediction != nil {
		t.Fatalf("unexpected no-model record: %+v", recNoModel)
	}

	// Activate evaluated model.
	modelArtifact := artifactWithVersion(t, artifact, "baseline.pred-hist.v1")
	manifest := buildSignedControllerManifest(t, publisher, modelArtifact, health.ControllerInferenceRuntime())
	evalBytes, evalDigest := buildPassingML05Report(t, manifest, 0.0, 2.0)
	writeEvalReportFile(t, evalDir, evalDigest, evalBytes)
	registerAndActivateModel(t, b.repo, publisher, modelArtifact, health.ControllerInferenceRuntime(), evalDigest, health.ML05PolicyVersion)

	// 2. Active model present, no telemetry on devA yet -> unknown (insufficient_evidence, model provenance retained, no prediction).
	t1 := t0.Add(time.Minute)
	b.clock.Advance(time.Minute)
	recNoEvidence, err := b.repo.EvaluateAndRecordDeviceHealth(ctx, cfg, devA, t1)
	if err != nil {
		t.Fatalf("record without evidence: %v", err)
	}
	if recNoEvidence.Health.Status != health.HealthStatusUnknown ||
		recNoEvidence.Health.UnknownReason != health.UnknownReasonInsufficientEvidence ||
		recNoEvidence.Health.Probability != nil || recNoEvidence.Health.HorizonHours != nil ||
		recNoEvidence.ModelProvenance == nil || recNoEvidence.ModelProvenance.Version != "baseline.pred-hist.v1" ||
		recNoEvidence.ModelProvenance.EvaluationSHA256 != evalDigest ||
		recNoEvidence.Evidence != nil || recNoEvidence.Prediction != nil {
		t.Fatalf("unexpected no-evidence record: %+v", recNoEvidence)
	}

	// 3. Seed 28 days of evidence on devA and devB; also record real telemetry v2 (no SMART) on devA at same asOf to test tie-breaking.
	startDay := b.clock.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 2).Add(12 * time.Hour)
	healthySMART7d := map[uint64][3]int64{
		23: {0, 11000, 0}, 24: {0, 11024, 0}, 25: {0, 11048, 0}, 26: {0, 11072, 0},
		27: {0, 11096, 0}, 28: {0, 11120, 0}, 29: {0, 11144, 0},
	}
	for i := range 28 {
		seq := uint64(2 + i)
		ts := startDay.AddDate(0, 0, i)
		acceptTelemetrySample(t, b, devA, keysA, seq, ts, nil)
		acceptTelemetrySample(t, b, devB, keysB, seq, ts, nil)
	}
	evalAsOf := startDay.AddDate(0, 0, 27).Add(20 * time.Minute)
	b.clock.Advance(evalAsOf.Sub(b.clock.Now()))

	// Same asOf timestamp twice (first real telemetry -> unknown insufficient_evidence, second SMART fixture -> healthy) to verify (as_of, id) tie breaking.
	recRealV2, err := b.repo.EvaluateAndRecordDeviceHealth(ctx, cfg, devA, evalAsOf)
	if err != nil {
		t.Fatalf("record telemetry v2: %v", err)
	}
	if recRealV2.Health.Status != health.HealthStatusUnknown ||
		recRealV2.Health.UnknownReason != health.UnknownReasonInsufficientEvidence ||
		recRealV2.Evidence == nil || recRealV2.Evidence.Sequence != 29 ||
		recRealV2.Prediction == nil || recRealV2.Features.Status != contracts.FeatureStatusIncomplete {
		t.Fatalf("unexpected telemetry v2 record: %+v", recRealV2)
	}

	recHealthy, err := b.repo.evaluateAndRecordDeviceHealth(ctx, cfg, devA, evalAsOf, makeSMARTMapReader(healthySMART7d))
	if err != nil {
		t.Fatalf("record healthy fixture: %v", err)
	}
	if recHealthy.Health.Status != health.HealthStatusHealthy ||
		recHealthy.Health.Probability == nil || recHealthy.Health.HorizonHours == nil || *recHealthy.Health.HorizonHours != 168 ||
		recHealthy.ModelProvenance == nil || recHealthy.ModelProvenance.EvaluationSHA256 != evalDigest ||
		recHealthy.Evidence == nil || recHealthy.Evidence.Sequence != 29 ||
		recHealthy.Features.Status != contracts.FeatureStatusComplete || recHealthy.Features.FeatureCount != 6 ||
		!recHealthy.FaultBaseline.Current.Sufficient || !recHealthy.FaultBaseline.Baseline.Sufficient {
		t.Fatalf("unexpected healthy record: %+v", recHealthy)
	}

	// Also record one stale_evidence evaluation and one record for devB.
	staleAsOf := startDay.AddDate(0, 0, 27).Add(time.Hour)
	recStale, err := b.repo.evaluateAndRecordDeviceHealth(ctx, cfg, devA, staleAsOf, makeSMARTMapReader(healthySMART7d))
	if err != nil {
		t.Fatalf("record stale fixture: %v", err)
	}
	if recStale.Health.Status != health.HealthStatusUnknown ||
		recStale.Health.UnknownReason != health.UnknownReasonStaleEvidence ||
		recStale.Health.Probability != nil || recStale.Health.HorizonHours != nil || !recStale.Stale {
		t.Fatalf("unexpected stale record: %+v", recStale)
	}
	if _, err := b.repo.evaluateAndRecordDeviceHealth(ctx, cfg, devB, evalAsOf, makeSMARTMapReader(healthySMART7d)); err != nil {
		t.Fatalf("record devB: %v", err)
	}

	// Build authenticated console API.
	service, err := NewDeviceStateService(b.repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: service}).Handler()
	viewer, _ := b.addSession(t, "viewer:pred", auth.RoleViewer, 0)

	getHistory := func(h http.Handler, device string, params url.Values, session string, want int) (contracts.PredictionHistoryV1, string) {
		t.Helper()
		if params.Get("deployment_id") == "" && params["deployment_id"] == nil {
			params.Set("deployment_id", b.repo.deploymentID)
		}
		r := httptest.NewRequest(http.MethodGet, "/console/api/devices/"+device+"/predictions?"+params.Encode(), nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("GET predictions %s %v: %d want %d: %s", device, params, w.Code, want, w.Body.String())
		}
		var page contracts.PredictionHistoryV1
		if want == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
		}
		return page, w.Body.String()
	}
	getLatest := func(h http.Handler, device string, params url.Values, session string, want int) (contracts.LatestPredictionV1, string) {
		t.Helper()
		if params.Get("deployment_id") == "" && params["deployment_id"] == nil {
			params.Set("deployment_id", b.repo.deploymentID)
		}
		r := httptest.NewRequest(http.MethodGet, "/console/api/devices/"+device+"/predictions/latest?"+params.Encode(), nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("GET latest %s %v: %d want %d: %s", device, params, w.Code, want, w.Body.String())
		}
		var latest contracts.LatestPredictionV1
		if want == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &latest); err != nil {
				t.Fatal(err)
			}
		}
		return latest, w.Body.String()
	}
	window := func(from, to time.Time, extra ...string) url.Values {
		v := url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
		for i := 0; i+1 < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		return v
	}

	// Paginate across all 5 devA records across a 30-day window (splitting the equal-timestamp pair!).
	winFrom := t0
	winTo := staleAsOf.Add(time.Minute)
	var ids []uint64
	var records []contracts.PredictionHistoryRecordV1
	cursor := ""
	pages := 0
	for {
		params := window(winFrom, winTo, "limit", "2")
		if cursor != "" {
			params.Set("after", cursor)
		}
		page, _ := getHistory(handler, devA, params, viewer, http.StatusOK)
		pages++
		for _, rec := range page.Records {
			ids = append(ids, rec.ID)
			records = append(records, rec)
		}
		if page.NextAfter == nil {
			break
		}
		cursor = *page.NextAfter
	}
	wantIDs := []uint64{recNoModel.ID, recNoEvidence.ID, recRealV2.ID, recHealthy.ID, recStale.ID}
	if !reflect.DeepEqual(ids, wantIDs) || pages != 3 {
		t.Fatalf("paged ids=%v pages=%d, want %v in 3 pages", ids, pages, wantIDs)
	}
	// Verify unknown/stale preservation on returned records.
	if records[0].Health.Probability != nil || records[1].Health.Probability != nil || records[2].Health.Probability != nil ||
		records[3].Health.Status != health.HealthStatusHealthy || records[3].Stale ||
		records[4].Health.Status != health.HealthStatusUnknown || records[4].Health.UnknownReason != health.UnknownReasonStaleEvidence || !records[4].Stale {
		t.Fatalf("unexpected preserved states: %+v", records)
	}

	// Empty window & empty device return empty non-nil slices; /latest on empty device is 404.
	if empty, _ := getHistory(handler, emptyDev, window(winFrom, winTo), viewer, http.StatusOK); len(empty.Records) != 0 || empty.Records == nil || empty.NextAfter != nil {
		t.Fatalf("unexpected empty device history: %+v", empty)
	}
	getLatest(handler, emptyDev, url.Values{}, viewer, http.StatusNotFound)

	// Record a fresh healthy prediction on devB and check /latest before and after expiry.
	latestB, _ := getLatest(handler, devB, url.Values{}, viewer, http.StatusOK)
	if latestB.Stale || latestB.CurrentHealth.Status != health.HealthStatusHealthy || latestB.CurrentHealth.Probability == nil {
		t.Fatalf("expected fresh current health on devB, got %+v", latestB)
	}
	// Advance clock past devB prediction expiry -> /latest must NOT present a current risk value.
	b.clock.Advance(2 * time.Hour)
	viewer, _ = b.addSession(t, "viewer:pred", auth.RoleViewer, 0)
	expiredB, _ := getLatest(handler, devB, url.Values{}, viewer, http.StatusOK)
	if !expiredB.Stale || expiredB.CurrentHealth.Status != health.HealthStatusUnknown ||
		expiredB.CurrentHealth.UnknownReason != health.UnknownReasonStaleEvidence ||
		expiredB.CurrentHealth.Probability != nil || expiredB.CurrentHealth.HorizonHours != nil {
		t.Fatalf("expired latest leaked current risk value: %+v", expiredB)
	}

	// Wrong-scope, unauthorized, unknown, and malformed queries fail without presenting a risk value.
	_, bodyUnauth := getHistory(handler, devA, window(winFrom, winTo), "", http.StatusUnauthorized)
	_, bodyScope := getHistory(handler, devA, url.Values{"deployment_id": {"deployment:other"}, "from": {winFrom.Format(time.RFC3339)}, "to": {winTo.Format(time.RFC3339)}}, viewer, http.StatusForbidden)
	_, bodyMissing := getHistory(handler, "device:unknown", window(winFrom, winTo), viewer, http.StatusNotFound)
	for _, bdy := range []string{bodyUnauth, bodyScope, bodyMissing} {
		if strings.Contains(bdy, "probability") {
			t.Fatalf("denied response disclosed probability: %s", bdy)
		}
	}
	getLatest(handler, devA, url.Values{}, "", http.StatusUnauthorized)
	getLatest(handler, devA, url.Values{"deployment_id": {"deployment:other"}}, viewer, http.StatusForbidden)
	getLatest(handler, "device:unknown", url.Values{}, viewer, http.StatusNotFound)

	badParams := []url.Values{
		{},
		{"from": {winFrom.Format(time.RFC3339)}},
		window(winFrom, winFrom),
		window(winTo, winFrom),
		window(winFrom, winFrom.Add(32*24*time.Hour)),
		window(winFrom, winTo, "limit", "0"),
		window(winFrom, winTo, "limit", "101"),
		window(winFrom, winTo, "limit", "05"),
		window(winFrom, winTo, "after", "garbage"),
		window(winFrom, winTo, "after", "1.0"),
		window(winFrom, winTo, "after", winFrom.Add(-time.Minute).Format(time.RFC3339)+".1"),
		window(winFrom, winTo, "other", "x"),
		{"deployment_id": {""}, "from": {winFrom.Format(time.RFC3339)}, "to": {winTo.Format(time.RFC3339)}},
	}
	for _, params := range badParams {
		getHistory(handler, devA, params, viewer, http.StatusBadRequest)
	}
	// Cursor from before window start is rejected.
	beforeCursor := fmt.Sprintf("%d.1", winFrom.Add(-time.Second).UnixMicro())
	getHistory(handler, devA, window(winFrom, winTo, "after", beforeCursor), viewer, http.StatusBadRequest)

	// Revoked device remains queryable for historical audit.
	if _, _, err := b.repo.RevokeDevice(ctx, contracts.DeviceRevocationRequestV1{
		SchemaVersion: contracts.DeviceRevocationRequestV1Version, DeviceID: devA, ReasonReference: "incident:audit",
	}, "https://id.example.test", "admin:test"); err != nil {
		t.Fatal(err)
	}
	if revokedHist, _ := getHistory(handler, devA, window(winFrom, winTo), viewer, http.StatusOK); len(revokedHist.Records) != 5 {
		t.Fatalf("revoked device history count=%d want 5", len(revokedHist.Records))
	}

	// Controller restart retains all persisted prediction history and provenance identically.
	db2, err := database.Open(ctx, b.url)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	repo2, err := NewPostgresRepository(ctx, db2, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	service2, err := NewDeviceStateService(repo2, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler2 := NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: service2}).Handler()

	beforeRestart, _ := getHistory(handler, devA, window(winFrom, winTo), viewer, http.StatusOK)
	afterRestart, _ := getHistory(handler2, devA, window(winFrom, winTo), viewer, http.StatusOK)
	if !reflect.DeepEqual(beforeRestart, afterRestart) || len(afterRestart.Records) != 5 {
		t.Fatalf("history differed across controller restart:\nbefore=%+v\nafter=%+v", beforeRestart, afterRestart)
	}
	latestBefore, _ := getLatest(handler, devB, url.Values{}, viewer, http.StatusOK)
	latestAfter, _ := getLatest(handler2, devB, url.Values{}, viewer, http.StatusOK)
	if !reflect.DeepEqual(latestBefore, latestAfter) {
		t.Fatalf("latest prediction differed across restart:\nbefore=%+v\nafter=%+v", latestBefore, latestAfter)
	}
}

func TestPredictionHistoryRejectsWrongScopeAndBrokenEvidenceReferences(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	publisher := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{51}, 32))
	pubKey := publisher.Public().(ed25519.PublicKey)
	artifact := loadBaselineModelBytes(t)
	evalDir := t.TempDir()
	cfg := HealthConfig{PublisherKey: pubKey, EvaluationReports: EvaluationReportDir(evalDir)}

	dev := "device:broken-ref"
	keys := enrollTestDevice(t, b, dev)
	modelArtifact := artifactWithVersion(t, artifact, "baseline.broken-ref.v1")
	manifest := buildSignedControllerManifest(t, publisher, modelArtifact, health.ControllerInferenceRuntime())
	evalBytes, evalDigest := buildPassingML05Report(t, manifest, 0.0, 2.0)
	writeEvalReportFile(t, evalDir, evalDigest, evalBytes)
	registerAndActivateModel(t, b.repo, publisher, modelArtifact, health.ControllerInferenceRuntime(), evalDigest, health.ML05PolicyVersion)

	startDay := b.clock.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 2).Add(12 * time.Hour)
	healthySMART7d := map[uint64][3]int64{
		23: {0, 11000, 0}, 24: {0, 11024, 0}, 25: {0, 11048, 0}, 26: {0, 11072, 0},
		27: {0, 11096, 0}, 28: {0, 11120, 0}, 29: {0, 11144, 0},
	}
	for i := range 28 {
		acceptTelemetrySample(t, b, dev, keys, uint64(2+i), startDay.AddDate(0, 0, i), nil)
	}
	asOf := startDay.AddDate(0, 0, 27).Add(20 * time.Minute)
	b.clock.Advance(asOf.Sub(b.clock.Now()))

	dh, err := b.repo.evaluateDeviceHealth(ctx, cfg, dev, asOf, makeSMARTMapReader(healthySMART7d))
	if err != nil {
		t.Fatal(err)
	}

	// Write-time rejections: wrong deployment scope, unknown device, missing sequence, mismatched evidence digest, mismatched model approval.
	wrongScope := dh
	wrongScope.DeploymentID = "deployment:other"
	if _, err := b.repo.RecordDeviceHealth(ctx, wrongScope); !errors.Is(err, ErrDeviceStateScope) {
		t.Fatalf("expected ErrDeviceStateScope, got %v", err)
	}
	unknownDev := dh
	unknownDev.DeviceID = "device:ghost"
	if _, err := b.repo.RecordDeviceHealth(ctx, unknownDev); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("expected ErrRepositoryNotFound, got %v", err)
	}
	missingSeq := dh
	missingSeqSample := *dh.LatestSample
	missingSeqSample.Sequence = 999
	missingSeq.LatestSample = &missingSeqSample
	if _, err := b.repo.RecordDeviceHealth(ctx, missingSeq); !errors.Is(err, ErrPredictionEvidenceBroken) {
		t.Fatalf("expected ErrPredictionEvidenceBroken for missing seq, got %v", err)
	}
	badDigest := dh
	badDigestSample := *dh.LatestSample
	badDigestSample.PayloadSHA256 = strings.Repeat("0", 64)
	badDigest.LatestSample = &badDigestSample
	if _, err := b.repo.RecordDeviceHealth(ctx, badDigest); !errors.Is(err, ErrPredictionEvidenceBroken) {
		t.Fatalf("expected ErrPredictionEvidenceBroken for digest mismatch, got %v", err)
	}
	badModel := dh
	badModelRef := *dh.Model
	badModelRef.SHA256 = strings.Repeat("1", 64)
	badModel.Model = &badModelRef
	if _, err := b.repo.RecordDeviceHealth(ctx, badModel); !errors.Is(err, ErrPredictionInvalid) {
		t.Fatalf("expected ErrPredictionInvalid for mismatched model ref, got %v", err)
	}
	badEval := dh
	badEval.Assessment.EvaluationSHA256 = strings.Repeat("2", 64)
	if _, err := b.repo.RecordDeviceHealth(ctx, badEval); !errors.Is(err, ErrPredictionEvidenceBroken) {
		t.Fatalf("expected ErrPredictionEvidenceBroken for eval mismatch, got %v", err)
	}

	var storedCount int
	if err := b.db.QueryRow(`SELECT count(*) FROM device_predictions`).Scan(&storedCount); err != nil || storedCount != 0 {
		t.Fatalf("refused writes left %d rows", storedCount)
	}

	// Database triggers refuse direct mutations and invalid inserts.
	rec, err := b.repo.RecordDeviceHealth(ctx, dh)
	if err != nil {
		t.Fatalf("valid RecordDeviceHealth failed: %v", err)
	}
	for name, stmt := range map[string]string{
		"update prediction": `UPDATE device_predictions SET rule_reason='tampered'`,
		"delete prediction": `DELETE FROM device_predictions`,
		"bad evidence digest insert": fmt.Sprintf(`INSERT INTO device_predictions (
			deployment_id, device_id, as_of, expires_at, recorded_at, rules_version, rule_reason,
			health_status, probability, probability_unit, horizon_hours, model_status,
			model_version, model_sha256, policy_version, policy_sha256, evaluation_sha256,
			evidence_sequence, evidence_collected_at, evidence_received_at, evidence_payload_sha256,
			evidence_request_sha256, evidence_source, evidence_telemetry_schema_version,
			feature_version, feature_window_start, feature_window_end, feature_status,
			feature_count, feature_samples_read, feature_last_sequence, feature_vector,
			fault_current_from, fault_current_to, fault_current_days, fault_current_sampled_days, fault_current_sufficient,
			fault_baseline_from, fault_baseline_to, fault_baseline_days, fault_baseline_sampled_days, fault_baseline_sufficient,
			fault_observation_note, fault_summary, fault_samples_read, fault_last_sequence, prediction
		) SELECT deployment_id, device_id, as_of + interval '1 second', expires_at + interval '1 second', recorded_at, rules_version, rule_reason,
			health_status, probability, probability_unit, horizon_hours, model_status,
			model_version, model_sha256, policy_version, policy_sha256, evaluation_sha256,
			evidence_sequence, evidence_collected_at, evidence_received_at, decode(repeat('00',32),'hex'),
			evidence_request_sha256, evidence_source, evidence_telemetry_schema_version,
			feature_version, feature_window_start, feature_window_end, feature_status,
			feature_count, feature_samples_read, feature_last_sequence, feature_vector,
			fault_current_from, fault_current_to, fault_current_days, fault_current_sampled_days, fault_current_sufficient,
			fault_baseline_from, fault_baseline_to, fault_baseline_days, fault_baseline_sampled_days, fault_baseline_sufficient,
			fault_observation_note, fault_summary, fault_samples_read, fault_last_sequence, prediction
		FROM device_predictions WHERE id = %d`, rec.ID),
	} {
		if _, err := b.db.Exec(stmt); err == nil {
			t.Fatalf("database allowed %s", name)
		}
	}

	// Corrupt underlying device_evidence payload at rest -> read queries must reject without returning a risk value.
	service, err := NewDeviceStateService(b.repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: service}).Handler()
	viewer, _ := b.addSession(t, "viewer:broken", auth.RoleViewer, 0)

	if _, err := b.db.Exec(`UPDATE device_evidence SET payload_bytes = $1 WHERE deployment_id=$2 AND device_id=$3 AND sequence=29`,
		[]byte(`{"tampered":true}`), b.repo.deploymentID, dev); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.PredictionHistory(ctx, dev, asOf.Add(-time.Hour), asOf.Add(time.Hour), nil, 10); !errors.Is(err, ErrPredictionEvidenceBroken) {
		t.Fatalf("expected ErrPredictionEvidenceBroken on PredictionHistory, got %v", err)
	}
	if _, err := b.repo.LatestDevicePrediction(ctx, dev); !errors.Is(err, ErrPredictionEvidenceBroken) {
		t.Fatalf("expected ErrPredictionEvidenceBroken on LatestDevicePrediction, got %v", err)
	}

	for _, path := range []string{
		fmt.Sprintf("/console/api/devices/%s/predictions?deployment_id=%s&from=%s&to=%s",
			dev, url.QueryEscape(b.repo.deploymentID),
			url.QueryEscape(asOf.Add(-time.Hour).Format(time.RFC3339)),
			url.QueryEscape(asOf.Add(time.Hour).Format(time.RFC3339))),
		fmt.Sprintf("/console/api/devices/%s/predictions/latest?deployment_id=%s",
			dev, url.QueryEscape(b.repo.deploymentID)),
	} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: viewer})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "probability") {
			t.Fatalf("%s with broken evidence returned %d body=%q", path, w.Code, w.Body.String())
		}
	}
}
