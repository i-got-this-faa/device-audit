package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/i-got-this-faa/device-audit/packages/health"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

// forecastDiagnosticBed has two enrolled devices whose newest assessment came
// from a promoted, evaluated and active model.
type forecastDiagnosticBed struct {
	*registryBed
	cfg      HealthConfig
	actor    contracts.ModelActorV1
	manifest contracts.ModelManifestV1
	digest   string
	devices  map[string]enrollmentKeys
	startDay time.Time
}

func newForecastDiagnosticBed(t *testing.T, devices ...string) *forecastDiagnosticBed {
	t.Helper()
	b := &forecastDiagnosticBed{registryBed: newRegistryBed(t), devices: map[string]enrollmentKeys{}}
	ctx := context.Background()
	pub := b.publisher.Public().(ed25519.PublicKey)
	b.actor = contracts.ModelActorV1(federated.Actor{Issuer: "https://id.example.test", Subject: "admin:test"})
	evalDir := t.TempDir()
	b.cfg = HealthConfig{PublisherKey: pub, EvaluationReports: EvaluationReportDir(evalDir)}
	for _, device := range devices {
		b.devices[device] = enrollTestDevice(t, b.enrollmentTestBed, device)
	}
	artifact := artifactWithVersion(t, loadBaselineModelBytes(t), "baseline.forecast-diagnostics.v1")
	b.manifest = buildSignedControllerManifest(t, b.publisher, artifact, health.ControllerInferenceRuntime())
	if _, _, err := b.repo.PutModelArtifact(ctx, upload(b.manifest, artifact), pub, b.actor); err != nil {
		t.Fatal(err)
	}
	report, digest := buildPassingML05Report(t, b.manifest, 0.0, 2.0)
	b.digest = digest
	writeEvalReportFile(t, evalDir, digest, report)
	if _, _, err := b.repo.PutModelEvaluation(ctx, signEvaluation(b.manifest, report, b.publisher), pub, b.actor); err != nil {
		t.Fatal(err)
	}
	request := contracts.ModelReferenceRequestV1{SchemaVersion: contracts.ModelReferenceRequestV1Version, ModelVersion: b.manifest.ModelVersion, ArtifactSHA256: b.manifest.ArtifactSHA256}
	if _, err := b.repo.SetModelReference(ctx, contracts.ModelSlotCandidate, request, b.actor); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.PromoteModel(ctx, promotionRequestFor(b.manifest, digest), b.actor); err != nil {
		t.Fatal(err)
	}
	b.startDay = b.clock.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 2).Add(12 * time.Hour)
	for device, keys := range b.devices {
		for i := range 28 {
			acceptTelemetrySample(t, b.enrollmentTestBed, device, keys, uint64(2+i), b.startDay.AddDate(0, 0, i), nil)
		}
	}
	return b
}

var (
	forecastHealthySMART = map[uint64][3]int64{
		23: {0, 11000, 0}, 24: {0, 11024, 0}, 25: {0, 11048, 0}, 26: {0, 11072, 0},
		27: {0, 11096, 0}, 28: {0, 11120, 0}, 29: {0, 11144, 0},
	}
	// Complete-week reallocations: the active model scores this degraded.
	forecastDegradedSMART = map[uint64][3]int64{
		23: {0, 11000, 0}, 24: {0, 11024, 0}, 25: {0, 11048, 0}, 26: {0, 11072, 0},
		27: {8, 11096, 0}, 28: {8, 11120, 0}, 29: {16, 11144, 0},
	}
)

// assess records an assessment for device at asOf from smart counters.
func (b *forecastDiagnosticBed) assess(t *testing.T, repo *PostgresRepository, device string, asOf time.Time, smart map[uint64][3]int64) {
	t.Helper()
	if delta := asOf.Sub(b.clock.Now()); delta > 0 {
		b.clock.Advance(delta)
	}
	if _, err := repo.evaluateAndRecordDeviceHealth(context.Background(), b.cfg, device, asOf, makeSMARTMapReader(smart)); err != nil {
		t.Fatal(err)
	}
}

func (b *forecastDiagnosticBed) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := b.db.QueryRow(`SELECT count(*) FROM `+table+` WHERE deployment_id=$1`, b.repo.deploymentID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestForecastDrivenDiagnosticsAreEvaluatedFreshDeduplicatedAndTraceable(t *testing.T) {
	b := newForecastDiagnosticBed(t, "device:fd-a", "device:fd-b", "device:fd-healthy")
	ctx := context.Background()
	diagKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x46}, ed25519.SeedSize))
	diagPub := diagKey.Public().(ed25519.PublicKey)
	actor := workflows.Actor{Issuer: "https://id.example.test", Subject: "admin:fd"}
	const devA, devB, devC = "device:fd-a", "device:fd-b", "device:fd-healthy"
	trigger := func(repo *PostgresRepository, device string) contracts.ForecastDiagnosticsV1 {
		t.Helper()
		out, err := repo.TriggerForecastDiagnostics(ctx, device, diagKey, actor)
		if err != nil {
			t.Fatalf("trigger %s: %v", device, err)
		}
		return out
	}

	if _, err := b.repo.TriggerForecastDiagnostics(ctx, "device:unknown", diagKey, actor); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
	// No assessment at all: nothing is launched and the reason is stable.
	none := trigger(b.repo, devA)
	if none.ForecastStatus != contracts.ForecastUnavailable || none.ForecastReason != contracts.ForecastReasonNoPrediction || len(none.Decisions) != 0 {
		t.Fatalf("no prediction: %+v", none)
	}

	asOf := b.startDay.AddDate(0, 0, 27).Add(20 * time.Minute)
	b.assess(t, b.repo, devA, asOf, forecastDegradedSMART)
	b.assess(t, b.repo, devB, asOf, forecastDegradedSMART)
	b.assess(t, b.repo, devC, asOf, forecastHealthySMART)

	// A healthy forecast does not call for a diagnostic.
	healthy := trigger(b.repo, devC)
	if healthy.ForecastStatus != contracts.ForecastAvailable || len(healthy.Decisions) != 0 {
		t.Fatalf("healthy forecast: %+v", healthy)
	}
	if b.count(t, "diagnostic_assignments") != 0 || b.count(t, "forecast_diagnostic_triggers") != 0 {
		t.Fatal("a healthy forecast queued work")
	}

	// A degraded, evaluated, fresh forecast launches one bounded storage probe on each endpoint.
	first := trigger(b.repo, devA)
	if first.ForecastStatus != contracts.ForecastAvailable || first.PolicyVersion != workflows.ForecastDiagnosticPolicyVersion || len(first.Decisions) != 1 {
		t.Fatalf("first trigger: %+v", first)
	}
	d := first.Decisions[0]
	if d.Category != "storage" || d.ProbeID != contracts.DiagnosticProbeStorageHealthV1 || d.Outcome != contracts.ForecastDiagnosticLaunched ||
		d.AssignmentStatus != string(workflows.StatusPending) || d.Probability < 0.5 || d.HorizonHours != 168 {
		t.Fatalf("launched decision: %+v", d)
	}
	assignmentA := d.AssignmentID
	rec, err := b.repo.DiagnosticAssignment(ctx, assignmentA)
	if err != nil {
		t.Fatal(err)
	}
	if rec.DeviceID != devA || rec.ProbeID != contracts.DiagnosticProbeStorageHealthV1 || rec.SignedAssignment.VerifySignature(diagPub) != nil ||
		rec.SignedAssignment.Arguments.ComponentID == nil || *rec.SignedAssignment.Arguments.ComponentID != "storage:disk-0" ||
		rec.SignedAssignment.Budget.WallSeconds != 30 || rec.RequestedBy != actor {
		t.Fatalf("assignment is not the bounded signed storage probe: %+v", rec)
	}
	secondEndpoint := trigger(b.repo, devB)
	if len(secondEndpoint.Decisions) != 1 || secondEndpoint.Decisions[0].Outcome != contracts.ForecastDiagnosticLaunched || secondEndpoint.Decisions[0].AssignmentID == assignmentA {
		t.Fatalf("second endpoint: %+v", secondEndpoint)
	}
	assignmentB := secondEndpoint.Decisions[0].AssignmentID

	// Repeated delivery of the same forecast, including after a restart, keeps one job.
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	for _, repo := range []*PostgresRepository{b.repo, b.repo, restarted} {
		again := trigger(repo, devA)
		if len(again.Decisions) != 1 || again.Decisions[0].Outcome != contracts.ForecastDiagnosticDeduplicated ||
			again.Decisions[0].AssignmentID != assignmentA || again.Decisions[0].AssignmentStatus != string(workflows.StatusPending) {
			t.Fatalf("repeat delivery: %+v", again)
		}
	}
	if b.count(t, "diagnostic_assignments") != 2 || b.count(t, "forecast_diagnostic_triggers") != 2 {
		t.Fatalf("repeat delivery changed state: assignments=%d triggers=%d", b.count(t, "diagnostic_assignments"), b.count(t, "forecast_diagnostic_triggers"))
	}

	// A newer assessment while the earlier job is unfinished adds no second job.
	newer := asOf.Add(10 * time.Minute)
	b.assess(t, b.repo, devB, newer, forecastDegradedSMART)
	inFlight := trigger(b.repo, devB)
	if len(inFlight.Decisions) != 1 || inFlight.Decisions[0].Outcome != contracts.ForecastDiagnosticSkipped ||
		inFlight.Decisions[0].Reason != contracts.ForecastDiagnosticReasonJobInFlight || inFlight.Decisions[0].AssignmentID != assignmentB {
		t.Fatalf("in-flight: %+v", inFlight)
	}
	if b.count(t, "diagnostic_assignments") != 2 {
		t.Fatal("an unfinished job was duplicated")
	}

	// Each endpoint runs its job and reports a device-signed local result.
	devices := map[string]struct{ assignment, evidence string }{devA: {assignmentA, "ref:forecast:a"}, devB: {assignmentB, "ref:forecast:b"}}
	runner := workflows.NewProbeRunner(func(_ context.Context, _ workflows.Request) ([]byte, error) {
		return []byte(`{"schema_version":"device-audit.probe-evidence.v1","health":"ok"}`), nil
	})
	for device, job := range devices {
		poll, err := b.repo.PollDiagnosticAssignments(ctx, device, time.Minute)
		if err != nil || len(poll.Assignments) != 1 || poll.Assignments[0].AssignmentID != job.assignment {
			t.Fatalf("poll %s: %+v err=%v", device, poll, err)
		}
		result, err := workflows.ExecuteAssignedToResult(ctx, runner, poll.Assignments[0], diagPub, b.devices[device].signing,
			b.repo.deploymentID, device, "boot:fd:1", job.evidence, 30, b.clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, created, err := b.repo.SubmitDiagnosticResult(ctx, result); err != nil || !created {
			t.Fatalf("submit %s: created=%v err=%v", device, created, err)
		}
	}
	for device, job := range devices {
		trace, err := restarted.ForecastDiagnosticTrace(ctx, device, 10)
		if err != nil || len(trace.Links) != 1 {
			t.Fatalf("trace %s: %+v err=%v", device, trace, err)
		}
		link := trace.Links[0]
		if link.AssignmentID != job.assignment || link.AssignmentStatus != string(workflows.StatusSucceeded) || link.Category != "storage" ||
			link.ResultState == nil || *link.ResultState != "succeeded" || len(link.Evidence) != 1 || link.Evidence[0].ReferenceID != job.evidence ||
			link.ModelVersion != b.manifest.ModelVersion || link.ArtifactSHA256 != b.manifest.ArtifactSHA256 || link.EvaluationSHA256 != b.digest ||
			link.EvidenceSequence == nil || *link.EvidenceSequence != 29 || link.PolicyVersion != workflows.ForecastDiagnosticPolicyVersion ||
			!link.AsOf.Equal(asOf) || link.TriggeredBy != contracts.ModelActorV1(actor) {
			t.Fatalf("forecast-to-job-to-insight trace %s: %+v", device, link)
		}
	}

	// Once the job finished, a newer fresh forecast may launch the next one.
	again := trigger(b.repo, devB)
	if len(again.Decisions) != 1 || again.Decisions[0].Outcome != contracts.ForecastDiagnosticLaunched || again.Decisions[0].AssignmentID == assignmentB {
		t.Fatalf("next forecast after a finished job: %+v", again)
	}
	if b.count(t, "diagnostic_assignments") != 3 || b.count(t, "forecast_diagnostic_triggers") != 3 {
		t.Fatal("unexpected job count after the next forecast")
	}

	// The link and the model behind it cannot be rewritten.
	if _, err := b.db.Exec(`UPDATE forecast_diagnostic_triggers SET probability=0`); err == nil {
		t.Fatal("trigger link was updated")
	}
	if _, err := b.db.Exec(`DELETE FROM forecast_diagnostic_triggers`); err == nil {
		t.Fatal("trigger link was deleted")
	}

	// A different active model makes the forecast stale; nothing is launched.
	jobs := b.count(t, "diagnostic_assignments")
	other := artifactWithVersion(t, loadBaselineModelBytes(t), "baseline.forecast-diagnostics-other.v1")
	registerAndActivateModel(t, b.repo, b.publisher, other, health.ControllerInferenceRuntime(), b.digest, health.ML05PolicyVersion)
	superseded := trigger(b.repo, devA)
	if superseded.ForecastStatus != contracts.ForecastStale || superseded.ForecastReason != contracts.ForecastReasonModelSuperseded || len(superseded.Decisions) != 0 {
		t.Fatalf("superseded model: %+v", superseded)
	}
	// Past expiry the same assessment is stale too, also after a restart.
	b.clock.Advance(3 * time.Hour)
	expired := trigger(restarted, devB)
	if expired.ForecastStatus != contracts.ForecastStale || len(expired.Decisions) != 0 {
		t.Fatalf("expired: %+v", expired)
	}
	if b.count(t, "diagnostic_assignments") != jobs {
		t.Fatal("a stale forecast launched work")
	}
}

func TestForecastDiagnosticRoutesAuthorizeAndServeTheTrace(t *testing.T) {
	b := newForecastDiagnosticBed(t, "device:fd-route")
	const device = "device:fd-route"
	diagKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x47}, ed25519.SeedSize))
	service, err := NewDiagnosticService(b.repo, b.admin, diagKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, Diagnostics: service}).Handler()
	b.assess(t, b.repo, device, b.startDay.AddDate(0, 0, 27).Add(20*time.Minute), forecastDegradedSMART)
	admin, csrf := b.addSession(t, "admin:fd-route", auth.RoleAdmin, 0)
	viewer, _ := b.addSession(t, "viewer:fd-route", auth.RoleViewer, 0)
	do := func(method, target, body, cookie, token string, want int) []byte {
		t.Helper()
		r := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: cookie})
		}
		if token != "" {
			r.Header.Set("Origin", "https://console.example.test")
			r.Header.Set("X-CSRF-Token", token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: %d want %d: %s", method, target, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	post := "/console/api/devices/" + device + "/forecast-diagnostics"
	do(http.MethodPost, post, "", "", "", http.StatusUnauthorized)
	do(http.MethodPost, post, "", viewer, csrf, http.StatusForbidden)
	do(http.MethodPost, post+"?force=1", "", admin, csrf, http.StatusBadRequest)
	do(http.MethodPost, post, `{"probe_id":"arbitrary_shell.v1"}`, admin, csrf, http.StatusBadRequest)
	do(http.MethodPost, "/console/api/devices/device:missing/forecast-diagnostics", "", admin, csrf, http.StatusNotFound)
	if b.count(t, "diagnostic_assignments") != 0 {
		t.Fatal("a refused request queued work")
	}

	var out contracts.ForecastDiagnosticsV1
	if err := json.Unmarshal(do(http.MethodPost, post, "", admin, csrf, http.StatusOK), &out); err != nil ||
		len(out.Decisions) != 1 || out.Decisions[0].Outcome != contracts.ForecastDiagnosticLaunched {
		t.Fatalf("launch over HTTP: %+v err=%v", out, err)
	}
	if err := json.Unmarshal(do(http.MethodPost, post, "{}", admin, csrf, http.StatusOK), &out); err != nil ||
		len(out.Decisions) != 1 || out.Decisions[0].Outcome != contracts.ForecastDiagnosticDeduplicated {
		t.Fatalf("repeat over HTTP: %+v err=%v", out, err)
	}

	scope := "?deployment_id=" + b.repo.deploymentID
	do(http.MethodGet, post+scope, "", "", "", http.StatusUnauthorized)
	do(http.MethodGet, post, "", viewer, "", http.StatusBadRequest)
	do(http.MethodGet, post+"?deployment_id=deployment:other", "", viewer, "", http.StatusForbidden)
	do(http.MethodGet, post+scope+"&limit=0", "", viewer, "", http.StatusBadRequest)
	do(http.MethodGet, "/console/api/devices/device:missing/forecast-diagnostics"+scope, "", viewer, "", http.StatusNotFound)
	var trace contracts.ForecastDiagnosticTraceV1
	if err := json.Unmarshal(do(http.MethodGet, post+scope, "", viewer, "", http.StatusOK), &trace); err != nil ||
		len(trace.Links) != 1 || trace.Links[0].AssignmentID != out.Decisions[0].AssignmentID || trace.Links[0].AssignmentStatus != string(workflows.StatusPending) ||
		len(trace.Links[0].Evidence) != 0 || trace.Links[0].ResultState != nil {
		t.Fatalf("trace over HTTP: %+v err=%v", trace, err)
	}
}
