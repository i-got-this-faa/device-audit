package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	c "github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// FED10 #115 at the console HTTP boundary with real PostgreSQL: a candidate
// becomes active only through a stored held-out evaluation and promotion.

// approveWithoutEvaluationGate inserts an approval the way the database would
// refuse, so tests can prove the loaders and the promotion do not rely on it.
func approveWithoutEvaluationGate(t *testing.T, repo *PostgresRepository, version, artifactSHA, evaluationSHA, policyVersion string) {
	t.Helper()
	tx, err := repo.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE model_approvals DISABLE TRIGGER model_approvals_require_evaluation`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO model_approvals (deployment_id, model_version, artifact_sha256, evaluation_sha256, policy_version,
		approved_at, actor_issuer, actor_subject) VALUES ($1,$2,decode($3,'hex'),decode($4,'hex'),$5,now(),'console:local','admin@example.com')`,
		repo.deploymentID, version, artifactSHA, evaluationSHA, policyVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`ALTER TABLE model_approvals ENABLE TRIGGER model_approvals_require_evaluation`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// evaluation signs report as the model publisher would.
func (b *registryBed) evaluation(t *testing.T, m c.ModelManifestV1, report []byte) c.ModelEvaluationSubmissionV1 {
	t.Helper()
	return signEvaluation(m, report, b.publisher)
}

func signEvaluation(m c.ModelManifestV1, report []byte, key ed25519.PrivateKey) c.ModelEvaluationSubmissionV1 {
	submission := c.ModelEvaluationSubmissionV1{SchemaVersion: c.ModelEvaluationSubmissionV1Version, ModelVersion: m.ModelVersion,
		ArtifactSHA256: m.ArtifactSHA256, Report: report, SigningKeyID: m.SigningKeyID}
	submission.Signature = hex.EncodeToString(ed25519.Sign(key, submission.SigningBytes()))
	return submission
}

func promotionRequestFor(m c.ModelManifestV1, evaluationSHA string) c.ModelPromotionRequestV1 {
	return c.ModelPromotionRequestV1{SchemaVersion: c.ModelPromotionRequestV1Version, ModelVersion: m.ModelVersion,
		ArtifactSHA256: m.ArtifactSHA256, EvaluationSHA256: evaluationSHA}
}

func passingReport(t *testing.T, m c.ModelManifestV1) ([]byte, string) {
	t.Helper()
	return buildPassingML05Report(t, m, 0.0, 2.0)
}

// reportWith builds the passing report for m and lets edit change its metrics.
func reportWith(t *testing.T, m c.ModelManifestV1, edit func(report map[string]any, metrics map[string]any)) ([]byte, string) {
	t.Helper()
	raw, _ := passingReport(t, m)
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	edit(report, report["metrics"].(map[string]any))
	out, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return out, sha256DigestHex(out)
}

func metric(point, lower, upper float64) map[string]any {
	return map[string]any{"point": point, "lower": lower, "upper": upper}
}

// stageCandidate uploads a signed inference artifact and points the candidate slot at it.
func (b *registryBed) stageCandidate(t *testing.T, version string) c.ModelManifestV1 {
	t.Helper()
	artifact := []byte("synthetic model bytes " + version)
	m := b.manifest(t, b.publisher, version, artifact, c.ModelPurposeInference)
	b.expect(t, http.MethodPost, "/console/api/models", upload(m, artifact), b.adminHeaders(), http.StatusCreated, "")
	b.expect(t, http.MethodPut, "/console/api/model-references/candidate", c.ModelReferenceRequestV1{SchemaVersion: c.ModelReferenceRequestV1Version,
		ModelVersion: version, ArtifactSHA256: m.ArtifactSHA256}, b.adminHeaders(), http.StatusOK, "")
	return m
}

func (b *registryBed) submit(t *testing.T, m c.ModelManifestV1, report []byte, status int, contains string) []byte {
	t.Helper()
	return b.expect(t, http.MethodPost, "/console/api/models/"+m.ModelVersion+"/evaluation", b.evaluation(t, m, report), b.adminHeaders(), status, contains)
}

func (b *registryBed) promote(t *testing.T, m c.ModelManifestV1, evaluationSHA string, status int, contains string) c.ModelPromotionV1 {
	t.Helper()
	body := b.expect(t, http.MethodPost, "/console/api/models/"+m.ModelVersion+"/promotion", promotionRequestFor(m, evaluationSHA), b.adminHeaders(), status, contains)
	var decision c.ModelPromotionV1
	if status < 300 {
		if err := json.Unmarshal(body, &decision); err != nil {
			t.Fatal(err)
		}
	}
	return decision
}

func (b *registryBed) activeVersion(t *testing.T) string {
	t.Helper()
	if refs := b.references(t, b.server); refs.Active != nil {
		return refs.Active.ModelVersion
	}
	return ""
}

func TestModelPromotionGatesCandidateOnHeldOutEvaluation(t *testing.T) {
	b := newRegistryBed(t)

	// A candidate with no evaluation cannot be promoted, and a viewer, a stale
	// administrator or a report from another key cannot supply evidence.
	m1 := b.stageCandidate(t, "synthetic.1")
	report1, digest1 := passingReport(t, m1)
	b.promote(t, m1, digest1, http.StatusNotFound, "")
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.1/evaluation", b.evaluation(t, m1, report1), b.viewer, http.StatusForbidden, "")
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.1/evaluation", b.evaluation(t, m1, report1), b.staleAdm, http.StatusForbidden, "")
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.1/evaluation", signEvaluation(m1, report1, stranger), b.adminHeaders(), http.StatusForbidden, string(c.ModelRejectionInvalidSignature))
	forged := b.evaluation(t, m1, report1)
	forged.Report = append(bytes.Clone(report1), ' ')
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.1/evaluation", forged, b.adminHeaders(), http.StatusForbidden, string(c.ModelRejectionInvalidSignature))
	// A report that names another model is refused and consumes nothing.
	other := b.manifest(t, b.publisher, "synthetic.other", []byte("other"), c.ModelPurposeInference)
	otherReport, _ := passingReport(t, other)
	b.submit(t, m1, otherReport, http.StatusConflict, string(c.ModelRejectionReferenceMismatch))

	// Poor calibration fails the frozen ML05 gate: the decision is recorded as
	// rejected, the candidate slot is cleared and nothing becomes active.
	poor, poorDigest := reportWith(t, m1, func(_ map[string]any, metrics map[string]any) {
		metrics["brier_skill_vs_prevalence"] = metric(-0.4, -0.6, -0.2)
		metrics["calibration_slope"] = metric(0.4, 0.3, 0.5)
	})
	b.submit(t, m1, poor, http.StatusCreated, `"verdict":"fail"`)
	b.submit(t, m1, poor, http.StatusOK, `"verdict":"fail"`)
	b.submit(t, m1, report1, http.StatusConflict, string(c.ModelRejectionVersionConflict))
	rejected := b.promote(t, m1, poorDigest, http.StatusCreated, `"outcome":"rejected"`)
	for _, reason := range []string{"evaluation_fail", "gate_failed:brier_skill", "gate_failed:calibration_slope_low"} {
		if !slices.Contains(rejected.Reasons, reason) {
			t.Fatalf("rejection reasons %v lack %q", rejected.Reasons, reason)
		}
	}
	if rejected.Baseline != nil || b.activeVersion(t) != "" {
		t.Fatalf("a rejected first candidate changed the registry: %+v active=%q", rejected, b.activeVersion(t))
	}
	if refs := b.references(t, b.server); refs.Candidate != nil {
		t.Fatalf("a decided candidate stayed in the candidate slot: %+v", refs)
	}
	b.expect(t, http.MethodPut, "/console/api/model-references/active", c.ModelReferenceRequestV1{SchemaVersion: c.ModelReferenceRequestV1Version,
		ModelVersion: "synthetic.1", ArtifactSHA256: m1.ArtifactSHA256}, b.adminHeaders(), http.StatusConflict, string(c.ModelRejectionNotApproved))
	// The decision is final and repeating it returns the stored one.
	b.promote(t, m1, poorDigest, http.StatusOK, `"outcome":"rejected"`)
	b.promote(t, m1, digest1, http.StatusConflict, string(c.ModelRejectionVersionConflict))

	// Missing evaluation data and an interrupted evaluation cannot decide, so
	// they never pass and never fail the model on evidence they do not have.
	m2 := b.stageCandidate(t, "synthetic.2")
	thin, thinDigest := reportWith(t, m2, func(report map[string]any, _ map[string]any) {
		report["counts"].(map[string]any)["test_devices"] = 12
		report["evaluation_error"] = "evaluation_interrupted_or_in_progress"
	})
	b.submit(t, m2, thin, http.StatusCreated, `"verdict":"blocked"`)
	blocked := b.promote(t, m2, thinDigest, http.StatusCreated, `"outcome":"rejected"`)
	for _, reason := range []string{"evaluation_blocked", "insufficient:test_devices", "evaluation_error"} {
		if !slices.Contains(blocked.Reasons, reason) {
			t.Fatalf("blocked reasons %v lack %q", blocked.Reasons, reason)
		}
	}
	var blockedEvaluation c.ModelEvaluationV1
	if err := json.Unmarshal(b.expect(t, http.MethodGet, "/console/api/models/synthetic.2/evaluation", nil, b.viewer, http.StatusOK, `"metrics":null`), &blockedEvaluation); err != nil {
		t.Fatal(err)
	}
	if blockedEvaluation.Verdict != c.ModelEvaluationBlocked || b.activeVersion(t) != "" {
		t.Fatalf("blocked evaluation: %+v active=%q", blockedEvaluation, b.activeVersion(t))
	}

	// A passing evaluation promotes the first model. Only the candidate slot
	// may be promoted, and the stored evaluation is readable with its metrics.
	m3 := b.stageCandidate(t, "synthetic.3")
	report3, digest3 := reportWith(t, m3, func(_ map[string]any, metrics map[string]any) {
		metrics["average_precision"] = metric(0.20, 0.10, 0.30)
	})
	b.promote(t, m3, digest3, http.StatusNotFound, "")
	b.submit(t, m3, report3, http.StatusCreated, `"verdict":"pass"`)
	b.promote(t, m3, strings.Repeat("0", 64), http.StatusConflict, string(c.ModelRejectionReferenceMismatch))
	first := b.promote(t, m3, digest3, http.StatusCreated, `"outcome":"promoted"`)
	if first.Baseline != nil || first.PromotionPolicyVersion != federated.PromotionPolicyVersion || len(first.Reasons) != 0 || b.activeVersion(t) != "synthetic.3" {
		t.Fatalf("first promotion: %+v active=%q", first, b.activeVersion(t))
	}
	var stored c.ModelEvaluationV1
	if err := json.Unmarshal(b.expect(t, http.MethodGet, "/console/api/models/synthetic.3/evaluation", nil, b.viewer, http.StatusOK, `"verdict":"pass"`), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Metrics["average_precision"].Point != 0.20 || stored.EvaluationSHA256 != digest3 || stored.SubmittedBy.Subject == "" {
		t.Fatalf("stored evaluation: %+v", stored)
	}
	approved := b.expect(t, http.MethodGet, "/console/api/models/synthetic.3", nil, b.viewer, http.StatusOK, `"policy_version":"ml05.v1"`)
	if !strings.Contains(string(approved), digest3) {
		t.Fatalf("approval does not cite the promoted evaluation: %s", approved)
	}
	b.promote(t, m3, digest3, http.StatusOK, `"outcome":"promoted"`)

	// A candidate that passes ML05 but is worse than the active model is
	// rejected on the regression gate, and the active model is unchanged.
	m4 := b.stageCandidate(t, "synthetic.4")
	report4, digest4 := reportWith(t, m4, func(_ map[string]any, metrics map[string]any) {
		metrics["average_precision"] = metric(0.19, 0.09, 0.29)
	})
	b.submit(t, m4, report4, http.StatusCreated, `"verdict":"pass"`)
	regressed := b.promote(t, m4, digest4, http.StatusCreated, `"outcome":"rejected"`)
	if !slices.Equal(regressed.Reasons, []string{"regression:active_average_precision"}) || regressed.Baseline == nil ||
		regressed.Baseline.ModelVersion != "synthetic.3" || len(regressed.Checks) != len(federated.RegressionGates) || b.activeVersion(t) != "synthetic.3" {
		t.Fatalf("regression decision: %+v active=%q", regressed, b.activeVersion(t))
	}

	// A better candidate replaces the active model and records its baseline.
	m5 := b.stageCandidate(t, "synthetic.5")
	report5, digest5 := reportWith(t, m5, func(_ map[string]any, metrics map[string]any) {
		metrics["average_precision"] = metric(0.25, 0.15, 0.35)
	})
	b.submit(t, m5, report5, http.StatusCreated, `"verdict":"pass"`)
	better := b.promote(t, m5, digest5, http.StatusCreated, `"outcome":"promoted"`)
	if better.Baseline == nil || better.Baseline.ModelVersion != "synthetic.3" || better.Baseline.EvaluationSHA256 != digest3 || b.activeVersion(t) != "synthetic.5" {
		t.Fatalf("improvement decision: %+v active=%q", better, b.activeVersion(t))
	}

	// The database refuses what the controller would not: an approval without a
	// passing evaluation, a promotion forged as promoted, and any change to a
	// stored evaluation or decision.
	if _, err := b.db.Exec(`INSERT INTO model_approvals (deployment_id, model_version, artifact_sha256, evaluation_sha256, policy_version, approved_at, actor_issuer, actor_subject)
		VALUES ($1,'synthetic.1',decode($2,'hex'),decode($3,'hex'),'ml05.v1',now(),'issuer','subject')`, b.repo.deploymentID, m1.ArtifactSHA256, poorDigest); err == nil {
		t.Fatal("database approved a model whose evaluation failed")
	}
	for _, statement := range []string{
		`UPDATE model_evaluations SET verdict='pass' WHERE model_version='synthetic.1'`,
		`DELETE FROM model_evaluations WHERE model_version='synthetic.1'`,
		`UPDATE model_promotions SET outcome='promoted', reasons='[]' WHERE model_version='synthetic.1'`,
		`DELETE FROM model_promotions WHERE model_version='synthetic.4'`,
	} {
		if _, err := b.db.Exec(statement); err == nil {
			t.Fatalf("database allowed %s", statement)
		}
	}

	// Restart: decisions and the active model are read back unchanged.
	restarted, err := NewPostgresRepository(context.Background(), b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	b.server = b.serve(t, restarted)
	var reread c.ModelPromotionV1
	if err := json.Unmarshal(b.expect(t, http.MethodGet, "/console/api/models/synthetic.4/promotion", nil, b.viewer, http.StatusOK, `"outcome":"rejected"`), &reread); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(reread.Reasons, regressed.Reasons) || b.activeVersion(t) != "synthetic.5" {
		t.Fatalf("restart changed decisions: %+v active=%q", reread, b.activeVersion(t))
	}
	report, err := restarted.EvaluationReport(context.Background(), digest5)
	if err != nil || !bytes.Equal(report, report5) {
		t.Fatalf("stored report for the health path: %v", err)
	}
	if _, err := restarted.EvaluationReport(context.Background(), strings.Repeat("a", 64)); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown report digest: %v", err)
	}
}

func TestModelPromotionCannotCompareWithAnUnevaluatedActiveModel(t *testing.T) {
	b := newRegistryBed(t)
	// An active model approved before FED10 has no stored evaluation, so a
	// candidate cannot be shown to be no worse and the active model stays.
	legacy := b.manifest(t, b.publisher, "synthetic.legacy", []byte("legacy"), c.ModelPurposeInference)
	b.expect(t, http.MethodPost, "/console/api/models", upload(legacy, []byte("legacy")), b.adminHeaders(), http.StatusCreated, "")
	approveWithoutEvaluationGate(t, b.repo, "synthetic.legacy", legacy.ArtifactSHA256, strings.Repeat("e", 64), health.ML05PolicyVersion)
	b.expect(t, http.MethodPut, "/console/api/model-references/active", c.ModelReferenceRequestV1{SchemaVersion: c.ModelReferenceRequestV1Version,
		ModelVersion: "synthetic.legacy", ArtifactSHA256: legacy.ArtifactSHA256}, b.adminHeaders(), http.StatusOK, "")

	m := b.stageCandidate(t, "synthetic.next")
	report, digest := passingReport(t, m)
	b.submit(t, m, report, http.StatusCreated, `"verdict":"pass"`)
	decision := b.promote(t, m, digest, http.StatusCreated, `"outcome":"rejected"`)
	if !slices.Equal(decision.Reasons, []string{"baseline_not_comparable"}) || b.activeVersion(t) != "synthetic.legacy" {
		t.Fatalf("decision %+v active=%q", decision, b.activeVersion(t))
	}
}

func TestModelPromotionConcurrentRequestsDecideOnce(t *testing.T) {
	b := newRegistryBed(t)
	m := b.stageCandidate(t, "synthetic.race")
	report, digest := passingReport(t, m)
	b.submit(t, m, report, http.StatusCreated, `"verdict":"pass"`)
	request := promotionRequestFor(m, digest)
	actor := c.ModelActorV1{Issuer: "console:local", Subject: "admin@example.com"}

	const callers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, failures := 0, 0
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, fresh, err := b.repo.PromoteModel(context.Background(), request, actor)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err != nil:
				failures++
			case fresh:
				created++
			}
		}()
	}
	wg.Wait()
	if created != 1 || failures != 0 || b.activeVersion(t) != "synthetic.race" {
		t.Fatalf("concurrent promotion created=%d failures=%d active=%q", created, failures, b.activeVersion(t))
	}
}
