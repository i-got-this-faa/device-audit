package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	c "github.com/i-got-this-faa/device-audit/packages/contracts"
)

// FED07 #112 at the console HTTP boundary with real PostgreSQL and sessions.

type registryBed struct {
	*enrollmentTestBed
	publisher ed25519.PrivateKey
	server    *httptest.Server
	viewer    map[string]string
	staleAdm  map[string]string
}

func newRegistryBed(t *testing.T) *registryBed {
	t.Helper()
	b := &registryBed{enrollmentTestBed: newEnrollmentTestBed(t), publisher: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))}
	b.server = b.serve(t, b.repo)
	session, csrf := b.addSession(t, "viewer:test", auth.RoleViewer, 0)
	b.viewer = map[string]string{"Cookie": "__Host-device-audit-session=" + session, "Origin": "https://console.example.test", "X-CSRF-Token": csrf}
	session, csrf = b.addSession(t, "admin:stale", auth.RoleAdmin, time.Hour)
	b.staleAdm = map[string]string{"Cookie": "__Host-device-audit-session=" + session, "Origin": "https://console.example.test", "X-CSRF-Token": csrf}
	return b
}

// serve starts a controller API over repo, as a controller restart would.
func (b *registryBed) serve(t *testing.T, repo *PostgresRepository) *httptest.Server {
	t.Helper()
	service, err := NewModelRegistryService(repo, b.admin, b.publisher.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(NewAPI(Config{MaxDevices: 1, Auth: b.admin, ModelRegistry: service}).Handler())
	t.Cleanup(server.Close)
	return server
}

// manifest signs a manifest for artifact with key.
func (b *registryBed) manifest(t *testing.T, key ed25519.PrivateKey, version string, artifact []byte, purposes ...string) c.ModelManifestV1 {
	t.Helper()
	features, _, err := c.FeatureNamesV1(c.FeatureVersionHDDSMART7DV1)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := c.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifact)
	m := c.ModelManifestV1{SchemaVersion: c.ModelManifestV1Version, ModelVersion: version, ArtifactSHA256: hex.EncodeToString(sum[:]),
		Architecture: "synthetic.v1", ParameterCount: 6, RuntimeName: "device-audit-runtime", RuntimeVersion: "1.0.0",
		FeatureVersion: c.FeatureVersionHDDSMART7DV1, Features: features, Purposes: purposes, SigningKeyID: keyID}
	message, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	return m
}

func upload(m c.ModelManifestV1, artifact []byte) c.ModelArtifactUploadV1 {
	return c.ModelArtifactUploadV1{SchemaVersion: c.ModelArtifactUploadV1Version, Manifest: m, Artifact: artifact, SourceReference: "training-run:synthetic"}
}

func (b *registryBed) call(t *testing.T, server *httptest.Server, method, path string, body any, headers map[string]string) (int, []byte, http.Header) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data, response.Header
}

func (b *registryBed) expect(t *testing.T, method, path string, body any, headers map[string]string, status int, contains string) []byte {
	t.Helper()
	got, data, _ := b.call(t, b.server, method, path, body, headers)
	if got != status || !strings.Contains(string(data), contains) {
		t.Fatalf("%s %s = %d %q, want %d containing %q", method, path, got, data, status, contains)
	}
	return data
}

func (b *registryBed) references(t *testing.T, server *httptest.Server) c.ModelReferencesV1 {
	t.Helper()
	status, data, _ := b.call(t, server, http.MethodGet, "/console/api/model-references", nil, b.viewer)
	var refs c.ModelReferencesV1
	if status != http.StatusOK || json.Unmarshal(data, &refs) != nil {
		t.Fatalf("references = %d %s", status, data)
	}
	return refs
}

func (b *registryBed) storedArtifacts(t *testing.T) int {
	t.Helper()
	var count int
	if err := b.db.QueryRow(`SELECT count(*) FROM model_artifacts`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestModelRegistryRejectsUnauthorizedAndTamperedArtifacts(t *testing.T) {
	b := newRegistryBed(t)
	artifact := []byte("synthetic model bytes v1")
	valid := b.manifest(t, b.publisher, "synthetic.1", artifact, c.ModelPurposeInference, c.ModelPurposeTraining)

	// Unauthorized callers and untrusted publishers store nothing.
	b.expect(t, http.MethodPost, "/console/api/models", upload(valid, artifact), nil, http.StatusUnauthorized, "")
	b.expect(t, http.MethodPost, "/console/api/models", upload(valid, artifact), b.viewer, http.StatusForbidden, "")
	b.expect(t, http.MethodPost, "/console/api/models", upload(valid, artifact), b.staleAdm, http.StatusForbidden, "")
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	b.expect(t, http.MethodPost, "/console/api/models", upload(b.manifest(t, other, "synthetic.1", artifact, c.ModelPurposeInference), artifact), b.adminHeaders(), http.StatusForbidden, string(c.ModelRejectionKeyMismatch))

	// Tampering with either the bytes or a signed field is refused.
	b.expect(t, http.MethodPost, "/console/api/models", upload(valid, []byte("synthetic model bytes v2")), b.adminHeaders(), http.StatusUnprocessableEntity, string(c.ModelRejectionDigestMismatch))
	changed := valid
	changed.RuntimeVersion = "2.0.0"
	b.expect(t, http.MethodPost, "/console/api/models", upload(changed, artifact), b.adminHeaders(), http.StatusForbidden, string(c.ModelRejectionInvalidSignature))
	b.expect(t, http.MethodPost, "/console/api/models", upload(valid, nil), b.adminHeaders(), http.StatusBadRequest, string(c.ModelRejectionInvalidRequest))
	if n := b.storedArtifacts(t); n != 0 {
		t.Fatalf("%d artifacts stored by refused uploads", n)
	}

	// A valid upload is stored once with its provenance; a repeat is not a new entry.
	var record c.ModelArtifactV1
	if err := json.Unmarshal(b.expect(t, http.MethodPost, "/console/api/models", upload(valid, artifact), b.adminHeaders(), http.StatusCreated, ""), &record); err != nil {
		t.Fatal(err)
	}
	if record.Manifest.ArtifactSHA256 != valid.ArtifactSHA256 || record.ArtifactByteSize != len(artifact) || record.SourceReference != "training-run:synthetic" ||
		record.UploadedBy.Subject != "admin:test" || record.Approval != nil || record.Manifest.RuntimeName != "device-audit-runtime" {
		t.Fatalf("record %+v", record)
	}
	b.expect(t, http.MethodPost, "/console/api/models", upload(valid, artifact), b.adminHeaders(), http.StatusOK, valid.ArtifactSHA256)

	// The same version with other bytes, or the same bytes as another version, conflicts.
	newer := []byte("synthetic model bytes v2")
	b.expect(t, http.MethodPost, "/console/api/models", upload(b.manifest(t, b.publisher, "synthetic.1", newer, c.ModelPurposeInference), newer), b.adminHeaders(), http.StatusConflict, string(c.ModelRejectionVersionConflict))
	b.expect(t, http.MethodPost, "/console/api/models", upload(b.manifest(t, b.publisher, "synthetic.renamed", artifact, c.ModelPurposeInference), artifact), b.adminHeaders(), http.StatusConflict, string(c.ModelRejectionVersionConflict))
	if n := b.storedArtifacts(t); n != 1 {
		t.Fatalf("%d artifacts stored, want 1", n)
	}

	// Bytes need an administrator; metadata needs a viewer.
	b.expect(t, http.MethodGet, "/console/api/models/synthetic.1/artifact", nil, b.viewer, http.StatusForbidden, "")
	b.expect(t, http.MethodGet, "/console/api/models/synthetic.1", nil, nil, http.StatusUnauthorized, "")
	b.expect(t, http.MethodGet, "/console/api/models/synthetic.1", nil, b.viewer, http.StatusOK, valid.Signature)
	status, data, header := b.call(t, b.server, http.MethodGet, "/console/api/models/synthetic.1/artifact", nil, b.adminHeaders())
	sum := sha256.Sum256(artifact)
	if status != http.StatusOK || !bytes.Equal(data, artifact) || header.Get("Repr-Digest") != "sha-256=:"+base64.StdEncoding.EncodeToString(sum[:])+":" {
		t.Fatalf("download = %d %q %v", status, data, header)
	}
	b.expect(t, http.MethodGet, "/console/api/models/synthetic.missing/artifact", nil, b.adminHeaders(), http.StatusNotFound, "")

	// Stored rows cannot be rewritten, and bytes changed at rest are never served.
	if _, err := b.db.Exec(`UPDATE model_artifacts SET artifact='\x00'::bytea`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("artifact update: %v", err)
	}
	if _, err := b.db.Exec(`DELETE FROM model_artifacts`); err == nil {
		t.Fatal("artifact delete was allowed")
	}
	if _, err := b.db.Exec(`ALTER TABLE model_artifacts DISABLE TRIGGER model_artifacts_immutable;
		UPDATE model_artifacts SET artifact='tampered'::bytea;
		ALTER TABLE model_artifacts ENABLE TRIGGER model_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	b.expect(t, http.MethodGet, "/console/api/models/synthetic.1/artifact", nil, b.adminHeaders(), http.StatusInternalServerError, "digest check")
}

func TestModelRegistryNeverActivatesAnUnapprovedCandidate(t *testing.T) {
	b := newRegistryBed(t)
	artifact := []byte("synthetic model bytes v1")
	m := b.manifest(t, b.publisher, "synthetic.1", artifact, c.ModelPurposeInference, c.ModelPurposeTraining)
	b.expect(t, http.MethodPost, "/console/api/models", upload(m, artifact), b.adminHeaders(), http.StatusCreated, "")
	ref := c.ModelReferenceRequestV1{SchemaVersion: c.ModelReferenceRequestV1Version, ModelVersion: "synthetic.1", ArtifactSHA256: m.ArtifactSHA256}

	if refs := b.references(t, b.server); refs.Active != nil || refs.Candidate != nil {
		t.Fatalf("empty registry has references: %+v", refs)
	}
	b.expect(t, http.MethodPut, "/console/api/model-references/candidate", ref, b.viewer, http.StatusForbidden, "")
	b.expect(t, http.MethodPut, "/console/api/model-references/candidate", ref, b.adminHeaders(), http.StatusOK, `"candidate":{"model_version":"synthetic.1"`)
	b.expect(t, http.MethodPut, "/console/api/model-references/active", ref, b.adminHeaders(), http.StatusConflict, string(c.ModelRejectionNotApproved))
	b.expect(t, http.MethodPut, "/console/api/model-references/retired", ref, b.adminHeaders(), http.StatusBadRequest, "")
	if refs := b.references(t, b.server); refs.Active != nil || refs.Candidate == nil {
		t.Fatalf("refused activation changed references: %+v", refs)
	}

	// The database refuses an unapproved active reference even if the controller asked.
	if _, err := b.db.Exec(`INSERT INTO model_references (deployment_id, slot, model_version, artifact_sha256, set_at, actor_issuer, actor_subject)
		VALUES ($1,'active','synthetic.1',decode($2,'hex'),now(),'issuer','subject')`, b.repo.deploymentID, m.ArtifactSHA256); err == nil {
		t.Fatal("database stored an unapproved active model")
	}

	// No route approves a model: the old approval endpoint is gone, and only a
	// promotion from a passing held-out evaluation can activate a candidate.
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.1/approval", map[string]string{}, b.adminHeaders(), http.StatusNotFound, "")
	report, digest := buildPassingML05Report(t, m, 0.0, 2.0)
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.1/evaluation", b.evaluation(t, m, report), b.adminHeaders(), http.StatusCreated, `"verdict":"pass"`)
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.1/promotion", promotionRequestFor(m, digest), b.adminHeaders(), http.StatusCreated, `"outcome":"promoted"`)
	if refs := b.references(t, b.server); refs.Active == nil || refs.Active.ModelVersion != "synthetic.1" || refs.Candidate != nil {
		t.Fatalf("promotion did not activate the candidate and clear its slot: %+v", refs)
	}

	// A training-only base can be evaluated but never becomes the inference model.
	trainOnly := []byte("synthetic training base")
	tm := b.manifest(t, b.publisher, "synthetic.base", trainOnly, c.ModelPurposeTraining)
	b.expect(t, http.MethodPost, "/console/api/models", upload(tm, trainOnly), b.adminHeaders(), http.StatusCreated, "")
	b.expect(t, http.MethodPut, "/console/api/model-references/candidate", c.ModelReferenceRequestV1{SchemaVersion: c.ModelReferenceRequestV1Version,
		ModelVersion: "synthetic.base", ArtifactSHA256: tm.ArtifactSHA256}, b.adminHeaders(), http.StatusOK, "")
	baseReport, baseDigest := buildPassingML05Report(t, tm, 0.0, 2.0)
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.base/evaluation", b.evaluation(t, tm, baseReport), b.adminHeaders(), http.StatusCreated, `"verdict":"pass"`)
	b.expect(t, http.MethodPost, "/console/api/models/synthetic.base/promotion", promotionRequestFor(tm, baseDigest), b.adminHeaders(), http.StatusCreated, `"reasons":["purpose_unsupported"]`)
	b.expect(t, http.MethodPut, "/console/api/model-references/active", c.ModelReferenceRequestV1{SchemaVersion: c.ModelReferenceRequestV1Version,
		ModelVersion: "synthetic.base", ArtifactSHA256: tm.ArtifactSHA256}, b.adminHeaders(), http.StatusConflict, string(c.ModelRejectionNotApproved))

	// A new unapproved candidate, then a restart: a new repository and server
	// over the same database keep both references and still refuse activation.
	next := []byte("synthetic model bytes v2")
	nm := b.manifest(t, b.publisher, "synthetic.2", next, c.ModelPurposeInference)
	b.expect(t, http.MethodPost, "/console/api/models", upload(nm, next), b.adminHeaders(), http.StatusCreated, "")
	nextRef := c.ModelReferenceRequestV1{SchemaVersion: c.ModelReferenceRequestV1Version, ModelVersion: "synthetic.2", ArtifactSHA256: nm.ArtifactSHA256}
	b.expect(t, http.MethodPut, "/console/api/model-references/candidate", nextRef, b.adminHeaders(), http.StatusOK, "")
	before := b.references(t, b.server)

	restarted, err := NewPostgresRepository(context.Background(), b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	b.server = b.serve(t, restarted)
	after := b.references(t, b.server)
	if after.Active == nil || after.Candidate == nil || *after.Active != *before.Active || *after.Candidate != *before.Candidate ||
		after.Active.ModelVersion != "synthetic.1" || after.Candidate.ModelVersion != "synthetic.2" {
		t.Fatalf("restart changed references: before %+v after %+v", before, after)
	}
	b.expect(t, http.MethodPut, "/console/api/model-references/active", nextRef, b.adminHeaders(), http.StatusConflict, string(c.ModelRejectionNotApproved))
	if refs := b.references(t, b.server); refs.Active.ModelVersion != "synthetic.1" {
		t.Fatalf("unapproved candidate became active: %+v", refs)
	}
}
