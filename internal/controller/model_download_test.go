package controller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	c "github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestMeshApprovedModelDownloadPostgres(t *testing.T) {
	b := newRegistryBed(t)
	keys := newEnrollmentKeys(t)
	token := b.issue(t, "model-download-device")
	challenge := b.challenge(t, token, keys)
	admission := admissionForChallenge(t, b.clock, challenge, keys)
	b.enrollmentTestBed.submit(t, token, admission, http.StatusCreated)
	node := &meshTestNode{peer: hex.EncodeToString(keys.networkPublic[:])}
	server := newMeshTestServer(t, MeshConfig{Node: node, Repository: b.repo, ModelDownloads: b.repo})

	request := func(peer, path string, expected int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, peer))
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, r)
		if w.Code != expected || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s returned %d, want %d, response %q", path, w.Code, expected, w.Body.String())
		}
		return w
	}
	first := b.stageCandidate(t, "download.1")
	artifactPath := func(m c.ModelManifestV1) string { return c.ModelDownloadArtifactPrefixV1 + m.ArtifactSHA256 }
	request(node.peer, c.ModelDownloadMetadataPathV1, http.StatusNotFound)
	request(node.peer, artifactPath(first), http.StatusNotFound)

	report, digest := passingReport(t, first)
	b.submit(t, first, report, http.StatusCreated, "")
	b.promote(t, first, digest, http.StatusCreated, "promoted")
	w := request(node.peer, c.ModelDownloadMetadataPathV1, http.StatusOK)
	var metadata c.ModelDownloadV1
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil || metadata.Validate() != nil ||
		metadata.DeploymentID != token.DeploymentID || metadata.Manifest.ArtifactSHA256 != first.ArtifactSHA256 ||
		metadata.EvaluationSHA256 != digest {
		t.Fatalf("incorrect approval metadata: %+v, %v", metadata, err)
	}
	w = request(node.peer, artifactPath(first), http.StatusOK)
	if w.Body.String() != "synthetic model bytes "+first.ModelVersion ||
		w.Header().Get("Content-Length") != strconv.Itoa(metadata.ArtifactByteSize) ||
		w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("incorrect artifact response: %s, %v", w.Body.String(), w.Header())
	}
	request("", artifactPath(first), http.StatusForbidden)
	request(node.peer, c.ModelDownloadArtifactPrefixV1+"bad", http.StatusBadRequest)
	w = httptest.NewRecorder()
	b.handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, artifactPath(first), nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("mesh download exposed on regular controller API: %d", w.Code)
	}

	second := b.stageCandidate(t, "download.2")
	request(node.peer, artifactPath(second), http.StatusNotFound)
	report, secondDigest := passingReport(t, second)
	b.submit(t, second, report, http.StatusCreated, "")
	b.promote(t, second, secondDigest, http.StatusCreated, "promoted")
	request(node.peer, artifactPath(first), http.StatusNotFound)
	request(node.peer, artifactPath(second), http.StatusOK)

	if _, err := b.db.Exec("UPDATE device_enrollments SET revoked_at=now() WHERE deployment_id=$1 AND device_id=$2", token.DeploymentID, token.DeviceID); err != nil {
		t.Fatal(err)
	}
	request(node.peer, artifactPath(second), http.StatusForbidden)
	request(node.peer, c.ModelDownloadMetadataPathV1, http.StatusForbidden)
}
