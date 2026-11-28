package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func postRoundUpdate(t *testing.T, mesh *http.Server, device meshTestDevice, update contracts.FederatedUpdateV1, status int, reason string) {
	t.Helper()
	raw, err := json.Marshal(update)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/federated/updates", bytes.NewReader(raw))
	r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, device.peer))
	w := httptest.NewRecorder()
	mesh.Handler.ServeHTTP(w, r)
	var response federatedUpdateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("update response %d %q: %v", w.Code, w.Body.String(), err)
	}
	if w.Code != status || response.RejectionReason != reason {
		t.Fatalf("update response %d %+v, want HTTP %d with reason %q", w.Code, response, status, reason)
	}
	if status == http.StatusCreated && (response.Status != "accepted" || response.Sequence != update.Sequence) {
		t.Fatalf("wrong acceptance receipt: %+v", response)
	}
	if status >= 400 && response.Status != "rejected" {
		t.Fatalf("wrong rejection receipt: %+v", response)
	}
}

func TestFederatedRoundContainsRejectedUpdatesAndDropout(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:containment")
	round.Deadline = formatRoundTime(b.clock.Now().Add(time.Minute))
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}
	mesh := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: b.repo, Now: b.clock.Now})
	b.stageCandidate(t, "baseline.existing-candidate")
	before := b.references(t, b.server)
	good, missing := b.devices[0], b.devices[1]
	now := b.clock.Now()
	weights := []float64{1, 2, 3, 4, 5, 6}
	accepted := signFederatedUpdate(t, b.repo.deploymentID, good, round, 2, now, now.Add(time.Minute), weights, 12)
	postRoundUpdate(t, mesh, good, accepted, http.StatusCreated, "")

	valid := signFederatedUpdate(t, b.repo.deploymentID, missing, round, 2, now, now.Add(time.Minute), weights, 12)
	malformed := valid
	malformed.WeightsBase64 = "not base64"
	nonfinite := valid
	raw := encodeBinary64Weights([]float64{math.Inf(1), 2, 3, 4, 5, 6})
	nonfinite.WeightsBase64 = base64.StdEncoding.EncodeToString(raw)
	nonfinite.UpdateSHA256 = sha256DigestHex(raw)
	otherBase := b.storeModel(t, "baseline.incompatible", []string{contracts.ModelPurposeTraining})
	incompatible := round
	incompatible.BaseModelVersion, incompatible.BaseModelSHA256 = otherBase.ModelVersion, otherBase.ArtifactSHA256
	wrongBase := signFederatedUpdate(t, b.repo.deploymentID, missing, incompatible, 2, now, now.Add(time.Minute), weights, 12)

	for _, tc := range []struct {
		name   string
		update contracts.FederatedUpdateV1
		status int
		reason string
		err    error
	}{
		{"malformed encoding", malformed, http.StatusBadRequest, contracts.EnvelopeRejectionInvalidPayload, federated.ErrUpdateInvalid},
		{"nonfinite weight", nonfinite, http.StatusBadRequest, contracts.EnvelopeRejectionInvalidPayload, federated.ErrUpdateInvalid},
		{"incompatible registered base", wrongBase, http.StatusConflict, "incompatible_update", federated.ErrUpdateIncompatible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			postRoundUpdate(t, mesh, missing, tc.update, tc.status, tc.reason)
			if _, created, err := b.repo.AcceptUpdate(ctx, tc.update); created || !errors.Is(err, tc.err) {
				t.Fatalf("repository acceptance created=%v err=%v, want %v", created, err, tc.err)
			}
		})
	}
	if _, created, err := b.repo.AggregateRound(ctx, round.RoundID, b.publisher, b.actor); created || !errors.Is(err, federated.ErrRoundNotOpen) {
		t.Fatalf("aggregation before deadline created=%v err=%v", created, err)
	}

	// At the exact deadline a valid submission still cannot fill the missing slot.
	b.clock.Advance(time.Minute)
	postRoundUpdate(t, mesh, missing, valid, http.StatusConflict, contracts.EnvelopeRejectionExpired)
	closed, err := b.repo.Round(ctx, round.RoundID)
	if err != nil || closed.Status != federated.RoundClosed || len(closed.Transitions) != 2 ||
		closed.Transitions[1].Reason != "deadline" || len(closed.Accepted) != 1 || closed.Accepted[0].DeviceID != good.id {
		t.Fatalf("deadline closure = %+v, err=%v", closed, err)
	}
	updates, err := b.repo.AcceptedUpdates(ctx, round.RoundID)
	if err != nil || len(updates) != 1 || updates[0].UpdateSHA256 != accepted.UpdateSHA256 {
		t.Fatalf("accepted updates = %+v, err=%v", updates, err)
	}
	failed, created, err := b.repo.AggregateRound(ctx, round.RoundID, b.publisher, b.actor)
	if !created || !errors.Is(err, federated.ErrInsufficientParticipants) || failed.Status != federated.AggregationFailed ||
		failed.FailureReason != "insufficient_participants" || failed.TotalSamples != 12 ||
		len(failed.Participants) != 1 || failed.Participants[0].DeviceID != good.id {
		t.Fatalf("dropout aggregation = %+v, created=%v, err=%v", failed, created, err)
	}
	if _, err := b.repo.ModelArtifact(ctx, round.CandidateID); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("failed round candidate lookup: %v", err)
	}
	if after := b.references(t, b.server); !reflect.DeepEqual(after, before) {
		t.Fatalf("failed round changed model references: before=%+v, after=%+v", before, after)
	}

	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	retry, created, err := restarted.AggregateRound(ctx, round.RoundID, b.publisher, b.actor)
	if created || !errors.Is(err, federated.ErrInsufficientParticipants) || !reflect.DeepEqual(retry, failed) {
		t.Fatalf("aggregation retry = %+v, created=%v, err=%v", retry, created, err)
	}

	// Rejections must leave the signing sequence free for the next round.
	next := b.round("round:after-dropout")
	if _, _, err := restarted.OpenRound(ctx, next, b.actor); err != nil {
		t.Fatal(err)
	}
	nextUpdate := signFederatedUpdate(t, b.repo.deploymentID, missing, next, valid.Sequence, b.clock.Now(), b.clock.Now().Add(time.Hour), weights, 12)
	if _, created, err := restarted.AcceptUpdate(ctx, nextUpdate); !created || err != nil {
		t.Fatalf("next round reused unconsumed sequence: created=%v err=%v", created, err)
	}
}

func TestFederatedRoundRegressionCannotReachEndpointDownloads(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	artifact := loadBaselineModelBytes(t)
	base := buildSignedControllerManifest(t, b.publisher, artifact, health.ControllerInferenceRuntime())
	base.Purposes = []string{contracts.ModelPurposeInference, contracts.ModelPurposeTraining}
	signing, err := base.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	base.Signature = hex.EncodeToString(ed25519.Sign(b.publisher, signing))
	reference := func(m contracts.ModelManifestV1) contracts.ModelReferenceRequestV1 {
		return contracts.ModelReferenceRequestV1{SchemaVersion: contracts.ModelReferenceRequestV1Version,
			ModelVersion: m.ModelVersion, ArtifactSHA256: m.ArtifactSHA256}
	}
	b.expect(t, http.MethodPost, "/console/api/models", upload(base, artifact), b.adminHeaders(), http.StatusCreated, "")
	b.expect(t, http.MethodPut, "/console/api/model-references/candidate", reference(base), b.adminHeaders(), http.StatusOK, "")
	report, digest := passingReport(t, base)
	b.submit(t, base, report, http.StatusCreated, `"verdict":"pass"`)
	b.promote(t, base, digest, http.StatusCreated, `"outcome":"promoted"`)
	before := b.references(t, b.server)
	if before.Active == nil || before.Active.ArtifactSHA256 != base.ArtifactSHA256 {
		t.Fatalf("wrong active baseline: %+v", before)
	}

	round := b.round("round:regression")
	round.Deadline = formatRoundTime(b.clock.Now().Add(time.Minute))
	round.BaseModelVersion, round.BaseModelSHA256 = base.ModelVersion, base.ArtifactSHA256
	round.ParameterCount = base.ParameterCount
	round.Participants = append(round.Participants, contracts.FederatedParticipantV1{
		DeviceID: b.devices[2].id, SigningKeyID: b.devices[2].keyID, Eligibility: "eligible",
	})
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}
	mesh := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: b.repo, Now: b.clock.Now, ModelDownloads: b.repo})
	now := b.clock.Now()
	honest := signFederatedUpdate(t, b.repo.deploymentID, b.devices[0], round, 2, now, now.Add(time.Minute), make([]float64, 7), 100)
	extreme := signFederatedUpdate(t, b.repo.deploymentID, b.devices[1], round, 2, now, now.Add(time.Minute), []float64{1e6, 0, 0, 0, 0, 0, 0}, 900)
	postRoundUpdate(t, mesh, b.devices[0], honest, http.StatusCreated, "")
	postRoundUpdate(t, mesh, b.devices[1], extreme, http.StatusCreated, "")

	// The silent third participant does not prevent aggregation when quorum is met.
	b.clock.Advance(time.Minute)
	agg, created, err := b.repo.AggregateRound(ctx, round.RoundID, b.publisher, b.actor)
	if err != nil || !created || agg.Status != federated.AggregationSucceeded || len(agg.Participants) != 2 ||
		agg.TotalSamples != 1000 || !slices.Equal(agg.Weights, []float64{900000, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("finite extreme update aggregation = %+v, created=%v, err=%v", agg, created, err)
	}
	candidate, _, err := b.repo.ModelArtifactBytes(ctx, round.CandidateID)
	if err != nil || candidate.ArtifactSHA256 != agg.CandidateModelSHA256 {
		t.Fatalf("candidate = %+v, err=%v", candidate, err)
	}

	// Submit synthetic held-out metrics for the actual aggregated artifact.
	// The report passes ML05, but its average precision regresses against the active model.
	degraded, evaluationSHA := reportWith(t, candidate, func(_ map[string]any, metrics map[string]any) {
		metrics["average_precision"] = metric(0.19, 0.09, 0.29)
	})
	b.promote(t, candidate, evaluationSHA, http.StatusNotFound, "")
	b.submit(t, candidate, degraded, http.StatusCreated, `"verdict":"pass"`)
	b.expect(t, http.MethodPut, "/console/api/model-references/active", reference(candidate), b.adminHeaders(),
		http.StatusConflict, string(contracts.ModelRejectionNotApproved))
	decision := b.promote(t, candidate, evaluationSHA, http.StatusCreated, `"outcome":"rejected"`)
	if !slices.Equal(decision.Reasons, []string{"regression:active_average_precision"}) ||
		decision.Baseline == nil || decision.Baseline.ArtifactSHA256 != base.ArtifactSHA256 {
		t.Fatalf("unexpected promotion decision: %+v", decision)
	}
	b.expect(t, http.MethodPut, "/console/api/model-references/active", reference(candidate), b.adminHeaders(),
		http.StatusConflict, string(contracts.ModelRejectionNotApproved))
	if after := b.references(t, b.server); !reflect.DeepEqual(after, before) {
		t.Fatalf("rejected candidate changed model references: before=%+v, after=%+v", before, after)
	}

	for _, tc := range []struct {
		path   string
		status int
		body   []byte
	}{
		{contracts.ModelDownloadArtifactPrefixV1 + candidate.ArtifactSHA256, http.StatusNotFound, nil},
		{contracts.ModelDownloadArtifactPrefixV1 + base.ArtifactSHA256, http.StatusOK, artifact},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, b.devices[0].peer))
		w := httptest.NewRecorder()
		mesh.Handler.ServeHTTP(w, r)
		if w.Code != tc.status || (tc.body != nil && !bytes.Equal(w.Body.Bytes(), tc.body)) {
			t.Fatalf("download %s status=%d, want %d and matching artifact if approved", tc.path, w.Code, tc.status)
		}
	}
}
