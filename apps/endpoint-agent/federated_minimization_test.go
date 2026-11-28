package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
)

type trainingFixtureNode struct {
	mesh.Server
	peer string
}

func (n trainingFixtureNode) PeerKey(net.Addr) (string, error) { return n.peer, nil }

type trainingFixtureRepo struct {
	binding controller.DeviceNetworkBinding
	round   contracts.FederatedRoundV1
	now     time.Time
	updates []contracts.FederatedUpdateV1
}

func (r *trainingFixtureRepo) NetworkPeerBinding(context.Context, string) (controller.DeviceNetworkBinding, error) {
	return r.binding, nil
}

func (*trainingFixtureRepo) AcceptEvidence(context.Context, contracts.EvidenceEnvelopeV1) (time.Time, error) {
	return time.Time{}, errors.New("unexpected telemetry")
}

func (r *trainingFixtureRepo) AcceptUpdate(_ context.Context, update contracts.FederatedUpdateV1) (federated.AcceptedUpdate, bool, error) {
	r.updates = append(r.updates, update)
	if err := update.CheckRound(r.round, r.now); err != nil {
		return federated.AcceptedUpdate{}, false, federated.ErrUpdateIncompatible
	}
	return federated.AcceptedUpdate{
		RoundID: update.RoundID, CandidateID: update.CandidateID, DeviceID: update.DeviceID,
		Sequence: update.Sequence, AcceptedAt: r.now,
	}, true, nil
}

func TestFederatedTrainingDataMinimization(t *testing.T) {
	at := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return at }
	store, dir, identity, receipt := admittedStore(t)
	store.close()
	req, key, localRequest := budgetedTrainingFixture(t, at, receipt)
	report, err := stageFederatedTraining(t.Context(), dir, key, localRequest, trainingExecution{
		now:   clock,
		power: func() error { return nil },
		fit: func(ctx context.Context, key string, request []byte) ([]byte, inferenceUsage, error) {
			var result bytes.Buffer
			err := runLocalCandidate(ctx, key, bytes.NewReader(request), &result, clock)
			return result.Bytes(), inferenceUsage{}, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join(dir, report.PendingFile))
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	node := trainingFixtureNode{peer: "peer:training-fixture"}
	repo := &trainingFixtureRepo{
		binding: controller.DeviceNetworkBinding{
			NetworkPublicKey: node.peer, DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID,
			SigningKeyID: receipt.SigningKeyID, SigningPublicKey: identity.signing.Public().(ed25519.PublicKey),
		},
		round: req.Round,
		now:   at,
	}
	_, ackKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := controller.MeshHTTPServer(controller.MeshConfig{
		Node: node, Repository: repo, AcknowledgementKey: ackKey,
		Logger: slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Now:    clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	post := func(body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/federated/updates", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(server.ConnContext(req.Context(), conn))
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, req)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("federated response is missing no-store")
		}
		return response
	}

	// Inspect the exact staged bytes used as the HTTP body, independently of
	// the contract decoder, so an accidental new field fails this test.
	wire := requireTrainingJSONFields(t, payload, `schema_version deployment_id device_id signing_key_id sequence
		issued_at expires_at round_id base_model_version base_model_sha256 candidate_id feature_version
		sample_count weights_base64 update_sha256 signature`)
	assertNoPrivateMaterial(t, identity, payload)
	response := post(payload)
	if response.Code != http.StatusCreated || len(repo.updates) != 1 {
		t.Fatalf("valid training submission: HTTP %d, repository calls=%d", response.Code, len(repo.updates))
	}
	update := repo.updates[0]
	if update.SampleCount != uint32(len(req.Examples)) || update.SchemaVersion != contracts.FederatedUpdateV1Version {
		t.Fatal("accepted submission has unexpected schema or sample count")
	}
	requireTrainingJSONFields(t, response.Body.Bytes(), "status round_id candidate_id device_id sequence accepted_at created")
	if logs.Len() != 0 {
		t.Fatal("accepted training submission produced a controller log entry")
	}

	const rawLog = "private-training-log-canary"
	for _, tc := range []struct {
		field string
		value any
	}{
		{"examples", req.Examples},
		{"raw_log", rawLog},
	} {
		t.Run(tc.field, func(t *testing.T) {
			value, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			wire[tc.field] = value
			defer delete(wire, tc.field)
			augmented, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			logs.Reset()
			response := post(augmented)
			if response.Code != http.StatusBadRequest || len(repo.updates) != 1 {
				t.Fatalf("augmented training submission: HTTP %d, repository calls=%d", response.Code, len(repo.updates))
			}
			reply := requireTrainingJSONFields(t, response.Body.Bytes(), "status rejection_reason")
			log := requireTrainingJSONFields(t, logs.Bytes(), "time level msg event reason peer")
			if string(reply["status"]) != `"rejected"` ||
				string(reply["rejection_reason"]) != `"invalid_payload"` ||
				string(log["level"]) != `"WARN"` ||
				string(log["msg"]) != `"federated update rejected"` ||
				string(log["event"]) != `"federated_update_rejected"` ||
				string(log["reason"]) != string(reply["rejection_reason"]) ||
				string(log["peer"]) != `"peer:training-fixture"` {
				t.Fatal("response or log did not use the expected fixed rejection metadata")
			}
		})
	}
}

func requireTrainingJSONFields(t *testing.T, raw []byte, names string) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	expected := strings.Fields(names)
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("capture must contain a single JSON object: %v", err)
	}
	if len(fields) != len(expected) {
		t.Fatalf("capture has %d fields, expected %d", len(fields), len(expected))
	}
	for _, name := range expected {
		if _, ok := fields[name]; !ok {
			t.Errorf("capture missing declared field %s", name)
		}
	}
	return fields
}
