package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestDownloadAndStageApprovedModel(t *testing.T) {
	active, manifest, publisher, report := testInferenceBundle(t)
	pinInferenceReport(t, &active, passingInferenceFixture(t, report))
	wantActive, err := infer(active)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := os.ReadFile(active.Config.ArtifactFile)
	if err != nil {
		t.Fatal(err)
	}
	store, _, _, receipt := admittedStore(t)
	defer store.close()

	// The staged model is a distinct version with its own signed bytes.
	artifact = bytes.ReplaceAll(artifact, []byte(manifest.ModelVersion), []byte("registry.1"))
	manifest.ModelVersion = "registry.1"
	sign := func(m *contracts.ModelManifestV1, data []byte) {
		sum := sha256.Sum256(data)
		m.ArtifactSHA256 = hex.EncodeToString(sum[:])
		message, err := m.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		m.Signature = hex.EncodeToString(ed25519.Sign(publisher, message))
	}
	sign(&manifest, artifact)
	metadata := contracts.ModelDownloadV1{
		SchemaVersion: contracts.ModelDownloadV1Version, DeploymentID: receipt.DeploymentID,
		Manifest: manifest, ArtifactByteSize: len(artifact), EvaluationSHA256: strings.Repeat("a", 64),
	}
	public := publisher.Public().(ed25519.PublicKey)

	run := func(t *testing.T, m contracts.ModelDownloadV1, data []byte, metadataCode, artifactCode int, wantFetch bool) error {
		t.Helper()
		var fetched atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case contracts.ModelDownloadMetadataPathV1:
				w.WriteHeader(metadataCode)
				if metadataCode == http.StatusOK {
					_ = json.NewEncoder(w).Encode(m)
				}
			case contracts.ModelDownloadArtifactPrefixV1 + m.Manifest.ArtifactSHA256:
				fetched.Add(1)
				if artifactCode == http.StatusOK {
					w.Header().Set("Content-Length", strconv.Itoa(m.ArtifactByteSize))
				}
				w.WriteHeader(artifactCode)
				_, _ = w.Write(data)
			default:
				http.NotFound(w, r)
			}
		}))
		defer srv.Close()
		transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}}
		defer transport.CloseIdleConnections()
		_, err := downloadAndStageModel(t.Context(), &http.Client{Transport: transport}, public, receipt.DeploymentID, store)
		expected := int32(0)
		if wantFetch {
			expected = 1
		}
		if fetched.Load() != expected {
			t.Fatalf("artifact requested %d times, want %d (error %v)", fetched.Load(), expected, err)
		}
		return err
	}

	if err := run(t, metadata, artifact[:len(artifact)/2], 200, 200, true); err == nil {
		t.Fatal("staged an interrupted download")
	}
	if _, err := store.root.Stat(stagedModelFile); !os.IsNotExist(err) {
		t.Fatalf("first failure published staging: %v", err)
	}
	// Simulate a stale private temporary file from an interrupted local write.
	if err := store.write(stagedModelFile+".tmp", []byte("uncommitted")); err != nil {
		t.Fatal(err)
	}
	if err := run(t, metadata, artifact, 200, 200, true); err != nil {
		t.Fatal(err)
	}
	committed, err := store.root.ReadFile(stagedModelFile)
	if err != nil {
		t.Fatal(err)
	}
	var staged stagedModel
	if err := json.Unmarshal(committed, &staged); err != nil || !bytes.Equal(staged.Artifact, artifact) ||
		staged.Metadata.Manifest.ArtifactSHA256 != manifest.ArtifactSHA256 || staged.Metadata.EvaluationSHA256 != metadata.EvaluationSHA256 {
		t.Fatalf("incorrect staged bundle: %v", err)
	}

	for _, tc := range []struct {
		name                       string
		metadataCode, artifactCode int
		wantFetch                  bool
		change                     func(*contracts.ModelDownloadV1, []byte) []byte
	}{
		{"peer denied", 403, 200, false, nil},
		{"no approved model", 404, 200, false, nil},
		{"active changed", 200, 404, true, nil},
		{"revoked after metadata", 200, 403, true, nil},
		{"wrong deployment", 200, 200, false, func(m *contracts.ModelDownloadV1, b []byte) []byte { m.DeploymentID = "other"; return b }},
		{"missing approval digest", 200, 200, false, func(m *contracts.ModelDownloadV1, b []byte) []byte { m.EvaluationSHA256 = ""; return b }},
		{"oversize metadata claim", 200, 200, false, func(m *contracts.ModelDownloadV1, b []byte) []byte {
			m.ArtifactByteSize = contracts.ModelArtifactMaxBytesV1 + 1
			return b
		}},
		{"bad signature", 200, 200, false, func(m *contracts.ModelDownloadV1, b []byte) []byte {
			m.Manifest.Signature = strings.Repeat("a", 128)
			return b
		}},
		{"incompatible runtime", 200, 200, false, func(m *contracts.ModelDownloadV1, b []byte) []byte {
			m.Manifest.RuntimeVersion = "2.0.0"
			sign(&m.Manifest, b)
			return b
		}},
		{"incompatible feature order", 200, 200, false, func(m *contracts.ModelDownloadV1, b []byte) []byte {
			m.Manifest.Features[0], m.Manifest.Features[1] = m.Manifest.Features[1], m.Manifest.Features[0]
			sign(&m.Manifest, b)
			return b
		}},
		{"tampered bytes", 200, 200, true, func(_ *contracts.ModelDownloadV1, b []byte) []byte { b[0] ^= 1; return b }},
		{"invalid signed payload", 200, 200, true, func(m *contracts.ModelDownloadV1, b []byte) []byte { b[0] ^= 1; sign(&m.Manifest, b); return b }},
		{"truncated transfer", 200, 200, true, func(_ *contracts.ModelDownloadV1, b []byte) []byte { return b[:len(b)/2] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, b := metadata, bytes.Clone(artifact)
			m.Manifest.Features = append([]string(nil), m.Manifest.Features...)
			if tc.change != nil {
				b = tc.change(&m, b)
			}
			if err := run(t, m, b, tc.metadataCode, tc.artifactCode, tc.wantFetch); err == nil {
				t.Fatal("invalid transfer succeeded")
			}
			after, err := store.root.ReadFile(stagedModelFile)
			if err != nil || !bytes.Equal(after, committed) {
				t.Fatalf("failed download changed verified staging: %v", err)
			}
			if _, err := store.root.Stat(stagedModelFile + ".tmp"); !os.IsNotExist(err) {
				t.Fatalf("failed download left partial staging: %v", err)
			}
			actual, err := infer(active)
			if err != nil || actual.Model == nil || *actual.Model != *wantActive.Model || *actual.Health.Probability != *wantActive.Health.Probability {
				t.Fatalf("failed download changed active inference: %+v, %v", actual, err)
			}
		})
	}
}
