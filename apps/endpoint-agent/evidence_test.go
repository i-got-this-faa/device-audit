package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// The CT04 golden payload with the device ID replaced by the admitted test device.
func testPayload(device string) []byte {
	return []byte(`{"schema_version":"device-audit.telemetry.v2","device_id":"` + device + `","collected_at":"2026-10-14T12:00:00Z","source":"fixture","metrics":{"cpu_utilization":{"value":0,"unit":"percent"},"gpu_utilization":{"value":null,"unit":"percent","missing_reason":"sensor_unavailable"}},"inventory":{"components":[{"id":"component:fixture","type":"cpu","model":"例"}]},"log_references":[]}`)
}

// admittedStore provisions the same files a successful enrollment commits,
// without a network peer. The caller owns closing the returned store.
func admittedStore(t *testing.T) (*identityStore, string, *identity, contracts.EnrollmentAcceptedV1) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	s, err := openIdentityStore(path, true)
	if err != nil {
		t.Fatal(err)
	}
	i, err := s.load(true)
	if err != nil {
		t.Fatal(err)
	}
	start := i.start("deployment:test", "device:test")
	scope, _ := json.Marshal(start)
	receipt := testAccepted(start)
	data, _ := json.Marshal(receipt)
	if s.write("scope.json", scope) != nil || s.initSequence(receipt) != nil || s.write(receiptFile, data) != nil {
		t.Fatal("write admitted identity fixture")
	}
	return s, path, i, receipt
}

func assertNoPrivateMaterial(t *testing.T, i *identity, data []byte) {
	t.Helper()
	for _, secret := range [][]byte{i.signing.Seed(), i.signing, i.network.Bytes()} {
		if bytes.Contains(data, []byte(hex.EncodeToString(secret))) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(secret))) || bytes.Contains(data, secret) {
			t.Fatal("private key material in endpoint output")
		}
	}
}

func verifyEnvelope(t *testing.T, i *identity, receipt contracts.EnrollmentAcceptedV1, data []byte) contracts.EvidenceEnvelopeV1 {
	t.Helper()
	var envelope contracts.EvidenceEnvelopeV1
	if err := json.Unmarshal(bytes.TrimSpace(data), &envelope); err != nil {
		t.Fatalf("decode signed evidence: %v", err)
	}
	if err := envelope.VerifySignature(i.signing.Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("signed evidence does not verify: %v", err)
	}
	if envelope.DeploymentID != receipt.DeploymentID || envelope.DeviceID != receipt.DeviceID || envelope.SigningKeyID != receipt.SigningKeyID {
		t.Fatal("evidence not bound to admitted identity")
	}
	assertNoPrivateMaterial(t, i, data)
	return envelope
}

func TestEvidenceSigningMonotonicAndBound(t *testing.T) {
	s, _, i, receipt := admittedStore(t)
	defer s.close()
	payload := testPayload(receipt.DeviceID)
	marker := "private-payload-marker"
	for _, invalid := range [][]byte{testPayload("other-device"), []byte(`{"` + marker + `":1}`), []byte("not json " + marker)} {
		if _, err := s.signEvidence(invalid, time.Now()); err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "other-device") {
			t.Fatal("invalid payload signed or echoed in error")
		}
	}
	for want := contracts.FirstEvidenceSequenceV1; want < contracts.FirstEvidenceSequenceV1+3; want++ {
		envelope, err := s.signEvidence(payload, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		// Rejected payloads above consumed no sequence.
		if envelope.Sequence != want {
			t.Fatalf("sequence %d, want %d", envelope.Sequence, want)
		}
		data, _ := json.Marshal(envelope)
		verifyEnvelope(t, i, receipt, data)
		decoded, _ := base64.StdEncoding.DecodeString(envelope.PayloadBase64)
		if !bytes.Equal(decoded, payload) {
			t.Fatal("payload was re-encoded before signing")
		}
	}
}

func TestEvidenceGoldenVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "packages", "contracts", "fixtures", "envelopes", "v1-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []struct {
			Name           string          `json:"name"`
			Envelope       json.RawMessage `json:"envelope"`
			SignatureValid bool            `json:"signature_valid"`
			CanonicalHex   string          `json:"canonical_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	// RFC 8032 section 7.1 TEST 1 seed: public test material, never operational.
	key := ed25519.NewKeyFromSeed(mustDecodeHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	public := key.Public().(ed25519.PublicKey)
	checked := map[string]bool{}
	for _, vector := range fixture.Vectors {
		switch vector.Name {
		case "valid offline evidence with nullable metric":
			var golden contracts.EvidenceEnvelopeV1
			if err := json.Unmarshal(vector.Envelope, &golden); err != nil {
				t.Fatal(err)
			}
			unsigned := golden
			unsigned.Signature = ""
			signed, err := signEvidenceEnvelope(key, unsigned)
			if err != nil {
				t.Fatal(err)
			}
			message, _ := signed.SigningBytes()
			if signed.Signature != golden.Signature || hex.EncodeToString(message) != vector.CanonicalHex {
				t.Fatal("endpoint signer diverges from CT04 golden canonical bytes or signature")
			}
			// Alter one payload byte and recompute the digest: the old signature must fail.
			payload, _ := base64.StdEncoding.DecodeString(golden.PayloadBase64)
			payload = bytes.Replace(payload, []byte(`"value":0`), []byte(`"value":1`), 1)
			altered := golden
			altered.PayloadBase64 = base64.StdEncoding.EncodeToString(payload)
			digest := sha256.Sum256(payload)
			altered.PayloadSHA256 = hex.EncodeToString(digest[:])
			if err := altered.VerifySignature(public); err == nil || err.Error() != contracts.EnvelopeRejectionInvalidSignature {
				t.Fatalf("altered payload verified: %v", err)
			}
			checked[vector.Name] = true
		case "altered payload stale digest", "altered payload recomputed digest":
			var altered contracts.EvidenceEnvelopeV1
			if json.Unmarshal(vector.Envelope, &altered) == nil && altered.VerifySignature(public) == nil {
				t.Fatalf("%s verified", vector.Name)
			}
			checked[vector.Name] = !vector.SignatureValid
		}
	}
	if len(checked) != 3 || !checked["altered payload stale digest"] || !checked["altered payload recomputed digest"] {
		t.Fatal("golden evidence vectors missing or changed classification")
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func evidenceProcess(path string, env ...string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestEvidenceProcess$")
	command.Env = append(append(os.Environ(), "DEVICE_AUDIT_TEST_EVIDENCE_DIR="+path), env...)
	return command
}

// TestEvidenceProcess is a fresh endpoint process for restart tests. A crash
// stage exits abruptly, without deferred cleanup, at that allocation point.
func TestEvidenceProcess(t *testing.T) {
	path := os.Getenv("DEVICE_AUDIT_TEST_EVIDENCE_DIR")
	if path == "" {
		return
	}
	if stage := os.Getenv("DEVICE_AUDIT_TEST_CRASH_STAGE"); stage != "" {
		sequenceStage = func(current string) {
			if current == stage {
				os.Exit(3)
			}
		}
	}
	if os.Getenv("DEVICE_AUDIT_TEST_EVIDENCE_LOOP") != "" {
		s, err := openIdentityStore(path, false)
		if err != nil {
			os.Exit(4)
		}
		for {
			envelope, err := s.signEvidence(testPayload("device:test"), time.Now())
			if err != nil {
				os.Exit(5)
			}
			data, _ := json.Marshal(envelope)
			os.Stdout.Write(append(data, '\n'))
		}
	}
	os.Args = []string{os.Args[0], "--sign-evidence", "--state-dir", path}
	main()
	os.Exit(0)
}

func TestEvidenceSequenceSurvivesForcedRestart(t *testing.T) {
	s, path, i, receipt := admittedStore(t)
	s.close()
	seen := map[uint64]bool{}
	var highest uint64
	record := func(envelope contracts.EvidenceEnvelopeV1) {
		t.Helper()
		if seen[envelope.Sequence] || envelope.Sequence <= highest {
			t.Fatalf("sequence %d reused or not monotonic after %d", envelope.Sequence, highest)
		}
		seen[envelope.Sequence] = true
		highest = envelope.Sequence
	}
	signFresh := func(crash string) (contracts.EvidenceEnvelopeV1, error) {
		t.Helper()
		var env []string
		if crash != "" {
			env = append(env, "DEVICE_AUDIT_TEST_CRASH_STAGE="+crash)
		}
		command := evidenceProcess(path, env...)
		command.Stdin = bytes.NewReader(testPayload(receipt.DeviceID))
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		assertNoPrivateMaterial(t, i, append(stdout.Bytes(), stderr.Bytes()...))
		if err != nil {
			if stdout.Len() != 0 {
				t.Fatal("crashed process released evidence")
			}
			return contracts.EvidenceEnvelopeV1{}, err
		}
		envelope := verifyEnvelope(t, i, receipt, stdout.Bytes())
		record(envelope)
		return envelope, nil
	}

	first, err := signFresh("")
	if err != nil || first.Sequence != contracts.FirstEvidenceSequenceV1 {
		t.Fatalf("fresh process signing failed: %v", err)
	}
	// Crash after the temporary write but before rename: that value was never
	// signed, so the next process may issue it.
	if _, err := signFresh("before-commit"); err == nil {
		t.Fatal("crash hook did not fire")
	}
	if next, err := signFresh(""); err != nil || next.Sequence != first.Sequence+1 {
		t.Fatalf("restart after uncommitted reservation: %v", err)
	}
	// Crash after the durable commit: the reserved value is skipped forever.
	previous := highest
	if _, err := signFresh("after-commit"); err == nil {
		t.Fatal("crash hook did not fire")
	}
	if next, err := signFresh(""); err != nil || next.Sequence != previous+2 {
		t.Fatalf("restart after committed reservation did not skip it: %v", err)
	}
	// Kill a signing loop at arbitrary points and resume in a fresh process.
	for round, target := range []int{1, 7, 23} {
		command := evidenceProcess(path, "DEVICE_AUDIT_TEST_EVIDENCE_LOOP=1")
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		lines := bufio.NewScanner(stdout)
		lines.Buffer(make([]byte, 0, 1<<20), 1<<20)
		for count := 0; count < target && lines.Scan(); count++ {
			record(verifyEnvelope(t, i, receipt, lines.Bytes()))
		}
		command.Process.Kill()
		// Envelopes already written before the kill are signed and count too.
		// Only a final line cut by the kill may be incomplete.
		var pending []byte
		for lines.Scan() {
			if pending != nil {
				record(verifyEnvelope(t, i, receipt, pending))
			}
			pending = bytes.Clone(lines.Bytes())
		}
		if pending != nil {
			var probe contracts.EvidenceEnvelopeV1
			if json.Unmarshal(pending, &probe) == nil {
				record(verifyEnvelope(t, i, receipt, pending))
			}
		}
		command.Wait()
		if _, err := signFresh(""); err != nil {
			t.Fatalf("round %d: resume after kill: %v", round, err)
		}
	}
	if len(seen) < 3+1+7+23+3 {
		t.Fatalf("only %d signed envelopes observed", len(seen))
	}
}

func TestEvidenceSequenceFailsClosed(t *testing.T) {
	for _, damage := range []string{"missing", "bitflip", "other-scope", "below-admission", "exhausted", "temp-directory", "unknown-field"} {
		t.Run(damage, func(t *testing.T) {
			s, _, i, receipt := admittedStore(t)
			defer s.close()
			state := sequenceState{SchemaVersion: sequenceStateVersion, DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID, LastReserved: 9}
			var data []byte
			switch damage {
			case "missing":
				if s.root.Remove(sequenceFile) != nil {
					t.Fatal("remove sequence fixture")
				}
			case "bitflip":
				data = encodeSequence(state)
				data[len(data)-3] ^= 1
			case "other-scope":
				state.DeviceID = "other-device"
				data = encodeSequence(state)
			case "below-admission":
				state.LastReserved = 0
				data = encodeSequence(state)
			case "exhausted":
				state.LastReserved = contracts.MaxEnvelopeSequence
				data = encodeSequence(state)
			case "temp-directory":
				if s.root.Mkdir(sequenceTempFile, 0700) != nil {
					t.Fatal("create temporary directory fixture")
				}
			case "unknown-field":
				body := []byte(`{"schema_version":"` + sequenceStateVersion + `","deployment_id":"deployment:test","device_id":"device:test","signing_key_id":"` + receipt.SigningKeyID + `","last_reserved":9,"reset":true}`)
				sum := sha256.Sum256(body)
				data = append(sum[:], body...)
			}
			if data != nil {
				if err := s.root.WriteFile(sequenceFile, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := s.read(sequenceFile)
			if _, err := s.signEvidence(testPayload(receipt.DeviceID), time.Now()); err == nil {
				t.Fatal("damaged sequence state signed evidence")
			} else {
				assertNoPrivateMaterial(t, i, []byte(err.Error()))
			}
			after, err := s.read(sequenceFile)
			if damage == "missing" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatal("missing sequence state was silently recreated")
				}
			} else if !bytes.Equal(before, after) {
				t.Fatal("damaged sequence state was repaired or reset")
			}
		})
	}
}
