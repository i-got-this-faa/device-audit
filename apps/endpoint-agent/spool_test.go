package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func spoolTestAck(t *testing.T, key ed25519.PrivateKey, e contracts.EvidenceEnvelopeV1) contracts.AcknowledgementV1 {
	t.Helper()
	signing, err := e.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := contracts.EnvelopeRequestSHA256V1(signing, e.Signature)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := contracts.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	a := contracts.AcknowledgementV1{
		SchemaVersion: contracts.AcknowledgementV1Version, DeploymentID: e.DeploymentID, DeviceID: e.DeviceID,
		ControllerKeyID: keyID, RequestSchemaVersion: e.SchemaVersion, RequestKeyID: e.SigningKeyID,
		RequestSequence: e.Sequence, RequestSHA256: digest, ReceivedAt: e.IssuedAt, Status: "accepted", LastSequence: &e.Sequence,
	}
	msg, err := a.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(key, msg))
	return a
}

func TestSpoolProcessRecovery(t *testing.T) {
	for _, stage := range []string{"append-staged", "append-committed", "dequeue-staged", "dequeue-committed"} {
		t.Run(stage, func(t *testing.T) {
			store, stateDir, i, receipt := admittedStore(t)
			dir := testServiceConfig(t, stateDir).EvidenceDir
			public := i.signing.Public().(ed25519.PublicKey)
			first, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			third, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			store.close()
			s, err := openEvidenceSpool(dir, minEvidenceCap, 3, public, receipt)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.append(first); err != nil {
				t.Fatal(err)
			}
			before, _, err := s.head()
			if err != nil {
				t.Fatal(err)
			}
			s.close()

			controller, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			input, _ := json.Marshal(spoolCrashInput{dir, stage, public, controller, receipt, second, spoolTestAck(t, private, first)})
			cmd := exec.Command(os.Args[0], "-test.run=^TestSpoolCrashProcess$")
			cmd.Env = append(os.Environ(), "DEVICE_AUDIT_TEST_SPOOL_CRASH=1")
			cmd.Stdin = bytes.NewReader(input)
			if out, err := cmd.CombinedOutput(); cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 88 {
				t.Fatalf("child did not exit at commit boundary: %v %s", err, out)
			}
			s, err = openEvidenceSpool(dir, minEvidenceCap, 3, public, receipt)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			switch stage {
			case "append-committed":
				if len(s.queue) != 2 {
					t.Fatal("committed append was lost")
				}
				if err := s.append(second); err == nil {
					t.Fatal("duplicate sequence accepted")
				}
				if err := s.append(third); err != nil {
					t.Fatalf("next sequence rejected after duplicate: %v", err)
				}
			case "dequeue-committed":
				if _, _, err := s.head(); !errors.Is(err, io.EOF) || s.acknowledged != first.Sequence {
					t.Fatal("dequeue commit was lost")
				}
				data, err := os.ReadFile(filepath.Join(dir, spoolRetired))
				if err != nil || !bytes.Equal(data, before) {
					t.Fatal("retirement changed signed bytes")
				}
				return
			default:
				if len(s.queue) != 1 || s.acknowledged != 0 {
					t.Fatal("uncommitted operation affected the queue")
				}
			}
			after, _, err := s.head()
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("recovery changed signed bytes")
			}
		})
	}
}

type spoolCrashInput struct {
	Dir, Stage         string
	Public, Controller ed25519.PublicKey
	Receipt            contracts.EnrollmentAcceptedV1
	Envelope           contracts.EvidenceEnvelopeV1
	Ack                contracts.AcknowledgementV1
}

func TestSpoolCrashProcess(t *testing.T) {
	if os.Getenv("DEVICE_AUDIT_TEST_SPOOL_CRASH") != "1" {
		return
	}
	var input spoolCrashInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		t.Fatal(err)
	}
	s, err := openEvidenceSpool(input.Dir, minEvidenceCap, 2, input.Public, input.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	spoolStage = func(stage string) {
		if stage == input.Stage {
			os.Exit(88)
		}
	}
	if input.Stage == "append-staged" || input.Stage == "append-committed" {
		err = s.append(input.Envelope)
	} else {
		err = s.acknowledge(input.Controller, input.Ack)
	}
	t.Fatalf("did not reach commit fault: %v", err)
}

func TestSpoolRetentionAndCorruption(t *testing.T) {
	store, stateDir, i, receipt := admittedStore(t)
	defer store.close()
	dir := testServiceConfig(t, stateDir).EvidenceDir
	public := i.signing.Public().(ed25519.PublicKey)
	first, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(first)
	legacy = append(append([]byte(" "), legacy...), '\n')
	if err := os.WriteFile(filepath.Join(dir, evidenceLogFile), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openEvidenceSpool(dir, minEvidenceCap, 1, public, receipt)
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := s.head()
	if err != nil || !bytes.Equal(data, legacy) {
		t.Fatal("migration changed the legacy bytes")
	}
	if err := s.append(second); !errors.Is(err, errEvidenceFull) {
		t.Fatalf("record cap: %v", err)
	}
	s.maxRecords = 2
	s.maxBytes = s.size
	if err := s.append(second); !errors.Is(err, errEvidenceFull) {
		t.Fatalf("byte cap: %v", err)
	}
	controller, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.acknowledge(controller, spoolTestAck(t, private, second)); err == nil {
		t.Fatal("accepted acknowledgement for a different sequence")
	}
	path := filepath.Join(dir, recordName(first.Sequence))
	if err := os.WriteFile(path, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.acknowledge(controller, spoolTestAck(t, private, first)); err == nil || s.acknowledged != 0 {
		t.Fatal("corrupt record was acknowledged")
	}
	s.close()
	if s, err := openEvidenceSpool(dir, minEvidenceCap, 1, public, receipt); err == nil {
		s.close()
		t.Fatal("corruption hidden on restart")
	}
}

func TestSpoolCommandAcknowledgesOnlyVerifiedHead(t *testing.T) {
	store, stateDir, i, receipt := admittedStore(t)
	cfg := testServiceConfig(t, stateDir)
	configPath := filepath.Join(t.TempDir(), "service.json")
	writeJSON(t, configPath, cfg)
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "ack.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, i.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		t.Fatal(err)
	}
	envelopes := make([]contracts.EvidenceEnvelopeV1, 2)
	for index := range envelopes {
		e, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		envelopes[index] = e
		if err := spool.append(e); err != nil {
			t.Fatal(err)
		}
	}
	spool.close()
	store.close()
	for _, e := range envelopes {
		var out bytes.Buffer
		if err := runSpoolCommand(configPath, "", spoolShowHead, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		expected, _ := json.Marshal(e)
		if !bytes.Equal(out.Bytes(), append(expected, '\n')) {
			t.Fatal("spool command changed original bytes or order")
		}
		ack, _ := json.Marshal(spoolTestAck(t, key, e))
		if err := runSpoolCommand(configPath, keyPath, spoolAcceptHead, bytes.NewReader(ack), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if err := runSpoolCommand(configPath, "", spoolShowHead, nil, io.Discard, io.Discard); !errors.Is(err, errEmptySpool) {
		t.Fatal("retired record was redelivered")
	}
}

func TestSpoolLegacyBatchArchiveAndSession(t *testing.T) {
	store, stateDir, i, receipt := admittedStore(t)
	dir := testServiceConfig(t, stateDir).EvidenceDir
	public := i.signing.Public().(ed25519.PublicKey)
	now := time.Now()
	var envelopes []contracts.EvidenceEnvelopeV1
	var lines [][]byte
	for _, when := range []time.Time{now.Add(-2 * time.Hour), now, now} {
		env, err := store.signEvidence(testPayload(receipt.DeviceID), when)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(env)
		envelopes = append(envelopes, env)
		lines = append(lines, append(raw, '\n'))
	}
	store.close()
	torn := []byte("{\"sequence\":")
	original := append(bytes.Join(lines, nil), torn...)
	if err := os.WriteFile(filepath.Join(dir, evidenceLogFile), original, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openEvidenceSpool(dir, minEvidenceCap, 1, public, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !s.legacyMore || len(s.queue) != 1 {
		t.Fatal("initial migration did not respect the batch cap")
	}
	name, err := s.archiveExpired(now)
	if err != nil || s.acknowledged != 0 {
		t.Fatalf("archive wrongly acknowledged evidence: %v", err)
	}
	s.close()
	archived, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || !bytes.Equal(archived, lines[0]) {
		t.Fatal("archiving changed the original bytes")
	}

	s, err = openEvidenceSpool(dir, minEvidenceCap, 1, public, receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if s.acknowledged != 0 || s.archivedThrough != envelopes[0].Sequence {
		t.Fatal("archival state was not distinct after restart")
	}
	if _, err := s.archiveExpired(now); err == nil {
		t.Fatal("unexpired head archived")
	}

	controller, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var acks, out bytes.Buffer
	for _, e := range envelopes[1:] {
		if err := json.NewEncoder(&acks).Encode(spoolTestAck(t, private, e)); err != nil {
			t.Fatal(err)
		}
	}
	if err := drainSpoolSession(s, controller, &acks, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), bytes.Join(lines[1:], nil)) || s.acknowledged != envelopes[2].Sequence {
		t.Fatal("session did not drain exact signed records in sequence")
	}
	tail, err := os.ReadFile(filepath.Join(dir, spoolLegacyTail))
	if err != nil || !s.recoveredTail || !bytes.Equal(tail, torn) {
		t.Fatal("bounded torn tail was not preserved")
	}
	if _, err := os.Stat(filepath.Join(dir, evidenceLogFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("legacy source still active after migration")
	}
}

func TestSpoolDiskFullDuringWrite(t *testing.T) {
	store, stateDir, identity, receipt := admittedStore(t)
	t.Cleanup(store.close)
	cfg := testServiceConfig(t, stateDir)
	configPath := filepath.Join(t.TempDir(), "service.json")
	writeJSON(t, configPath, cfg)
	deviceKey := identity.signing.Public().(ed25519.PublicKey)
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, deviceKey, receipt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spool.close)
	first, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.append(first); err != nil {
		t.Fatal(err)
	}
	original, _, err := spool.head()
	if err != nil {
		t.Fatal(err)
	}
	lost, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	spool.writeRecord = func(file *os.File, data []byte) (int, error) {
		n, err := file.Write(data[:len(data)/2])
		if err != nil {
			return n, err
		}
		return n, syscall.ENOSPC
	}
	if err := spool.append(lost); !errors.Is(err, syscall.ENOSPC) || errors.Is(err, errEvidenceFull) {
		t.Fatalf("disk-full write returned %v", err)
	}
	pending := filepath.Join(cfg.EvidenceDir, spoolPending)
	partial, err := os.ReadFile(pending)
	if err != nil || len(partial) == 0 || json.Valid(partial) {
		t.Fatalf("expected a truncated staging file, got %d bytes: %v", len(partial), err)
	}
	controller, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.acknowledge(controller, spoolTestAck(t, key, first)); err == nil || spool.acknowledged != 0 {
		t.Fatal("failed spool accepted an acknowledgement")
	}
	var out bytes.Buffer
	if err := drainSpoolSession(spool, controller, bytes.NewReader(nil), &out); err == nil || out.Len() != 0 {
		t.Fatal("failed spool returned a delivery record")
	}
	spool.close()
	store.close()

	if err := runSpoolCommand(configPath, "", spoolShowHead, nil, &out, io.Discard); err != nil || !bytes.Equal(out.Bytes(), original) {
		t.Fatalf("recovery did not return the original signed head: %v", err)
	}
	if _, err := os.Stat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("uncommitted staging file after restart: %v", err)
	}
	spool, err = openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, deviceKey, receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.close()
	if len(spool.queue) != 1 || spool.size != int64(len(original)) || spool.acknowledged != 0 {
		t.Fatalf("incorrect recovered spool state: records=%d bytes=%d acknowledged=%d", len(spool.queue), spool.size, spool.acknowledged)
	}
	if err := spool.acknowledge(controller, spoolTestAck(t, key, first)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := spool.head(); !errors.Is(err, io.EOF) {
		t.Fatalf("failed append became visible after retiring the original head: %v", err)
	}
}

func TestSpoolCommittedRecordRequiresNewline(t *testing.T) {
	store, stateDir, i, receipt := admittedStore(t)
	t.Cleanup(store.close)
	cfg := testServiceConfig(t, stateDir)
	configPath := filepath.Join(t.TempDir(), "service.json")
	writeJSON(t, configPath, cfg)
	public := i.signing.Public().(ed25519.PublicKey)
	e, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	path := filepath.Join(cfg.EvidenceDir, recordName(e.Sequence))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := openEvidenceSpool(cfg.EvidenceDir, minEvidenceCap, 3, public, receipt); err == nil {
		s.close()
		t.Fatal("committed record with a truncated delimiter accepted")
	}
	store.close()
	var out bytes.Buffer
	if err := runSpoolCommand(configPath, "", spoolShowHead, nil, &out, io.Discard); err == nil || errors.Is(err, errEmptySpool) || out.Len() != 0 {
		t.Fatalf("truncated committed record was reported as delivered or empty: %v", err)
	}
	if stored, err := os.ReadFile(path); err != nil || !bytes.Equal(stored, raw) {
		t.Fatalf("restart changed the truncated committed record: %v", err)
	}
}
