package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type drainTestTransport func(*http.Request) (*http.Response, error)

func (send drainTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	defer req.Body.Close()
	return send(req)
}

func newDrainTestSpool(t *testing.T) (*evidenceSpool, []contracts.EvidenceEnvelopeV1, [][]byte) {
	t.Helper()
	store, path, id, receipt := admittedStore(t)
	defer store.close()
	cfg := testServiceConfig(t, path)
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, id.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(spool.close)
	var envelopes []contracts.EvidenceEnvelopeV1
	var records [][]byte
	for range 2 {
		e, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := spool.append(e); err != nil {
			t.Fatal(err)
		}
		data, err := spool.root.ReadFile(recordName(e.Sequence))
		if err != nil {
			t.Fatal(err)
		}
		envelopes, records = append(envelopes, e), append(records, data)
	}
	return spool, envelopes, records
}

func TestSpoolDrainKeepsUnacknowledgedHead(t *testing.T) {
	for _, tc := range []struct {
		name, message string
		change        func(*contracts.AcknowledgementV1)
		status        int
	}{
		{name: "wrong device", message: "invalid controller acknowledgement", status: 200, change: func(a *contracts.AcknowledgementV1) { a.DeviceID = "device:other" }},
		{name: "wrong sequence", message: "invalid controller acknowledgement", status: 200, change: func(a *contracts.AcknowledgementV1) { a.RequestSequence++; a.LastSequence = &a.RequestSequence }},
		{name: "wrong digest", message: "invalid controller acknowledgement", status: 200, change: func(a *contracts.AcknowledgementV1) { a.RequestSHA256 = strings.Repeat("0", 64) }},
		{name: "bad signature", message: "invalid controller acknowledgement", status: 200},
		{name: "revoked", message: "revoked_key", status: 409, change: func(a *contracts.AcknowledgementV1) {
			reason := contracts.EnvelopeRejectionRevokedKey
			a.Status, a.RejectionReason, a.LastSequence = "rejected", &reason, nil
		}},
		{name: "replay", message: "replay", status: 409, change: func(a *contracts.AcknowledgementV1) {
			reason := contracts.EnvelopeRejectionReplay
			a.Status, a.RejectionReason = "rejected", &reason
		}},
		{name: "denied admission", message: "mesh admission denied", status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spool, envelopes, records := newDrainTestSpool(t)
			key, private, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			a := spoolTestAck(t, private, envelopes[0])
			if tc.change != nil {
				tc.change(&a)
				message, err := a.SigningBytes()
				if err != nil {
					t.Fatal(err)
				}
				a.Signature = hex.EncodeToString(ed25519.Sign(private, message))
			}
			if tc.name == "bad signature" {
				a.Signature = strings.Repeat("0", 128)
			}
			body, _ := json.Marshal(a)
			if tc.name == "denied admission" {
				body = []byte("forbidden")
			}
			attempts := 0
			client := &http.Client{Transport: drainTestTransport(func(req *http.Request) (*http.Response, error) {
				attempts++
				got, err := io.ReadAll(req.Body)
				if err != nil || !bytes.Equal(got, records[0]) {
					t.Fatal("submitted something other than the exact spool head")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})}
			err = drainEvidence(t.Context(), spool, key, func(ctx context.Context, data []byte, e contracts.EvidenceEnvelopeV1) (contracts.AcknowledgementV1, error) {
				return postMeshEvidence(ctx, client, key, data, e)
			}, nil, t.Logf)
			if !errors.Is(err, errDeliveryBlocked) || !strings.Contains(err.Error(), tc.message) || attempts != 1 {
				t.Fatalf("attempts=%d, result=%v", attempts, err)
			}
			for index, e := range envelopes {
				got, err := spool.root.ReadFile(recordName(e.Sequence))
				if err != nil || !bytes.Equal(got, records[index]) {
					t.Fatalf("record %d changed after failed delivery: %v", e.Sequence, err)
				}
			}
			if spool.acknowledged != 0 {
				t.Fatal("failed delivery advanced the acknowledgement mark")
			}
		})
	}
}

func TestSpoolDrainBackoffAndOrdering(t *testing.T) {
	spool, envelopes, records := newDrainTestSpool(t)
	key, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make([][]byte, len(envelopes))
	for i, e := range envelopes {
		accepted[i], _ = json.Marshal(spoolTestAck(t, private, e))
	}
	synctest.Test(t, func(t *testing.T) {
		retryStatus := []int{0, 200, 503, 429, 408, 500, 503, 503, 503}
		var sent []uint64
		var times []time.Time
		client := &http.Client{Transport: drainTestTransport(func(req *http.Request) (*http.Response, error) {
			times = append(times, time.Now())
			attempt := len(times) - 1
			index := 0
			if attempt > len(retryStatus) {
				index = 1
			}
			data, err := io.ReadAll(req.Body)
			if err != nil || !bytes.Equal(data, records[index]) {
				t.Fatalf("attempt %d changed bytes or skipped the unacknowledged head", attempt)
			}
			sent = append(sent, envelopes[index].Sequence)
			if attempt < len(retryStatus) {
				switch status := retryStatus[attempt]; status {
				case 0:
					return nil, io.EOF
				case 200:
					return &http.Response{StatusCode: status, Body: io.NopCloser(iotest.ErrReader(io.ErrUnexpectedEOF))}, nil
				default:
					return &http.Response{StatusCode: status, Body: http.NoBody}, nil
				}
			}
			if attempt == len(retryStatus)+1 {
				return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(accepted[index]))}, nil
		})}
		if err := drainEvidence(t.Context(), spool, key, func(ctx context.Context, data []byte, e contracts.EvidenceEnvelopeV1) (contracts.AcknowledgementV1, error) {
			return postMeshEvidence(ctx, client, key, data, e)
		}, nil, t.Logf); err != nil {
			t.Fatal(err)
		}
		want := append(slices.Repeat([]uint64{envelopes[0].Sequence}, len(retryStatus)+1), envelopes[1].Sequence, envelopes[1].Sequence)
		if !slices.Equal(sent, want) || spool.acknowledged != envelopes[1].Sequence || len(spool.queue) != 0 {
			t.Fatalf("sent %v, acknowledged %d, remaining %d", sent, spool.acknowledged, len(spool.queue))
		}
		for i, cap := 0, initialDeliveryBackoff; i < len(retryStatus); i, cap = i+1, min(cap*2, maxDeliveryBackoff) {
			delay := times[i+1].Sub(times[i])
			if delay < cap/2 || delay >= cap {
				t.Fatalf("retry %d waited %s, want [%s, %s)", i, delay, cap/2, cap)
			}
		}
		if !times[len(times)-2].Equal(times[len(times)-3]) {
			t.Fatal("acknowledged head delayed delivery of the next record")
		}
		if delay := times[len(times)-1].Sub(times[len(times)-2]); delay < initialDeliveryBackoff/2 || delay >= initialDeliveryBackoff {
			t.Fatalf("backoff after acknowledged head was not reset: %s", delay)
		}
	})
}

func TestSpoolDrainCancelsBackoffWithoutRetiring(t *testing.T) {
	spool, _, _ := newDrainTestSpool(t)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		attempts := 0
		go func() {
			done <- drainEvidence(ctx, spool, nil, func(context.Context, []byte, contracts.EvidenceEnvelopeV1) (contracts.AcknowledgementV1, error) {
				attempts++
				return contracts.AcknowledgementV1{}, errDeliveryRetry
			}, nil, t.Logf)
		}()
		synctest.Wait()
		cancel()
		if err := <-done; err != nil || attempts != 1 || len(spool.queue) != 2 {
			t.Fatalf("cancellation: err=%v attempts=%d queued=%d", err, attempts, len(spool.queue))
		}
	})
}
