package controller

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
)

// FED01 #40 at the repository boundary with real PostgreSQL.

type roundBed struct {
	*registryBed
	actor   federated.Actor
	devices []meshTestDevice // a, b and c are enrolled; d is enrolled but not selected
	base    contracts.ModelManifestV1
}

const roundBaseVersion = "baseline.1"

func newRoundBed(t *testing.T) *roundBed {
	t.Helper()
	b := &roundBed{registryBed: newRegistryBed(t), actor: federated.Actor{Issuer: "https://id.example.test", Subject: "admin:test"}}
	for _, id := range []string{"device:a", "device:b", "device:c", "device:d"} {
		b.devices = append(b.devices, enrollMeshTestDevice(t, b.enrollmentTestBed, id))
	}
	b.base = b.storeModel(t, roundBaseVersion, []string{contracts.ModelPurposeTraining, contracts.ModelPurposeInference})
	return b
}

func (b *roundBed) storeModel(t *testing.T, version string, purposes []string) contracts.ModelManifestV1 {
	t.Helper()
	artifact := []byte("synthetic model bytes " + version)
	manifest := b.manifest(t, b.publisher, version, artifact, purposes...)
	if _, _, err := b.repo.PutModelArtifact(context.Background(), upload(manifest, artifact), b.publisher.Public().(ed25519.PublicKey),
		contracts.ModelActorV1(b.actor)); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func formatRoundTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// round selects devices a and b as eligible and d as not authorized; c is
// enrolled but left out, so it is not a participant.
func (b *roundBed) round(id string) contracts.FederatedRoundV1 {
	now := b.clock.Now()
	reason := "not_authorized"
	return contracts.FederatedRoundV1{
		SchemaVersion: contracts.FederatedRoundV1Version, DeploymentID: b.repo.deploymentID, RoundID: id, CandidateID: "candidate:" + id,
		BaseModelVersion: roundBaseVersion, BaseModelSHA256: b.base.ArtifactSHA256, FeatureVersion: b.base.FeatureVersion, ParameterCount: b.base.ParameterCount,
		OpenedAt: formatRoundTime(now), Deadline: formatRoundTime(now.Add(time.Hour)), MinParticipants: 2,
		Participants: []contracts.FederatedParticipantV1{
			{DeviceID: "device:b", SigningKeyID: b.devices[1].keyID, Eligibility: "eligible"},
			{DeviceID: "device:a", SigningKeyID: b.devices[0].keyID, Eligibility: "eligible"},
			{DeviceID: "device:d", SigningKeyID: b.devices[3].keyID, Eligibility: "ineligible", Reason: &reason},
		},
	}
}

func (b *roundBed) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := b.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// requireNoRounds checks that a refused request left no round behind.
func (b *roundBed) requireNoRounds(t *testing.T) {
	t.Helper()
	for _, table := range []string{"federated_rounds", "federated_round_participants", "federated_round_events"} {
		if n := b.count(t, table); n != 0 {
			t.Fatalf("%s has %d rows after a refused request", table, n)
		}
	}
}

func TestFederatedRoundDuplicatesAndRestartKeepOneLifecycle(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:1")

	record, created, err := b.repo.OpenRound(ctx, round, b.actor)
	if err != nil || !created || record.Status != federated.RoundOpen || len(record.Transitions) != 1 ||
		record.Transitions[0].To != federated.RoundOpen || record.Transitions[0].By == nil || record.Transitions[0].By.Subject != "admin:test" {
		t.Fatalf("open = %+v created=%v err=%v", record, created, err)
	}

	// The same round, with its participants listed in another order, is a repeat.
	repeated := round
	repeated.Participants = []contracts.FederatedParticipantV1{round.Participants[2], round.Participants[1], round.Participants[0]}
	again, created, err := b.repo.OpenRound(ctx, repeated, b.actor)
	if err != nil || created || !reflect.DeepEqual(again, record) {
		t.Fatalf("repeat = %+v created=%v err=%v", again, created, err)
	}

	// A different round under the same round or candidate ID conflicts.
	changed := round
	changed.Deadline = formatRoundTime(b.clock.Now().Add(2 * time.Hour))
	if _, _, err := b.repo.OpenRound(ctx, changed, b.actor); !errors.Is(err, federated.ErrRoundConflict) {
		t.Fatalf("changed deadline: %v", err)
	}
	reused := b.round("round:2")
	reused.CandidateID = round.CandidateID
	if _, _, err := b.repo.OpenRound(ctx, reused, b.actor); !errors.Is(err, federated.ErrRoundConflict) {
		t.Fatalf("reused candidate: %v", err)
	}
	if b.count(t, "federated_rounds") != 1 || b.count(t, "federated_round_participants") != 3 || b.count(t, "federated_round_events") != 1 {
		t.Fatal("duplicate or conflicting requests changed stored state")
	}

	// A participant is admitted once; a repeat returns the same admission.
	first, created, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID)
	if err != nil || !created || len(first.Accepted) != 1 || first.Accepted[0].DeviceID != "device:a" {
		t.Fatalf("accept = %+v created=%v err=%v", first, created, err)
	}
	second, created, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID)
	if err != nil || created || !reflect.DeepEqual(first, second) {
		t.Fatalf("repeated accept = %+v created=%v err=%v", second, created, err)
	}

	// A new repository over the same database, as after a restart, reads one lifecycle.
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Round(ctx, "round:1")
	if err != nil || !reflect.DeepEqual(got, first) {
		t.Fatalf("after restart = %+v err=%v, want %+v", got, err, first)
	}
	if _, created, err := restarted.OpenRound(ctx, round, b.actor); err != nil || created {
		t.Fatalf("open after restart created=%v err=%v", created, err)
	}
	if b.count(t, "federated_rounds") != 1 || b.count(t, "federated_round_events") != 1 {
		t.Fatal("restart created another lifecycle")
	}
}

func TestFederatedRoundRefusesIneligibleParticipants(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	if _, _, err := b.repo.OpenRound(ctx, b.round("round:1"), b.actor); err != nil {
		t.Fatal(err)
	}
	refuse := func(name, device, key string) {
		t.Helper()
		if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", device, key); !errors.Is(err, federated.ErrParticipantNotEligible) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	refuse("listed ineligible", "device:d", b.devices[3].keyID)
	refuse("enrolled but not selected", "device:c", b.devices[2].keyID)
	refuse("unknown device", "device:nobody", b.devices[0].keyID)
	refuse("another device's key", "device:a", b.devices[1].keyID)
	if _, _, err := b.repo.AcceptParticipant(ctx, "round:missing", "device:a", b.devices[0].keyID); !errors.Is(err, federated.ErrRoundNotFound) {
		t.Fatalf("unknown round: %v", err)
	}

	// A revocation after the snapshot overrides it.
	if _, _, err := b.repo.RevokeDevice(ctx, revocationRequest("device:b", "reason:test"), b.actor.Issuer, b.actor.Subject); err != nil {
		t.Fatal(err)
	}
	refuse("revoked after the snapshot", "device:b", b.devices[1].keyID)
	if n := b.count(t, "federated_round_participants WHERE accepted_at IS NOT NULL"); n != 0 {
		t.Fatalf("%d participants admitted by refused requests", n)
	}
}

func TestFederatedRoundRefusesUnregisteredBaseAndUnenrolledParticipants(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	b.storeModel(t, "inference-only.1", []string{contracts.ModelPurposeInference})

	cases := map[string]struct {
		change func(*contracts.FederatedRoundV1)
		want   error
	}{
		"unstored base version": {func(r *contracts.FederatedRoundV1) { r.BaseModelVersion = "missing.1" }, federated.ErrBaseNotRegistered},
		"digest of another artifact": {func(r *contracts.FederatedRoundV1) {
			r.BaseModelSHA256 = "00" + r.BaseModelSHA256[2:]
		}, federated.ErrBaseNotRegistered},
		"base without the training purpose": {func(r *contracts.FederatedRoundV1) {
			stored, err := b.repo.ModelArtifact(ctx, "inference-only.1")
			if err != nil {
				t.Fatal(err)
			}
			r.BaseModelVersion, r.BaseModelSHA256 = stored.Manifest.ModelVersion, stored.Manifest.ArtifactSHA256
		}, federated.ErrBaseNotRegistered},
		"parameter count differs":  {func(r *contracts.FederatedRoundV1) { r.ParameterCount++ }, federated.ErrBaseNotRegistered},
		"feature version differs":  {func(r *contracts.FederatedRoundV1) { r.FeatureVersion = "other-features.v1" }, federated.ErrBaseNotRegistered},
		"participant not enrolled": {func(r *contracts.FederatedRoundV1) { r.Participants[0].DeviceID = "device:ghost" }, federated.ErrParticipantNotEligible},
		"participant with another key": {func(r *contracts.FederatedRoundV1) {
			r.Participants[0].SigningKeyID = b.devices[2].keyID
		}, federated.ErrParticipantNotEligible},
		"deadline already passed": {func(r *contracts.FederatedRoundV1) {
			r.OpenedAt, r.Deadline = formatRoundTime(b.clock.Now().Add(-2*time.Hour)), formatRoundTime(b.clock.Now().Add(-time.Hour))
		}, federated.ErrRoundNotOpen},
		"opened in the future": {func(r *contracts.FederatedRoundV1) {
			r.OpenedAt, r.Deadline = formatRoundTime(b.clock.Now().Add(time.Hour)), formatRoundTime(b.clock.Now().Add(2*time.Hour))
		}, federated.ErrRoundNotOpen},
	}
	i := 0
	for name, tc := range cases {
		i++
		round := b.round(fmt.Sprintf("round:case%d", i))
		tc.change(&round)
		if _, _, err := b.repo.OpenRound(ctx, round, b.actor); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// A device already revoked cannot be listed as eligible.
	if _, _, err := b.repo.RevokeDevice(ctx, revocationRequest("device:b", "reason:test"), b.actor.Issuer, b.actor.Subject); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.OpenRound(ctx, b.round("round:revoked"), b.actor); !errors.Is(err, federated.ErrParticipantNotEligible) {
		t.Errorf("revoked participant listed eligible: %v", err)
	}
	b.requireNoRounds(t)

	// It can be listed as ineligible, so the controller can record why.
	round := b.round("round:revoked")
	revoked := "revoked"
	round.Participants = []contracts.FederatedParticipantV1{
		{DeviceID: "device:a", SigningKeyID: b.devices[0].keyID, Eligibility: "eligible"},
		{DeviceID: "device:c", SigningKeyID: b.devices[2].keyID, Eligibility: "eligible"},
		{DeviceID: "device:b", SigningKeyID: b.devices[1].keyID, Eligibility: "ineligible", Reason: &revoked},
	}
	if _, created, err := b.repo.OpenRound(ctx, round, b.actor); err != nil || !created {
		t.Errorf("revoked participant listed ineligible: created=%v err=%v", created, err)
	}
}

func TestFederatedRoundDeadline(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	for _, id := range []string{"round:1", "round:2", "round:3"} {
		if _, _, err := b.repo.OpenRound(ctx, b.round(id), b.actor); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID); err != nil {
		t.Fatal(err)
	}

	// The deadline is exclusive: at it, no participant can be admitted.
	b.clock.Advance(time.Hour)
	if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", "device:b", b.devices[1].keyID); !errors.Is(err, federated.ErrRoundNotOpen) {
		t.Fatalf("accept at the deadline: %v", err)
	}
	record, err := b.repo.Round(ctx, "round:1")
	if err != nil || record.Status != federated.RoundClosed || len(record.Accepted) != 1 || len(record.Transitions) != 2 {
		t.Fatalf("round after deadline = %+v err=%v", record, err)
	}
	if closing := record.Transitions[1]; closing.From != federated.RoundOpen || closing.To != federated.RoundClosed || closing.Reason != "deadline" || closing.By != nil {
		t.Fatalf("closing transition = %+v", closing)
	}

	// Later attempts and reads add no transitions and never reopen the round.
	for range 3 {
		if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", "device:b", b.devices[1].keyID); !errors.Is(err, federated.ErrRoundNotOpen) {
			t.Fatalf("accept after close: %v", err)
		}
	}
	if _, err := b.repo.CancelRound(ctx, "round:1", b.actor); !errors.Is(err, federated.ErrRoundNotOpen) {
		t.Fatalf("cancel after close: %v", err)
	}
	// A participant admitted before the deadline gets the stored admission back.
	if _, created, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID); err != nil || created {
		t.Fatalf("repeat after close created=%v err=%v", created, err)
	}
	if again, _ := b.repo.Round(ctx, "round:1"); !reflect.DeepEqual(again, record) {
		t.Fatalf("round changed after refused requests: %+v", again)
	}

	// A sweep closes the rounds nothing has touched, once each.
	for _, want := range []int{2, 0} {
		if closed, err := b.repo.CloseExpiredRounds(ctx); err != nil || closed != want {
			t.Fatalf("sweep closed %d err=%v, want %d", closed, err, want)
		}
	}
	if n := b.count(t, "federated_round_events WHERE reason='deadline'"); n != 3 {
		t.Fatalf("%d deadline transitions, want 3", n)
	}
}

func TestFederatedRoundCancel(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	if _, _, err := b.repo.OpenRound(ctx, b.round("round:1"), b.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.CancelRound(ctx, "round:1", federated.Actor{}); err == nil {
		t.Fatal("cancel without an authenticated actor")
	}
	if _, err := b.repo.CancelRound(ctx, "round:missing", b.actor); !errors.Is(err, federated.ErrRoundNotFound) {
		t.Fatalf("cancel unknown round: %v", err)
	}
	cancelled, err := b.repo.CancelRound(ctx, "round:1", b.actor)
	if err != nil || cancelled.Status != federated.RoundCancelled || len(cancelled.Transitions) != 2 || cancelled.Transitions[1].By == nil {
		t.Fatalf("cancel = %+v err=%v", cancelled, err)
	}
	if again, err := b.repo.CancelRound(ctx, "round:1", b.actor); err != nil || !reflect.DeepEqual(again, cancelled) {
		t.Fatalf("repeated cancel = %+v err=%v", again, err)
	}
	if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID); !errors.Is(err, federated.ErrRoundNotOpen) {
		t.Fatalf("accept after cancel: %v", err)
	}
	// Time passing does not turn a cancelled round into a closed one.
	b.clock.Advance(2 * time.Hour)
	if record, err := b.repo.Round(ctx, "round:1"); err != nil || record.Status != federated.RoundCancelled || len(record.Transitions) != 2 {
		t.Fatalf("cancelled round after deadline = %+v err=%v", record, err)
	}
}

// Concurrent identical requests commit one open and one admission.
func TestFederatedRoundConcurrentRequestsCommitOnce(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:1")
	run := func(call func() (bool, error)) (created int) {
		var wg sync.WaitGroup
		var n atomic.Int32
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if wasCreated, err := call(); err != nil {
					t.Error(err)
				} else if wasCreated {
					n.Add(1)
				}
			}()
		}
		wg.Wait()
		return int(n.Load())
	}
	if n := run(func() (bool, error) { _, created, err := b.repo.OpenRound(ctx, round, b.actor); return created, err }); n != 1 {
		t.Fatalf("%d concurrent opens created a round, want 1", n)
	}
	if n := run(func() (bool, error) {
		_, created, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID)
		return created, err
	}); n != 1 {
		t.Fatalf("%d concurrent admissions created, want 1", n)
	}
	if b.count(t, "federated_rounds") != 1 || b.count(t, "federated_round_events") != 1 {
		t.Fatal("concurrent requests stored more than one lifecycle")
	}
}

// The database refuses what the controller code must never do, so a missed
// check in a future code path cannot reopen a round or admit a bad participant.
func TestFederatedRoundDatabaseRefusesInvalidTransitions(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	if _, _, err := b.repo.OpenRound(ctx, b.round("round:1"), b.actor); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.OpenRound(ctx, b.round("round:2"), b.actor); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.CancelRound(ctx, "round:2", b.actor); err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"reopen a cancelled round":     `UPDATE federated_rounds SET status='open' WHERE round_id='round:2'`,
		"close a cancelled round":      `UPDATE federated_rounds SET status='closed' WHERE round_id='round:2'`,
		"move the deadline":            `UPDATE federated_rounds SET deadline = deadline + interval '1 hour' WHERE round_id='round:1'`,
		"delete a round":               `DELETE FROM federated_rounds WHERE round_id='round:1'`,
		"admit into a cancelled round": `UPDATE federated_round_participants SET accepted_at=now() WHERE round_id='round:2' AND device_id='device:a'`,
		"admit an ineligible device":   `UPDATE federated_round_participants SET accepted_at=now() WHERE round_id='round:1' AND device_id='device:d'`,
		"make an ineligible one fit":   `UPDATE federated_round_participants SET eligibility='eligible', reason=NULL WHERE round_id='round:1' AND device_id='device:d'`,
		"admit at the deadline": `UPDATE federated_round_participants p SET accepted_at=(SELECT deadline FROM federated_rounds r WHERE r.round_id=p.round_id)
			WHERE round_id='round:1' AND device_id='device:b'`,
		"admit before the round opened": `UPDATE federated_round_participants p SET accepted_at=(SELECT opened_at - interval '1 second' FROM federated_rounds r WHERE r.round_id=p.round_id)
			WHERE round_id='round:1' AND device_id='device:b'`,
		"insert a participant already admitted": `INSERT INTO federated_round_participants (deployment_id, round_id, device_id, signing_key_id, eligibility, accepted_at)
			SELECT 'deployment:enrollment-test', 'round:1', device_id, signing_key_id, 'eligible', now() FROM device_enrollments WHERE device_id='device:c'`,
		"delete a participant": `DELETE FROM federated_round_participants WHERE round_id='round:1'`,
		"rewrite history":      `UPDATE federated_round_events SET reason='deadline'`,
		"delete history":       `DELETE FROM federated_round_events`,
		"participant that never enrolled": `INSERT INTO federated_round_participants (deployment_id, round_id, device_id, signing_key_id, eligibility)
			SELECT deployment_id, round_id, 'device:ghost', signing_key_id, 'eligible' FROM federated_round_participants WHERE round_id='round:1' LIMIT 1`,
	}
	for name, statement := range refused {
		if _, err := b.db.Exec(statement); err == nil {
			t.Errorf("database allowed: %s", name)
		}
	}
	// An admitted participant cannot be admitted again with a new time.
	if _, _, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE federated_round_participants SET accepted_at=now() WHERE round_id='round:1' AND device_id='device:a'`); err == nil {
		t.Error("database allowed a second admission time")
	}
}

// A repeat after the deadline returns the stored admission and records the
// closing the round was owed.
func TestFederatedRoundRepeatAdmissionAfterDeadlineClosesRound(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	if _, _, err := b.repo.OpenRound(ctx, b.round("round:1"), b.actor); err != nil {
		t.Fatal(err)
	}
	admitted, _, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID)
	if err != nil {
		t.Fatal(err)
	}
	b.clock.Advance(time.Hour)
	record, created, err := b.repo.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID)
	if err != nil || created || record.Status != federated.RoundClosed || len(record.Transitions) != 2 ||
		!reflect.DeepEqual(record.Accepted, admitted.Accepted) {
		t.Fatalf("repeat after deadline = %+v created=%v err=%v", record, created, err)
	}
}

// The enrollment lock can wait on a revocation past the deadline. The clock is
// read again after it, and an admission never records a time at or after it.
func TestFederatedRoundDeadlineCrossedAfterEnrollmentLock(t *testing.T) {
	b := newRoundBed(t)
	ctx := context.Background()
	round := b.round("round:1")
	if _, _, err := b.repo.OpenRound(ctx, round, b.actor); err != nil {
		t.Fatal(err)
	}
	deadline := mustParseRoundTime(round.Deadline)
	var reads atomic.Int32
	racing, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: func() time.Time {
		if reads.Add(1) == 1 {
			return deadline.Add(-time.Second) // the early check still sees an open round
		}
		return deadline
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := racing.AcceptParticipant(ctx, "round:1", "device:a", b.devices[0].keyID); !errors.Is(err, federated.ErrRoundNotOpen) {
		t.Fatalf("accept across the deadline: %v", err)
	}
	record, err := b.repo.Round(ctx, "round:1")
	if err != nil || record.Status != federated.RoundClosed || len(record.Accepted) != 0 || len(record.Transitions) != 2 {
		t.Fatalf("round = %+v err=%v", record, err)
	}
}
