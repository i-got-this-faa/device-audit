package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

const diagnosticPollInterval = 5 * time.Second

type diagnosticTransport interface {
	pollDiagnostics(context.Context, string) (workflows.PollResponse, error)
	sendDiagnostic(context.Context, *diagnosticJob) error
}

func (s *meshEvidenceSender) pollDiagnostics(ctx context.Context, deviceID string) (workflows.PollResponse, error) {
	var poll workflows.PollResponse
	err := s.diagnosticRequest(ctx, "poll", nil, &poll, http.StatusOK)
	if err == nil && (poll.Status != "ok" || poll.DeviceID != deviceID || len(poll.Assignments) > 1 ||
		(len(poll.Assignments) == 1 && poll.LeaseExpiresAt == nil)) {
		err = fmt.Errorf("%w: invalid diagnostic poll response", errDeliveryBlocked)
	}
	return poll, err
}

func (s *meshEvidenceSender) sendDiagnostic(ctx context.Context, job *diagnosticJob) error {
	result, err := job.result()
	if err != nil {
		return err
	}
	var ack workflows.ResultReceipt
	err = s.diagnosticRequest(ctx, "results", job.Result, &ack, http.StatusOK, http.StatusCreated)
	if err != nil {
		return err
	}
	// CT06 receipts are authenticated by the pinned mesh peer. TLS enrollment
	// and the separate CT04 signed evidence acknowledgements are unaffected.
	_, acceptedErr := time.Parse(time.RFC3339, ack.AcceptedAt)
	if ack.Status != "accepted" || ack.AssignmentID != result.AssignmentID || ack.DeviceID != result.DeviceID ||
		ack.State != result.State || ack.Sequence != result.Sequence || acceptedErr != nil {
		return fmt.Errorf("%w: mismatched diagnostic receipt", errDeliveryBlocked)
	}
	return nil
}

func (s *meshEvidenceSender) diagnosticRequest(ctx context.Context, path string, data []byte, output any, success ...int) error {
	if err := s.connect(ctx); err != nil {
		return err
	}
	err := postDiagnostic(ctx, s.client.HTTPClient(), path, data, output, success)
	s.resetOnRetry(err)
	return err
}

func postDiagnostic(ctx context.Context, client *http.Client, path string, data []byte, output any, success []int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+mesh.ApplicationHost+"/v1/diagnostics/"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: diagnostic %s request failed", errDeliveryRetry, path)
	}
	defer response.Body.Close()
	status := response.StatusCode
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests || status >= 500 {
		return fmt.Errorf("%w: diagnostic %s returned HTTP %d", errDeliveryRetry, path, status)
	}
	if !slices.Contains(success, status) {
		return fmt.Errorf("%w: diagnostic %s returned HTTP %d", errDeliveryBlocked, path, status)
	}
	const maxDiagnosticResponse = 64 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDiagnosticResponse+1))
	if err != nil {
		return fmt.Errorf("%w: diagnostic %s response interrupted", errDeliveryRetry, path)
	}
	if len(body) > maxDiagnosticResponse || json.Unmarshal(body, output) != nil {
		return fmt.Errorf("%w: invalid diagnostic %s response", errDeliveryBlocked, path)
	}
	return nil
}

type diagnosticDelivery struct {
	store      *identityStore
	identity   *identity
	receipt    contracts.EnrollmentAcceptedV1
	authority  ed25519.PublicKey
	bootID     string
	runner     *workflows.ProbeRunner
	sequenceMu *sync.Mutex
	transport  diagnosticTransport

	job      *diagnosticJob
	offer    workflows.PollResponse
	nextPoll time.Time
}

func (d *diagnosticDelivery) run(ctx context.Context, spool *evidenceSpool, ackKey ed25519.PublicKey, send sendEvidence, wake <-chan struct{}, logf func(string, ...any)) error {
	var err error
	d.job, err = d.store.loadDiagnosticJob(d.authority, d.identity.signing.Public().(ed25519.PublicKey), d.receipt)
	if err != nil {
		return err
	}
	backoff := initialDeliveryBackoff
	for ctx.Err() == nil {
		delay, err := d.step(ctx, spool, ackKey, send)
		switch {
		case ctx.Err() != nil && (err == nil || errors.Is(err, context.Canceled) || errors.Is(err, errDeliveryRetry)):
			return nil
		case errors.Is(err, errDeliveryRetry):
			delay = backoff/2 + rand.N(backoff/2)
			logf("delivery will retry in %s: %v", delay.Round(time.Millisecond), err)
			backoff = min(backoff*2, maxDeliveryBackoff)
		case err != nil:
			return err
		default:
			backoff = initialDeliveryBackoff
		}
		if delay > 0 {
			timer := time.NewTimer(delay)
			// Wake promptly for new telemetry except during retry backoff.
			ready := wake
			if err != nil {
				ready = nil
			}
			select {
			case <-ctx.Done():
			case <-ready:
			case <-timer.C:
			}
			timer.Stop()
		}
	}
	return nil
}

func (d *diagnosticDelivery) step(ctx context.Context, spool *evidenceSpool, ackKey ed25519.PublicKey, send sendEvidence) (time.Duration, error) {
	now := time.Now()
	if d.job != nil && len(d.job.Result) == 0 {
		return 0, d.recover(ctx)
	}
	if d.job == nil {
		if err := d.pollAndExecute(ctx, now); err != nil {
			return 0, err
		}
	}
	data, envelope, err := spool.head()
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	// The sampling callback holds sequenceMu across reservation and append.
	// The diagnostic claim held that same lock, so any earlier telemetry is
	// already queued. Deliver the smallest sequence across the two spools.
	if d.job != nil && (errors.Is(err, io.EOF) || d.job.ResultSequence < envelope.Sequence) {
		if err := d.transport.sendDiagnostic(ctx, d.job); err != nil {
			return 0, err
		}
		if err := commitSpoolRename(d.store.root, activeDiagnosticJob, retiredDiagnosticJob); err != nil {
			return 0, fmt.Errorf("retire accepted diagnostic result: %w", err)
		}
		d.job = nil
		return 0, nil
	}
	if errors.Is(err, io.EOF) {
		return time.Until(d.nextPoll), nil
	}
	ack, err := send(ctx, data, envelope)
	if err != nil {
		return 0, err
	}
	return 0, spool.acknowledge(ackKey, ack)
}

func (d *diagnosticDelivery) poll(ctx context.Context) error {
	offer, err := d.transport.pollDiagnostics(ctx, d.receipt.DeviceID)
	if err != nil {
		return err
	}
	d.offer = offer
	d.nextPoll = time.Now().Add(diagnosticPollInterval)
	return nil
}

func (d *diagnosticDelivery) recover(ctx context.Context) error {
	if err := d.poll(ctx); err != nil {
		return err
	}
	job := d.job
	cancelled := slices.Contains(d.offer.CancelAssignmentIDs, job.Assignment.AssignmentID)
	result, err := workflows.RecoverDiagnosticAssignment(job.Assignment, d.identity.signing, job.BootID,
		job.AssignmentSHA256, job.ResultSequence, job.AdmittedAt, job.StartedAt, time.Now(), cancelled)
	if err != nil {
		return err
	}
	return d.store.finishDiagnosticJob(job, result)
}

func (d *diagnosticDelivery) pollAndExecute(ctx context.Context, now time.Time) error {
	if len(d.offer.Assignments) == 0 && !now.Before(d.nextPoll) {
		if err := d.poll(ctx); err != nil {
			return err
		}
	}
	if len(d.offer.Assignments) == 0 {
		return nil
	}
	assignment := d.offer.Assignments[0]
	d.offer.Assignments = nil
	if d.offer.LeaseExpiresAt == nil || time.Now().Add(time.Duration(assignment.Budget.WallSeconds)*time.Second).After(*d.offer.LeaseExpiresAt) {
		return nil
	}
	job := new(diagnosticJob)
	err := d.executeWithCancellation(ctx, assignment, job, diagnosticPollInterval)
	if job.ResultSequence != 0 {
		d.job = job
	}
	if errors.Is(err, workflows.ErrAssignmentReplay) || errors.Is(err, workflows.ErrAssignmentExpired) {
		return nil
	}
	return err
}

// Cancellation polling uses the same authenticated peer and mesh session as
// normal dispatch. The controller keeps only one live lease per endpoint.
func (d *diagnosticDelivery) executeWithCancellation(ctx context.Context, assignment contracts.DiagnosticAssignmentV1, job *diagnosticJob, interval time.Duration) error {
	probeCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() {
		_, err := d.store.executeDiagnosticAssignment(probeCtx, d.runner, assignment, d.authority, d.identity, d.receipt, d.bootID, job, d.sequenceMu)
		done <- err
		stop()
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return err
		case <-probeCtx.Done():
			return <-done
		case <-ticker.C:
			if d.poll(probeCtx) == nil && slices.Contains(d.offer.CancelAssignmentIDs, assignment.AssignmentID) {
				stop()
			}
		}
	}
}
