package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

type serviceInference struct {
	queue     chan inferenceSample
	cancel    context.CancelFunc
	done      chan struct{}
	next      time.Time
	daily     [contracts.FeatureWindowDays]health.SMARTReading
	latestDay time.Time
}

func startServiceInference(ctx context.Context, config *inferenceConfig, store *identityStore, deployment string, run inferenceRunner, logf func(string, ...any)) *serviceInference {
	if config == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	worker := &serviceInference{
		queue: make(chan inferenceSample, 1), cancel: cancel, done: make(chan struct{}),
	}
	loggedRun := func(ctx context.Context, req inferenceRequest) (inferenceResult, error) {
		result, err := run(ctx, req)
		if err != nil {
			logf("endpoint inference unavailable: %s", inferenceFailureCode(err))
		}
		return result, err
	}
	go func() {
		defer close(worker.done)
		active := *config
		if active.StagedEvaluationFile != "" {
			active = activateStagedModel(ctx, active, store, deployment, run, logf)
		}
		for {
			select {
			case <-ctx.Done():
				return
			case sample := <-worker.queue:
				if ctx.Err() != nil {
					return
				}
				prediction := predictSample(ctx, active, sample, time.Now().UTC(), loggedRun)
				if data, err := json.Marshal(prediction); err == nil && ctx.Err() == nil {
					logf("endpoint inference: %s", data)
				}
			}
		}
	}()
	return worker
}

func (w *serviceInference) close() {
	if w != nil {
		w.cancel()
		<-w.done
	}
}

// observe runs on the sampling goroutine. It keeps one slot per UTC day and
// copies at most seven records per job. A full queue never stalls telemetry.
func (w *serviceInference) observe(payload contracts.TelemetryV2, digest string, now time.Time) {
	if w == nil {
		return
	}
	r := health.ReadingFromTelemetry(payload)
	day := r.ObservedAt.UTC().Truncate(24 * time.Hour)
	if day.Before(w.latestDay) || r.ObservedAt.After(now) {
		return
	}
	w.latestDay = day
	slot := &w.daily[(day.Unix()/86400%contracts.FeatureWindowDays+contracts.FeatureWindowDays)%contracts.FeatureWindowDays]
	if slot.ObservedAt.UTC().Truncate(24*time.Hour) != day {
		*slot = r
	} else if !r.ObservedAt.Before(slot.ObservedAt) {
		// CT03 keeps the latest non-null reading per counter in each UTC day.
		if r.SMART5Raw != nil {
			slot.SMART5Raw = r.SMART5Raw
		}
		if r.SMART9Raw != nil {
			slot.SMART9Raw = r.SMART9Raw
		}
		if r.SMART197Raw != nil {
			slot.SMART197Raw = r.SMART197Raw
		}
		slot.ObservedAt = r.ObservedAt
	}
	if now.Before(w.next) {
		return
	}
	select {
	case w.queue <- inferenceSample{deviceID: payload.DeviceID, digest: digest, at: payload.CollectedAt,
		readings: append([]health.SMARTReading(nil), w.daily[:]...)}:
		w.next = now.Add(inferenceCadence)
	default:
	}
}
