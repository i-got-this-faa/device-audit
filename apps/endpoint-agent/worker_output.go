package main

import (
	"context"
	"errors"
)

type limitedWorkerOutput struct {
	data     []byte
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *limitedWorkerOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-len(w.data) {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("worker output limit reached")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
