package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func serveTransports(ctx context.Context, admin net.Listener, handler http.Handler, application net.Listener, meshServer *http.Server) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	adminServer := &http.Server{Handler: adminOnly(handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	results := make(chan error, 2)
	go func() { results <- adminServer.Serve(admin) }()
	go func() { results <- meshServer.Serve(application) }()
	var err error
	select {
	case err = <-results:
	case <-ctx.Done():
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = adminServer.Shutdown(shutdown)
	_ = meshServer.Shutdown(shutdown)
	_ = adminServer.Close()
	_ = meshServer.Close()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("controller transport stopped unexpectedly")
	}
	return nil
}

// The public HTTPS boundary excludes fixture and device application APIs.
func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/telemetry" || r.URL.Path == "/v1/evidence" || strings.HasPrefix(r.URL.Path, "/v1/devices/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
