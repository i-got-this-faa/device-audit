package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
)

func main() {
	address := flag.String("listen", "127.0.0.1:8080", "loopback development listener")
	transport := flag.String("transport", "loopback", "loopback or mesh")
	flag.Parse()
	if *transport != "loopback" {
		slog.Error("transport unavailable", "transport", *transport, "error", mesh.ErrNotImplemented)
		os.Exit(1)
	}
	listener, err := mesh.ListenLocal(*address)
	if err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}
	server := &http.Server{Handler: controller.NewAPI(1000).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("development controller ready", "address", listener.Addr(), "storage", "memory", "health_model", "not_implemented")
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
