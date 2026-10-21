package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Getenv("DEVICE_AUDIT_DATABASE_URL")); err != nil {
		slog.Error("controller failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, defaultDatabaseURL string) error {
	flags := flag.NewFlagSet("controller", flag.ContinueOnError)
	address := flags.String("listen", "127.0.0.1:8080", "loopback development listener")
	transport := flags.String("transport", "loopback", "loopback or mesh")
	databaseURL := flags.String("database-url", defaultDatabaseURL, "PostgreSQL URL; empty keeps development samples in memory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *transport != "loopback" {
		return fmt.Errorf("transport %q: %w", *transport, mesh.ErrNotImplemented)
	}

	databaseStatus := "not_configured"
	schemaVersion := 0
	var db *sql.DB
	if *databaseURL != "" {
		var err error
		db, err = database.Open(ctx, *databaseURL)
		if err != nil {
			return fmt.Errorf("database startup failed: %w", err)
		}
		defer db.Close()
		schemaVersion, err = database.Migrate(ctx, db)
		if err != nil {
			return fmt.Errorf("schema migration failed: %w", err)
		}
		databaseStatus = "connected"
		slog.Info("database schema ready", "schema_version", schemaVersion)
	} else {
		slog.Warn("durable database not configured; samples remain in memory")
	}

	listener, err := mesh.ListenLocal(*address)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	api := controller.NewAPI(controller.Config{MaxDevices: 1000, DatabaseStatus: databaseStatus, SchemaVersion: schemaVersion})
	server := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("development controller ready", "address", listener.Addr(), "sample_storage", "memory", "database", databaseStatus, "schema_version", schemaVersion, "health_model", "not_implemented")
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}
