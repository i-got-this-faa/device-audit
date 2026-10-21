package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
)

type environment struct {
	DatabaseURL      string
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	PublicOrigin     string
	BootstrapAdmin   string
	OIDCRequiredAMR  string
}

func main() {
	if err := run(context.Background(), os.Args[1:], environmentFromOS()); err != nil {
		slog.Error("controller failed", "error", err)
		os.Exit(1)
	}
}

func environmentFromOS() environment {
	env := environment{
		DatabaseURL:      os.Getenv("DEVICE_AUDIT_DATABASE_URL"),
		OIDCIssuer:       os.Getenv("DEVICE_AUDIT_OIDC_ISSUER"),
		OIDCClientID:     os.Getenv("DEVICE_AUDIT_OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("DEVICE_AUDIT_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  os.Getenv("DEVICE_AUDIT_OIDC_REDIRECT_URL"),
		PublicOrigin:     os.Getenv("DEVICE_AUDIT_PUBLIC_ORIGIN"),
		BootstrapAdmin:   os.Getenv("DEVICE_AUDIT_BOOTSTRAP_ADMIN"),
		OIDCRequiredAMR:  "mfa",
	}
	// An explicitly empty value disables local AMR enforcement; an unset value
	// keeps the deployment default.
	if value, ok := os.LookupEnv("DEVICE_AUDIT_OIDC_REQUIRED_AMR"); ok {
		env.OIDCRequiredAMR = value
	}
	return env
}

func run(ctx context.Context, args []string, defaults environment) error {
	flags := flag.NewFlagSet("controller", flag.ContinueOnError)
	address := flags.String("listen", "127.0.0.1:8080", "loopback development listener")
	transport := flags.String("transport", "loopback", "loopback or mesh")
	databaseURL := flags.String("database-url", "", "PostgreSQL URL; empty keeps development samples in memory")
	oidcIssuer := flags.String("oidc-issuer", defaults.OIDCIssuer, "configured OIDC issuer URL")
	oidcClientID := flags.String("oidc-client-id", defaults.OIDCClientID, "OIDC confidential client ID")
	oidcClientSecret := flags.String("oidc-client-secret", defaults.OIDCClientSecret, "OIDC confidential client secret")
	oidcRedirectURL := flags.String("oidc-redirect-url", defaults.OIDCRedirectURL, "exact OIDC callback URL")
	publicOrigin := flags.String("public-origin", defaults.PublicOrigin, "public HTTPS origin used for cookies and Origin checks")
	bootstrapAdmin := flags.String("bootstrap-admin", defaults.BootstrapAdmin, "local OIDC subject to preprovision as the first admin")
	requiredAMR := flags.String("oidc-required-amr", defaults.OIDCRequiredAMR, "required ID token amr value; empty relies on the issuer MFA policy")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	provided := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if !provided["database-url"] {
		*databaseURL = defaults.DatabaseURL
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

	authStatus := "not_configured"
	var consoleAuth *auth.Service
	authConfig := authFlags{
		issuer:         *oidcIssuer,
		clientID:       *oidcClientID,
		clientSecret:   *oidcClientSecret,
		redirectURL:    *oidcRedirectURL,
		publicOrigin:   *publicOrigin,
		bootstrapAdmin: *bootstrapAdmin,
		requiredAMR:    *requiredAMR,
	}
	if authConfig.configured() {
		if db == nil {
			return errors.New("console auth requires --database-url for durable sessions and role bindings")
		}
		var err error
		consoleAuth, err = configureAuth(ctx, db, authConfig)
		if err != nil {
			return fmt.Errorf("console auth startup failed: %w", err)
		}
		authStatus = "oidc"
		slog.Info("console authentication ready", "issuer", authConfig.issuer)
	}

	listener, err := mesh.ListenLocal(*address)
	if err != nil {
		return fmt.Errorf("listen failed: %w", err)
	}
	api := controller.NewAPI(controller.Config{
		MaxDevices:     1000,
		DatabaseStatus: databaseStatus,
		SchemaVersion:  schemaVersion,
		Auth:           consoleAuth,
		AuthStatus:     authStatus,
	})
	server := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("development controller ready", "address", listener.Addr(), "sample_storage", "memory", "database", databaseStatus, "schema_version", schemaVersion, "auth", authStatus, "health_model", "not_implemented")
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}

type authFlags struct {
	issuer         string
	clientID       string
	clientSecret   string
	redirectURL    string
	publicOrigin   string
	bootstrapAdmin string
	requiredAMR    string
}

func (f authFlags) configured() bool {
	return f.issuer != "" || f.clientID != "" || f.clientSecret != "" || f.redirectURL != "" || f.publicOrigin != "" || f.bootstrapAdmin != ""
}

func configureAuth(ctx context.Context, db *sql.DB, cfg authFlags) (*auth.Service, error) {
	required := []struct {
		name  string
		value string
	}{
		{"--oidc-issuer", cfg.issuer},
		{"--oidc-client-id", cfg.clientID},
		{"--oidc-client-secret", cfg.clientSecret},
		{"--oidc-redirect-url", cfg.redirectURL},
		{"--public-origin", cfg.publicOrigin},
	}
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return nil, fmt.Errorf("%s is required when console auth is configured", field.name)
		}
	}
	origin, err := url.Parse(cfg.publicOrigin)
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("--public-origin must be an absolute origin without a path, query or fragment")
	}
	redirect, err := url.Parse(cfg.redirectURL)
	if err != nil || redirect.Scheme != origin.Scheme || redirect.Host != origin.Host || redirect.User != nil || redirect.Path != "/auth/callback" || redirect.RawQuery != "" || redirect.Fragment != "" {
		return nil, errors.New("--oidc-redirect-url must be the /auth/callback path on --public-origin")
	}
	if origin.Scheme != "https" && !(origin.Scheme == "http" && (origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1" || origin.Hostname() == "localhost")) {
		return nil, errors.New("--public-origin must use https outside loopback development")
	}

	store := auth.NewPostgresStore(db)
	provider := auth.NewOIDCProvider(cfg.issuer, cfg.clientID, cfg.clientSecret, cfg.redirectURL, nil)
	service, err := auth.NewService(auth.Config{
		Issuer:       cfg.issuer,
		PublicOrigin: cfg.publicOrigin,
		Store:        store,
		Provider:     provider,
		RequiredAMR:  strings.TrimSpace(cfg.requiredAMR),
	})
	if err != nil {
		return nil, err
	}
	if cfg.bootstrapAdmin != "" {
		if err := service.EnsureBinding(ctx, cfg.bootstrapAdmin, auth.RoleAdmin); err != nil {
			return nil, fmt.Errorf("preprovision bootstrap admin: %w", err)
		}
	}
	bindings, err := store.Bindings(ctx, cfg.issuer)
	if err != nil {
		return nil, fmt.Errorf("read console role bindings: %w", err)
	}
	for _, binding := range bindings {
		if binding.Role == auth.RoleAdmin {
			return service, nil
		}
	}
	return nil, errors.New("console auth has no admin role binding; preprovision an admin subject; --bootstrap-admin only creates a missing binding and never changes an existing role")
}
