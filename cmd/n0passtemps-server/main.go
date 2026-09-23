// Command n0passtemps-server runs the authentication service.
//
// It is one static binary. Everything it needs beyond a database and two
// secrets is compiled in, including the schema migrations and the
// administration interface, so there is no asset directory to deploy and no
// version skew between the binary and its migrations.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Socold/n0passtemps/internal/alerts"
	"github.com/Socold/n0passtemps/internal/api"
	"github.com/Socold/n0passtemps/internal/assertion"
	"github.com/Socold/n0passtemps/internal/audit"
	"github.com/Socold/n0passtemps/internal/auditsink"
	"github.com/Socold/n0passtemps/internal/config"
	"github.com/Socold/n0passtemps/internal/crypto/envelope"
	"github.com/Socold/n0passtemps/internal/crypto/kek"
	"github.com/Socold/n0passtemps/internal/health"
	"github.com/Socold/n0passtemps/internal/janitor"
	"github.com/Socold/n0passtemps/internal/logging"
	"github.com/Socold/n0passtemps/internal/store"
	"github.com/Socold/n0passtemps/internal/store/postgres"
	"github.com/Socold/n0passtemps/internal/store/sqlite"
	"github.com/Socold/n0passtemps/internal/subject"
	"github.com/Socold/n0passtemps/internal/throttle"
	"github.com/Socold/n0passtemps/internal/version"
	"github.com/Socold/n0passtemps/internal/webauthn"
)

func main() {
	// Everything real happens in run, so that deferred cleanup actually runs.
	// os.Exit in main would skip it, and the deferred work here includes
	// closing the database and zeroizing key material.
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "n0passtemps: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath  = flag.String("config", "", "path to config.toml, empty to configure entirely from the environment")
		showVersion = flag.Bool("version", false, "print the version and exit")
		checkOnly   = flag.Bool("check-config", false, "validate the configuration and exit without starting")
		migrateOnly = flag.Bool("migrate", false, "apply pending migrations and exit")
		bootstrap   = flag.Bool("bootstrap-admin", false, "create the first administrative token, print it once and exit")
		force       = flag.Bool("force", false, "with -bootstrap-admin, create a token even though an administrator already exists")
		admins      = flag.Int("admins", 1, "with -bootstrap-admin, how many administrative tokens to create; use 2 when dual approval is on")
	)
	flag.Parse()

	if *showVersion {
		info := version.Current()
		fmt.Printf("n0passtemps-server %s\n", info.Version)
		if info.Commit != "" {
			fmt.Printf("commit:  %s\n", info.Commit)
		}
		if info.BuildDate != "" {
			fmt.Printf("built:   %s\n", info.BuildDate)
		}
		fmt.Printf("go:      %s\n", info.GoVersion)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		// A configuration error is reported before the logger exists, so it
		// goes to stderr in plain text. The validator returns every problem it
		// found rather than the first, so an operator fixes one round instead
		// of many.
		return fmt.Errorf("configuration is not valid:\n%w", err)
	}

	log := logging.New(cfg.Logging, os.Stdout)
	slog.SetDefault(log)

	if *checkOnly {
		fmt.Println("configuration is valid")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The keyring comes first. Nothing that touches a sealed secret can be
	// built without it, and an operator who has misplaced it should learn so
	// immediately rather than after the listener is up.
	keyring, err := openKeyring(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if c, ok := keyring.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}()

	st, err := openStore(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Error("store did not close cleanly", slog.Any("error", err))
		}
	}()

	if cfg.Database.AutoMigrate || *migrateOnly {
		if err := st.Migrate(ctx); err != nil {
			return fmt.Errorf("apply migrations: %w", err)
		}
	}
	if *migrateOnly {
		log.Info("migrations applied", slog.String("engine", st.Engine()))
		return nil
	}

	sealer := envelope.NewSealer(keyring)

	subjects, err := subject.New(cfg.Subject, st, sealer, time.Now)
	if err != nil {
		return fmt.Errorf("subject service: %w", err)
	}
	defer subjects.Close()

	signingKey, err := assertion.LoadPrivateKeyPEM(cfg.Assertion.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("assertion signing key: %w\n"+
			"generate one with: n0passtemps-wizard assertion-key init --out %s",
			err, cfg.Assertion.SigningKeyPath)
	}
	issuer, err := assertion.NewIssuer(signingKey, cfg.Assertion.Issuer,
		cfg.Assertion.TTL.Duration, cfg.Assertion.AllowedClockSkew.Duration)
	if err != nil {
		return fmt.Errorf("assertion issuer: %w", err)
	}

	recorder := audit.NewRecorder(st, log)
	alertEngine := alerts.New(st, log, time.Now)
	limiter := throttle.New(st, cfg.Throttle, time.Now)

	// The external audit sink, when one is configured. It is built before the
	// tenant is provisioned so that the very first entry a deployment writes is
	// offered to the witness like every other one.
	shipper, err := openAuditSink(cfg, st, alertEngine, log)
	if err != nil {
		return err
	}
	if shipper != nil {
		recorder.SetSink(shipper)
		sink := auditsink.Start(ctx, shipper)
		defer sink.Stop()
	}

	rp, err := webauthn.New(cfg.WebAuthn, st, time.Now)
	if err != nil {
		return fmt.Errorf("webauthn relying party: %w", err)
	}

	if err := ensureTenant(ctx, cfg, st, recorder, log); err != nil {
		return err
	}

	if *bootstrap {
		return bootstrapAdmin(ctx, cfg, st, recorder, *force, *admins)
	}
	warnIfNoAdministrator(ctx, cfg, st, log)

	// The keyring records no history, so the rotation reminder is anchored on
	// the age of the database rather than on when the key actually changed. It
	// errs towards reporting rotation as overdue, which is the safe direction.
	checker := health.New(cfg, st, keyring, keyringAnchor(ctx, cfg, st, log), time.Now)
	if shipper != nil {
		checker.SetAuditSinkProbe(shipper.Endpoint(), shipper.Probe)
	}

	if cfg.Audit.VerifyOnStart {
		if err := verifyChainOnStart(ctx, cfg, recorder, alertEngine, log); err != nil {
			return err
		}
	}

	adminUI, err := buildAdminUI(cfg, st, recorder, subjects, rp, limiter, log)
	if err != nil {
		return fmt.Errorf("administration interface: %w", err)
	}
	// A nil *Handler stored in an http.Handler field would be a non-nil
	// interface holding a nil pointer, and the router's check for a configured
	// interface would pass. Convert only when there is something to convert.
	var adminHandler http.Handler
	if adminUI != nil {
		adminHandler = adminUI
	}

	srv := api.NewServer(api.Deps{
		Config:    cfg,
		Store:     st,
		Subjects:  subjects,
		WebAuthn:  rp,
		Sealer:    sealer,
		Assertion: issuer,
		Recorder:  recorder,
		Alerts:    alertEngine,
		Limiter:   limiter,
		Health:    checker,
		Logger:    log,
		Clock:     time.Now,
		AdminUI:   adminHandler,
	})

	jan := janitor.New(cfg, st, recorder, alertEngine, log, time.Now)
	jan.SetKEKProbe(checker.KEKRotation)
	sweeper := janitor.Start(ctx, jan)
	defer sweeper.Stop()

	return serve(ctx, cfg, srv.Routes(), recorder, log)
}

// openKeyring loads the configured key encryption key provider.
func openKeyring(cfg *config.Config) (keyring, error) {
	switch cfg.KEK.Provider {
	case "file":
		// The data directories are passed in so the provider can refuse a key
		// that lives beside the ciphertext it protects. See docs/adr/0009.
		p, err := kek.LoadFileProvider(cfg.KEK.Path, cfg.DataDirs()...)
		if err != nil {
			return nil, fmt.Errorf("keyring: %w\n"+
				"create one with: n0passtemps-wizard kek init --out %s", err, cfg.KEK.Path)
		}
		return p, nil
	case "env":
		p, err := kek.LoadEnvProvider(cfg.KEK.EnvVar)
		if err != nil {
			return nil, fmt.Errorf("keyring: %w", err)
		}
		return p, nil
	default:
		return nil, fmt.Errorf("keyring: provider %q is not supported", cfg.KEK.Provider)
	}
}

// openAuditSink builds the external audit shipper, or reports that none is
// configured.
//
// A nil shipper and a nil error is the normal case: the sink is off unless an
// endpoint is set, and this product's argument is that it runs with no outbound
// network access at all. Every other failure stops the start, because a
// deployment that believes its audit log is being witnessed and is not would
// only find out from an alert nobody had reason to expect.
func openAuditSink(cfg *config.Config, st store.Store, al *alerts.Engine, log *slog.Logger) (*auditsink.Shipper, error) {
	shipper, err := auditsink.New(auditsink.Options{
		Config:        cfg.Audit.Sink,
		TenantID:      cfg.TenantID(),
		WatermarkPath: cfg.AuditSinkWatermarkPath(),
		Backlog:       st,
		Alerts:        al,
		Logger:        log,
		Clock:         time.Now,
	})
	switch {
	case errors.Is(err, auditsink.ErrNotConfigured):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("external audit sink: %w\n"+
			"set %sAUDIT_SINK_TOKEN, or the variable named by audit.sink.token_env, "+
			"to the credential the receiver issued", err, config.EnvPrefix)
	}
	return shipper, nil
}

// openStore connects to the configured database.
func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (store.Store, error) {
	switch cfg.Database.Driver {
	case "sqlite":
		st, err := sqlite.Open(sqlite.Options{
			DSN:             cfg.Database.DSN,
			MaxReadConns:    cfg.Database.MaxOpenConns,
			BusyTimeout:     cfg.Database.BusyTimeout.Duration,
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime.Duration,
			Logger:          log,
		})
		if err != nil {
			return nil, fmt.Errorf("open sqlite database: %w", err)
		}
		return st, nil
	case "postgres":
		st, err := postgres.Open(postgres.Options{
			DSN: cfg.Database.DSN,
			// Validate refuses a pool outside 1..config.MaxDatabaseConns, so
			// the pool size is known to fit an int32 by the time it is read.
			// #nosec G115 -- config.Validate bounds max_open_conns by config.MaxDatabaseConns (4096)
			MaxConns:        int32(cfg.Database.MaxOpenConns),
			ConnMaxLifetime: cfg.Database.ConnMaxLifetime.Duration,
			Logger:          log,
		})
		if err != nil {
			return nil, fmt.Errorf("open postgres database: %w", err)
		}
		return st, nil
	default:
		return nil, fmt.Errorf("database driver %q is not supported", cfg.Database.Driver)
	}
}

// ensureTenant provisions the single tenant a v1 deployment serves.
func ensureTenant(ctx context.Context, cfg *config.Config, st store.Store, rec *audit.Recorder, log *slog.Logger) error {
	id := cfg.TenantID()

	if _, err := st.GetTenant(ctx, id); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("read tenant %q: %w", id, err)
	}

	now := time.Now().UTC()
	t := &store.Tenant{
		ID:        id,
		Name:      cfg.Tenant.Name,
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.CreateTenant(ctx, t); err != nil {
		return fmt.Errorf("create tenant %q: %w", id, err)
	}

	log.InfoContext(ctx, "tenant provisioned", slog.String("tenant_id", id))
	if err := rec.Success(ctx, audit.Event{
		TenantID:     id,
		EventType:    audit.EventServiceStarted,
		ActorType:    store.ActorSystem,
		ResourceType: "tenant",
		ResourceID:   id,
		Detail:       map[string]any{"action": "tenant_provisioned"},
	}); err != nil {
		return fmt.Errorf("audit tenant provisioning: %w", err)
	}
	return nil
}

// verifyChainOnStart walks the audit chain before serving traffic.
//
// It is off by default because the cost is linear in the size of the log. An
// operator who turns it on wants the service to refuse to start on a broken
// chain rather than serve traffic while its own record is untrustworthy.
func verifyChainOnStart(ctx context.Context, cfg *config.Config, rec *audit.Recorder, al *alerts.Engine, log *slog.Logger) error {
	start := time.Now()
	checked, brokenAt, err := rec.Verify(ctx, cfg.TenantID(), 1)
	if err != nil {
		return fmt.Errorf("verify audit chain: %w", err)
	}

	if brokenAt != 0 {
		if _, alertErr := al.AuditChainBroken(ctx, cfg.TenantID(), brokenAt); alertErr != nil {
			log.ErrorContext(ctx, "audit chain alert not raised", slog.Any("error", alertErr))
		}
		return fmt.Errorf("the audit chain does not verify from entry %d; the log has "+
			"been altered since it was written. Investigate before serving traffic, or "+
			"set audit.verify_on_start to false to start anyway", brokenAt)
	}

	log.InfoContext(ctx, "audit chain verified",
		slog.Int64("entries", checked),
		slog.Duration("took", time.Since(start)))
	return nil
}

// serve runs the listener until the context is cancelled, then shuts down
// gracefully.
func serve(ctx context.Context, cfg *config.Config, handler http.Handler, rec *audit.Recorder, log *slog.Logger) error {
	srv := &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: handler,

		ReadTimeout:  cfg.Server.ReadTimeout.Duration,
		WriteTimeout: cfg.Server.WriteTimeout.Duration,
		IdleTimeout:  cfg.Server.IdleTimeout.Duration,

		// The defence against a client that opens a connection and dribbles
		// headers. Without it, a handful of such connections hold workers
		// open indefinitely.
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Duration,

		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	if cfg.Server.TLSCertFile != "" {
		srv.TLSConfig = &tls.Config{
			MinVersion: health.MinTLSVersion,
			// The cipher list is left to the Go standard library. It tracks
			// the current recommendations, and a hand-written list in an
			// application is a list nobody updates.
		}
	}

	if err := rec.Success(ctx, audit.Event{
		TenantID:  cfg.TenantID(),
		EventType: audit.EventServiceStarted,
		ActorType: store.ActorSystem,
		Detail: map[string]any{
			"version":   version.Current().Version,
			"addr":      cfg.Server.Addr,
			"tls":       cfg.Server.TLSCertFile != "",
			"lite_mode": cfg.Features.LiteMode,
		},
	}); err != nil {
		return fmt.Errorf("audit service start: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening",
			slog.String("addr", cfg.Server.Addr),
			slog.Bool("tls", cfg.Server.TLSCertFile != ""),
			slog.String("version", version.Current().Version))

		var err error
		if cfg.Server.TLSCertFile != "" {
			err = srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("listener: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	log.Info("shutting down", slog.Duration("grace", cfg.Server.ShutdownGrace.Duration))

	// The shutdown context is deliberately detached from the cancelled one:
	// reusing it would abort the graceful drain immediately, which is the
	// opposite of what a grace period is for.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownGrace.Duration)
	defer cancel()

	if err := rec.Success(shutdownCtx, audit.Event{
		TenantID:  cfg.TenantID(),
		EventType: audit.EventServiceStopping,
		ActorType: store.ActorSystem,
	}); err != nil {
		log.Error("shutdown not audited", slog.Any("error", err))
	}

	if err := srv.Shutdown(shutdownCtx); err != nil {
		// An in-flight ceremony that did not finish draining is dropped. The
		// challenge stays unconsumed and expires on its own, so the user
		// retries rather than ending up in an inconsistent state.
		return fmt.Errorf("shutdown did not complete within the grace period: %w", err)
	}

	log.Info("stopped")
	return nil
}
