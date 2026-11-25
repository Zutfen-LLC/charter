// Command charter runs the control-plane API and its migrations.
//
//	charter migrate   apply pending migrations and exit
//	charter serve     migrate, then serve HTTP
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/migrate"
	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/server"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "serve" && os.Args[1] != "migrate") {
		fmt.Fprintln(os.Stderr, "usage: charter serve|migrate")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		log.Fatal(err)
	}
}

func run(cmd string) error {
	cfg := config.Load()
	if cfg.EvidenceBackend != config.EvidenceBackendPostgresAppend && cfg.EvidenceBackend != config.EvidenceBackendTestFixture {
		return fmt.Errorf("unsupported CHARTER_EVIDENCE_BACKEND %q: supported are %q (and its alias %q); neither is retention-enforced",
			cfg.EvidenceBackend, config.EvidenceBackendPostgresAppend, config.EvidenceBackendTestFixture)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cmd == "migrate" {
		return migrateOnly(ctx, cfg)
	}
	return serve(ctx, cfg)
}

// migrateOnly is the bootstrap step. It is the only place the schema-owner
// credential is used, and it exits when done: the serving process never has it.
func migrateOnly(ctx context.Context, cfg config.Config) error {
	url := cfg.MigrateDatabaseURL
	if url == "" {
		url = cfg.DatabaseURL // development fallback; production sets CHARTER_MIGRATE_DATABASE_URL
	}
	if url == "" {
		return errors.New("CHARTER_MIGRATE_DATABASE_URL (schema owner) is required for migrate")
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := migrate.Up(ctx, pool)
	if err != nil {
		return err
	}
	log.Printf("migrations applied: %v", applied)
	return nil
}

// Serving holds the runtime pools after every safety check has passed.
type Serving struct {
	Workspace, Evidence *pgxpool.Pool
}

func (s *Serving) Close() {
	if s.Workspace != nil {
		s.Workspace.Close()
	}
	if s.Evidence != nil {
		s.Evidence.Close()
	}
}

// openServing opens the two least-privilege pools and REFUSES to continue on
// unsafe configuration: migration credentials in the serving environment, a
// workspace or evidence login that is a superuser, the schema owner, a member
// of the owner role, or holds privileges it should not, or a database that is
// not fully migrated. The serving process never migrates.
func openServing(ctx context.Context, cfg config.Config) (*Serving, error) {
	if cfg.MigrateDatabaseURL != "" {
		return nil, errors.New("CHARTER_MIGRATE_DATABASE_URL is set: migration credentials must not be present in the serving process; run `charter migrate` separately")
	}
	if cfg.DatabaseURL == "" || cfg.EvidenceDatabaseURL == "" {
		return nil, errors.New("CHARTER_DATABASE_URL (workspace login) and CHARTER_EVIDENCE_DATABASE_URL (evidence login) are both required")
	}
	if cfg.DatabaseURL == cfg.EvidenceDatabaseURL {
		return nil, errors.New("the workspace and evidence logins must be different credentials")
	}
	s := &Serving{}
	var err error
	if s.Workspace, err = pgxpool.New(ctx, cfg.DatabaseURL); err != nil {
		return nil, err
	}
	if s.Evidence, err = pgxpool.New(ctx, cfg.EvidenceDatabaseURL); err != nil {
		s.Close()
		return nil, err
	}
	for _, check := range []func() error{
		func() error { return evidence.CheckWorkspaceRuntime(ctx, s.Workspace) },
		func() error { return evidence.CheckEvidenceRuntime(ctx, s.Evidence) },
		func() error {
			p, err := migrate.Pending(ctx, s.Workspace)
			if err != nil {
				return fmt.Errorf("cannot read migration state: %w", err)
			}
			if len(p) > 0 {
				return fmt.Errorf("database is not migrated (pending: %v); run `charter migrate`", p)
			}
			return nil
		},
	} {
		if err := check(); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

func serve(ctx context.Context, cfg config.Config) error {
	deps, err := openServing(ctx, cfg)
	if err != nil {
		return err
	}
	defer deps.Close()
	ev := evidence.PG{DB: deps.Evidence}
	// Single-instance fence, then recovery: every turn a previous run left
	// without a terminal event is resolved (explicitly marked, never replayed)
	// BEFORE any request is accepted. Recovery is only safe while no other live
	// instance can be mid-turn, which the fence guarantees.
	fence, err := ev.AcquireFence(ctx)
	if err != nil {
		return err
	}
	defer fence.Release()
	rec := &evidence.Recorder{Backend: ev, Policy: server.StubPolicy(), Logf: log.Printf}
	n, err := rec.Recover(ctx, time.Now())
	if err != nil {
		return fmt.Errorf("evidence recovery: %w", err)
	}
	log.Printf("evidence recovery: %d unfinished turn(s) marked turn_interrupted (crash_recovery)", n)

	var opts []server.Option
	if cfg.OIDC.Configured() {
		o := cfg.OIDC.EntraDefaults()
		v, err := buildVerifier(o)
		if err != nil {
			return err
		}
		opts = append(opts, server.WithAuth(&server.Auth{Verifier: v, Store: &store.Store{DB: deps.Workspace}, Evidence: rec}))
		log.Printf("OIDC enabled: issuer=%s tenant=%s", o.Issuer, o.TenantID)
		if o.AllowInsecureLoopback {
			log.Printf("WARNING: plain-HTTP loopback IdP fixture mode enabled; never use outside local testing")
		}
	} else {
		log.Printf("OIDC not configured: only /healthz and /readyz are served (no data API)")
	}

	srv := &http.Server{Addr: cfg.Addr, Handler: server.New(pingAll{deps.Workspace, deps.Evidence}, server.PostgresEvidenceBackend(), opts...), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("charter listening on %s (evidence: postgres-append-only, NOT retention-enforced)", cfg.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// buildVerifier validates the (default-expanded) OIDC configuration and builds
// the token verifier. Incomplete or unsafe configuration, including a missing
// delegated scope, is an error: the server then refuses to start rather than
// serving with weaker token-purpose checks.
func buildVerifier(o config.OIDC) (*oidc.Verifier, error) {
	o = o.EntraDefaults()
	if err := o.Validate(); err != nil {
		return nil, err
	}
	return oidc.NewVerifier(oidc.Config{Issuer: o.Issuer, Audience: o.Audience, TenantID: o.TenantID,
		RequiredScope: o.RequiredScope,
		Keys:          &oidc.JWKSFetcher{URL: o.JWKSURL, AllowLoopbackHTTP: o.AllowInsecureLoopback}})
}

// pingAll reports ready only if every serving pool answers.
type pingAll []*pgxpool.Pool

func (p pingAll) Ping(ctx context.Context) error {
	for _, db := range p {
		if err := db.Ping(ctx); err != nil {
			return err
		}
	}
	return nil
}
