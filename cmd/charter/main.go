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
	if cfg.DatabaseURL == "" {
		return errors.New("CHARTER_DATABASE_URL is required")
	}
	if cfg.EvidenceBackend != config.EvidenceBackendPostgresAppend && cfg.EvidenceBackend != config.EvidenceBackendTestFixture {
		return fmt.Errorf("unsupported CHARTER_EVIDENCE_BACKEND %q: supported are %q (and its alias %q); neither is retention-enforced",
			cfg.EvidenceBackend, config.EvidenceBackendPostgresAppend, config.EvidenceBackendTestFixture)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	applied, err := migrate.Up(ctx, pool)
	if err != nil {
		return err
	}
	log.Printf("migrations applied: %v", applied)
	if cmd == "migrate" {
		return nil
	}

	// Evidence: resolve every turn a previous run left without a terminal event
	// (explicitly marked, never replayed) BEFORE accepting any request. If this
	// fails the server refuses to start rather than serve with unresolved turns.
	rec := &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: server.StubPolicy(), Logf: log.Printf}
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
		opts = append(opts, server.WithAuth(&server.Auth{Verifier: v, Store: &store.Store{DB: pool}, Evidence: rec}))
		log.Printf("OIDC enabled: issuer=%s tenant=%s", o.Issuer, o.TenantID)
		if o.AllowInsecureLoopback {
			log.Printf("WARNING: plain-HTTP loopback IdP fixture mode enabled; never use outside local testing")
		}
	} else {
		log.Printf("OIDC not configured: only /healthz and /readyz are served (no data API)")
	}

	srv := &http.Server{Addr: cfg.Addr, Handler: server.New(pool, server.PostgresEvidenceBackend(), opts...), ReadHeaderTimeout: 5 * time.Second}
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
