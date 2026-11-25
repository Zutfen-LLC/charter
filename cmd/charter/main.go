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
	if cfg.EvidenceBackend != config.EvidenceBackendTestFixture {
		return fmt.Errorf("unsupported CHARTER_EVIDENCE_BACKEND %q: only %q exists in the pilot scaffold",
			cfg.EvidenceBackend, config.EvidenceBackendTestFixture)
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

	var opts []server.Option
	if cfg.OIDC.Configured() {
		o := cfg.OIDC.EntraDefaults()
		if o.Issuer == "" || o.Audience == "" || o.TenantID == "" || o.JWKSURL == "" {
			return errors.New("incomplete OIDC config: need CHARTER_OIDC_TENANT_ID and CHARTER_OIDC_AUDIENCE (Entra defaults for issuer and JWKS URL), or all four CHARTER_OIDC_* values")
		}
		v, err := oidc.NewVerifier(oidc.Config{Issuer: o.Issuer, Audience: o.Audience, TenantID: o.TenantID,
			Keys: &oidc.JWKSFetcher{URL: o.JWKSURL}})
		if err != nil {
			return err
		}
		opts = append(opts, server.WithAuth(&server.Auth{Verifier: v, Store: &store.Store{DB: pool}}))
		log.Printf("OIDC enabled: issuer=%s tenant=%s", o.Issuer, o.TenantID)
	} else {
		log.Printf("OIDC not configured: only /healthz and /readyz are served (no data API)")
	}

	srv := &http.Server{Addr: cfg.Addr, Handler: server.New(pool, server.TestFixtureBackend(), opts...), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("charter listening on %s (TEST EVIDENCE BACKEND: not retention-enforced)", cfg.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
