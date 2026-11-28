// Command charter runs the control-plane API and its migrations.
//
//	charter migrate   apply pending migrations and exit
//	charter serve     check credentials, recover, then serve HTTP
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/migrate"
	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/routing"
	"github.com/Zutfen-LLC/charter/internal/server"
	"github.com/Zutfen-LLC/charter/internal/sharepoint"
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
	if cfg.EvidenceBackend != config.EvidenceBackendPostgresAppend && cfg.EvidenceBackend != config.EvidenceBackendTestFixture && cfg.EvidenceBackend != config.EvidenceBackendRetentionS3 {
		return errors.New("unsupported CHARTER_EVIDENCE_BACKEND")
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
	Workspace, Evidence, Budget *pgxpool.Pool
	qualification               qualificationStatement
}

func (s *Serving) Close() {
	if s.Budget != nil {
		s.Budget.Close()
	}
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
	openPool := pgxpool.New
	if cfg.EvidenceBackend == config.EvidenceBackendRetentionS3 {
		if err = validateSyntheticDatabases(cfg); err != nil {
			return nil, err
		}
		if err = validateLabConfig(cfg.Addr, cfg.RetentionS3); err != nil {
			return nil, err
		}
		s.qualification, err = loadQualification(ctx, cfg.RetentionS3, time.Now())
		if err != nil {
			return nil, err
		}
		openPool = func(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
			return openRetainedCoordinationPool(ctx, dsn, s.qualification)
		}
	}
	if s.Workspace, err = openPool(ctx, cfg.DatabaseURL); err != nil {
		return nil, err
	}
	if s.Evidence, err = openPool(ctx, cfg.EvidenceDatabaseURL); err != nil {
		s.Close()
		return nil, err
	}
	if cfg.BudgetDatabaseURL != "" {
		s.Budget, err = openPool(ctx, cfg.BudgetDatabaseURL)
		if err != nil {
			s.Close()
			return nil, errors.New("cannot configure budget database")
		}
		w, b := s.Workspace.Config().ConnConfig, s.Budget.Config().ConnConfig
		if w.Host != b.Host || w.Port != b.Port || w.Database != b.Database || w.RuntimeParams["search_path"] != b.RuntimeParams["search_path"] {
			s.Close()
			return nil, errors.New("budget and workspace credentials must target the same database and schema")
		}
		if err := evidence.CheckBudgetRuntime(ctx, s.Budget); err != nil {
			s.Close()
			return nil, err
		}
	} else if cfg.OIDC.Configured() {
		s.Close()
		return nil, errors.New("CHARTER_BUDGET_DATABASE_URL is required to enable the authenticated inference API")
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
	// No external SharePoint transport is enabled in the standard executable.
	return serveWithSharePoint(ctx, cfg, nil)
}

// serveWithSharePoint is the trusted composition seam; an Auth client cannot
// choose, instantiate or configure it. Synthetic retained serving refuses any
// connector other than the in-memory deterministic implementation.
func serveWithSharePoint(ctx context.Context, cfg config.Config, connector *sharepoint.Connector) error {
	if connector != nil && cfg.EvidenceBackend == config.EvidenceBackendRetentionS3 && !connector.Synthetic() {
		return errors.New("retained synthetic profile does not admit external source transports")
	}
	if cfg.EvidenceBackend == config.EvidenceBackendRetentionS3 {
		if err := validateSyntheticOIDC(cfg.OIDC); err != nil {
			return err
		}
	}
	deps, err := openServing(ctx, cfg)
	if err != nil {
		return err
	}
	defer deps.Close()
	ev := evidence.PG{DB: deps.Evidence}
	// Both ownership and drain locks are held before recovery. The recovery
	// scan and every evidence commit use the non-reconnecting owner session.
	fence, err := ev.AcquireFence(ctx)
	if err != nil {
		return err
	}
	defer fence.Release()
	var backend evidence.Backend = ev.WithFence(fence)
	info := server.PostgresEvidenceBackend()
	depsReady := readinessDeps{pingAll{deps.Workspace, deps.Evidence}}
	deployment := ""
	if cfg.EvidenceBackend == config.EvidenceBackendRetentionS3 {
		deployment = cfg.RetentionS3.Deployment
	}
	checkCtx, cancelCheck := context.WithTimeout(ctx, 15*time.Second)
	defer cancelCheck()
	if err := checkBackendBinding(checkCtx, deps.Evidence, deployment); err != nil {
		return err
	}
	if cfg.EvidenceBackend == config.EvidenceBackendRetentionS3 {
		selected, check, err := connectRetained(checkCtx, cfg.RetentionS3, deps.qualification, fence)
		if err != nil {
			return fmt.Errorf("retention storage startup refused: %w", err)
		}
		backend, info = selected, check.info()
		depsReady = append(depsReady, check)
	}
	rec := &evidence.Recorder{Backend: backend, Fence: fence, Logf: log.Printf}
	// C07 records lifecycle: control-plane store on the workspace credential,
	// authoritative backend for enumeration, and (when the deployment binds a
	// records-scoped storage credential) native legal holds and versioned
	// deletes. The guard keeps new matching work under hold protection.
	recordsService := &records.Service{Store: &records.Store{DB: deps.Workspace}, Backend: backend, Retained: cfg.EvidenceBackend == config.EvidenceBackendRetentionS3, Logf: log.Printf}
	if cfg.EvidenceBackend == config.EvidenceBackendRetentionS3 {
		if cfg.RetentionS3.RecordsAccessKey == "" || cfg.RetentionS3.RecordsSecretFile == "" {
			// Without the records transport, storage-native protection cannot
			// be established: holds fail closed (never silently effective)
			// and disposal is refused.
			log.Printf("records lifecycle: storage transport not configured; holds stay pending and disposal is refused")
		} else if rtc, err := connectRecordsTransport(ctx, cfg.RetentionS3); err != nil {
			return fmt.Errorf("records storage transport refused: %w", err)
		} else {
			recordsService.Storage = rtc
		}
	}
	rec.Lifecycle = recordsService
	ledger := evidence.PG{DB: deps.Budget}
	if deps.Budget != nil {
		modelCfg := routing.DefaultConfig()
		modelCfg.Endpoint = cfg.LocalModelURL
		retained := cfg.EvidenceBackend == config.EvidenceBackendRetentionS3
		if retained && cfg.LocalModelURL != "" {
			return errors.New("retained synthetic profile does not admit HTTP model endpoints")
		}
		rec.Governance = routing.Governance(modelCfg, ledger, retained, func() { log.Print("synthetic retention provider invoked") })
		rec.Accounting = ledger.ReconcileBudget
		depsReady = append(depsReady, deps.Budget)
	}
	n, err := rec.Recover(ctx, time.Time{})
	if err != nil {
		return fmt.Errorf("evidence recovery: %w", err)
	}
	log.Printf("evidence recovery: resolved %d unfinished turn(s)", n)
	if err := recordsService.Recover(ctx); err != nil {
		return fmt.Errorf("records lifecycle recovery: %w", err)
	}
	if deps.Budget != nil {
		if err := ledger.RecoverBudget(ctx, backend); err != nil {
			return fmt.Errorf("budget recovery: %w", err)
		}
	}

	var opts []server.Option
	if cfg.OIDC.Configured() {
		o := cfg.OIDC.EntraDefaults()
		v, err := buildVerifier(o)
		if err != nil {
			return err
		}
		auth := &server.Auth{Verifier: v, Store: &store.Store{DB: deps.Workspace}, Evidence: rec, Budget: ledger.Summary, SharePoint: connector, Records: recordsService}
		if retained, ok := backend.(*evidence.RetentionBackend); ok && recordsService.Storage != nil {
			auth.Exports = &server.RetainedExports{Records: recordsService, Backend: retained}
		}
		opts = append(opts, server.WithAuth(auth))
		log.Printf("OIDC enabled: issuer=%s tenant=%s", o.Issuer, o.TenantID)
		if o.AllowInsecureLoopback {
			log.Printf("WARNING: plain-HTTP loopback IdP fixture mode enabled; never use outside local testing")
		}
	} else {
		log.Printf("OIDC not configured: only /healthz and /readyz are served (no data API)")
	}

	handler := server.New(depsReady, info, opts...)
	if recordsService.Retained {
		maintenance, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			tick := time.NewTicker(time.Minute)
			defer tick.Stop()
			for maintenance.Err() == nil {
				pass, cancel := context.WithTimeout(maintenance, 10*time.Second)
				if err := recordsService.Store.ReconcileDueExports(pass); err != nil && maintenance.Err() == nil {
					log.Print("export custody maintenance: reconciliation unavailable")
				}
				cancel()
				select {
				case <-maintenance.Done():
				case <-tick.C:
				}
			}
		}()
		defer func() { stop(); <-done }()
	}
	log.Printf("charter evidence backend: kind=%s retention_enforced=%t scope=%s", info.Kind, info.RetentionEnforced, info.RetentionStatus)
	return serveFencedHTTP(ctx, cfg.Addr, fence, handler)
}

// serveFencedHTTP stops accepting connections immediately on shutdown or on
// detected ownership loss. It joins handlers before its caller releases the
// ownership and drain locks. Closing the listener alone does not join them.
func serveFencedHTTP(ctx context.Context, addr string, fence *evidence.Fence, handler http.Handler) error {
	if err := fence.Check(ctx); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	handlerCtx, cancelHandlers := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelHandlers()
	monitorCtx, cancelMonitor := context.WithCancel(context.Background())
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		fence.Monitor(monitorCtx)
	}()
	defer func() { cancelMonitor(); <-monitorDone }()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := fence.Check(r.Context()); err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			handler.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 5 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return handlerCtx },
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(listener) }()
	log.Printf("charter listening on %s", listener.Addr())
	select {
	case <-ctx.Done():
	case <-fence.Lost():
		err = evidence.ErrFenceLost
	case e := <-serveErr:
		if !errors.Is(e, http.ErrServerClosed) {
			err = e
		}
	}
	cancelHandlers()
	// Do not release the locks on a timer while a non-cooperative handler is
	// still active. An operator can forcibly terminate a stuck process.
	if shutErr := srv.Shutdown(context.Background()); err == nil {
		err = shutErr
	}
	select {
	case <-fence.Lost():
		if err == nil {
			err = evidence.ErrFenceLost
		}
	default:
	}
	return err
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
