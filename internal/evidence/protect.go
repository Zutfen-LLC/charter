package evidence

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Outcome of one destructive attempt. Only Refused counts toward qualification,
// and only when the refusal is demonstrably a protection refusal for a target
// that exists, using the credential that was meant to be tested. Anything that
// merely failed (outage, bad role, missing target, unrelated error, timeout) is
// Inconclusive: it proves nothing and can never qualify.
type Outcome string

const (
	Refused      Outcome = "REFUSED"
	Allowed      Outcome = "ALLOWED"
	Inconclusive Outcome = "INCONCLUSIVE"
)

// Attack names. Qualification requires every one of them to be Refused.
const (
	AttackRewriteEvent      = "rewrite event"
	AttackDeleteEvent       = "delete event"
	AttackRewriteObject     = "rewrite object"
	AttackDeleteObject      = "delete object"
	AttackDeleteTurn        = "delete turn"
	AttackTruncate          = "truncate"
	AttackDisableGuards     = "disable protections"
	AttackDropTable         = "drop table"
	AttackGrantSelf         = "grant self destructive privileges"
	AttackAssumeOwner       = "assume owner role"
	AttackDropSchema        = "drop evidence schema"
	AttackIndirectAuthority = "indirect evidence authority"
)

// AllAttacks is the required set.
var AllAttacks = []string{AttackRewriteEvent, AttackDeleteEvent, AttackRewriteObject, AttackDeleteObject,
	AttackDeleteTurn, AttackTruncate, AttackDisableGuards, AttackDropTable, AttackGrantSelf, AttackAssumeOwner, AttackDropSchema, AttackIndirectAuthority}

type Finding struct {
	Attack  string
	Outcome Outcome
	Detail  string
}

// Report is the result of qualifying one credential against one backend.
type Report struct {
	Prober   string
	Findings []Finding
}

// Qualified is true only if every required attack was attempted and Refused. An
// empty or partial report never qualifies, and neither does a run that used
// AsRole (a privileged connection switching roles): that checks the privilege
// layer but cannot judge whether the credential could escalate, so only a
// direct login credential can qualify.
func (r Report) Qualified() bool {
	if len(r.Findings) != len(AllAttacks) {
		return false
	}
	got := map[string]bool{}
	for _, f := range r.Findings {
		if f.Outcome != Refused || got[f.Attack] {
			return false
		}
		got[f.Attack] = true
	}
	for _, a := range AllAttacks {
		if !got[a] {
			return false
		}
	}
	return true
}

// Count returns how many findings have the given outcome.
func (r Report) Count(o Outcome) int {
	n := 0
	for _, f := range r.Findings {
		if f.Outcome == o {
			n++
		}
	}
	return n
}

func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: qualified=%v\n", r.Prober, r.Qualified())
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  %-36s %-12s %s\n", f.Attack, f.Outcome, f.Detail)
	}
	return b.String()
}

// Prober attacks one backend with one credential. Preflight must establish
// that the run is meaningful (reachable, right identity, target exists, the
// credential can do ordinary work); if it returns an error every attack is
// recorded Inconclusive and none is attempted.
type Prober interface {
	Name() string
	Preflight(ctx context.Context, tenantID, turnID, objectSHA string) error
	Attempt(ctx context.Context, attack, tenantID, turnID, objectSHA string) (Outcome, string)
}

// QualifyProtection runs the preflight, then every attack, and reports each
// outcome. It never returns a bare "no violations".
func QualifyProtection(ctx context.Context, p Prober, tenantID, turnID, objectSHA string) Report {
	rep := Report{Prober: p.Name()}
	if err := p.Preflight(ctx, tenantID, turnID, objectSHA); err != nil {
		for _, a := range AllAttacks {
			rep.Findings = append(rep.Findings, Finding{a, Inconclusive, "preflight failed: " + err.Error()})
		}
		return rep
	}
	for _, a := range AllAttacks {
		o, d := p.Attempt(ctx, a, tenantID, turnID, objectSHA)
		rep.Findings = append(rep.Findings, Finding{a, o, d})
	}
	return rep
}

// TableNames lets the harness be pointed at other tables (tests aim it at a
// deliberately unprotected copy to prove it can see an ALLOWED outcome).
type TableNames struct{ Turns, Events, Objects string }

var identRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func (t TableNames) valid() bool {
	return identRe.MatchString(t.Turns) && identRe.MatchString(t.Events) && identRe.MatchString(t.Objects)
}

// DefaultTables are the real evidence tables.
var DefaultTables = TableNames{Turns: "evidence_turns", Events: "evidence_events", Objects: "evidence_objects"}

// PGProber attacks the PostgreSQL backend over DB, which should be the ACTUAL
// runtime pool (the credential the server uses), not an owner connection that
// merely SET ROLEs. Every attempt runs in a transaction that is always rolled
// back, so a successful attack is not left behind.
type PGProber struct {
	// DB is the credential under test.
	DB *pgxpool.Pool
	// Identity is the PostgreSQL role DB must be running as (current_user). It
	// is verified, never assumed: a connection that is not who we think it is
	// would make every refusal meaningless.
	Identity string
	// AsRole, if set, additionally runs each attempt after SET LOCAL ROLE. The
	// identity check then expects AsRole. Failure to switch is Inconclusive.
	AsRole string
	// Admin is a privileged connection used only to verify that the targets
	// exist and to learn the owner role; it is never used to attack.
	Admin *pgxpool.Pool
	// Tables defaults to DefaultTables.
	Tables TableNames
	// Timeout bounds each attempt (statement_timeout). Default 5s.
	Timeout time.Duration

	scope *probeScope
}

func (p *PGProber) tables() TableNames {
	if p.Tables == (TableNames{}) {
		return DefaultTables
	}
	return p.Tables
}

func (p *PGProber) Name() string {
	who := p.Identity
	if p.AsRole != "" {
		who = p.AsRole
	}
	return "postgres/" + who
}

func (p *PGProber) expected() string {
	if p.AsRole != "" {
		return p.AsRole
	}
	return p.Identity
}

// begin opens the always-rolled-back attempt transaction and verifies identity.
func validRoleIdent(name string) bool {
	if name == "" || len(name) > 63 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (p *PGProber) begin(ctx context.Context) (pgx.Tx, error) {
	if p.DB == nil {
		return nil, errors.New("missing runtime database connection")
	}
	tx, err := p.DB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	to := p.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL statement_timeout = %d`, to.Milliseconds())); err != nil {
		_ = rollbackProbe(tx)
		return nil, fmt.Errorf("setup: %w", err)
	}
	if p.AsRole != "" {
		if !validRoleIdent(p.AsRole) {
			_ = rollbackProbe(tx)
			return nil, errors.New("invalid AsRole")
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{p.AsRole}.Sanitize()); err != nil {
			_ = rollbackProbe(tx)
			return nil, fmt.Errorf("SET ROLE %s failed: %w", p.AsRole, err)
		}
	}
	var cu, su string
	if err := tx.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&cu, &su); err != nil {
		_ = rollbackProbe(tx)
		return nil, fmt.Errorf("identity query: %w", err)
	}
	if !validRoleIdent(p.expected()) || cu != p.expected() || (p.AsRole == "" && (cu != su || su != p.DB.Config().ConnConfig.User)) {
		_ = rollbackProbe(tx)
		return nil, fmt.Errorf("credential identity is %q (session %q), expected %q", cu, su, p.expected())
	}
	return tx, nil
}

func (p *PGProber) Preflight(ctx context.Context, tenant, turn, object string) error {
	p.scope = nil
	if p.DB == nil || p.Admin == nil {
		return errors.New("prober needs the credential under test and an admin connection")
	}
	if !p.tables().valid() {
		return errors.New("invalid table names")
	}
	scope, err := p.adminScope(ctx, tenant, turn, object)
	if err != nil {
		return err
	}
	tx, err := p.begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackProbe(tx) //nolint:errcheck
	if err := scope.checkRuntime(ctx, tx); err != nil {
		return fmt.Errorf("runtime credential does not resolve the admin-verified targets: %w", err)
	}
	// Positive control on a scratch table establishes the ability to run the
	// operations in this session; arbitrary failed SQL is not a refusal.
	for _, q := range []string{`CREATE TEMP TABLE _ctl_probe(x int) ON COMMIT DROP`, `INSERT INTO _ctl_probe VALUES (1)`,
		`UPDATE _ctl_probe SET x = 2`, `DELETE FROM _ctl_probe`} {
		if tag, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("positive control failed on %q: %w", q, err)
		} else if strings.HasPrefix(q, "UPDATE") && tag.RowsAffected() != 1 {
			return errors.New("positive control matched no rows")
		}
	}
	if err := rollbackProbe(tx); err != nil {
		return err
	}
	p.scope = &scope
	return nil
}

func (p *PGProber) Attempt(ctx context.Context, attack, tenant, turn, sha string) (Outcome, string) {
	t := p.tables()
	if !t.valid() {
		return Inconclusive, "invalid table identifiers"
	}
	if p.scope == nil {
		// A standalone self-grant control may use its own verified runtime target.
		// Only a positive preflight can ever produce a full qualified report.
		if attack == AttackGrantSelf && p.Admin == nil {
			return p.grantAttempt(ctx)
		}
		return Inconclusive, "targets have not been verified by preflight"
	}
	if tenant != p.scope.tenant || turn != p.scope.turn || sha != p.scope.object {
		return Inconclusive, "attempt coordinates differ from the preflight target"
	}
	scope, err := p.adminScope(ctx, tenant, turn, sha)
	if err != nil || scope != *p.scope {
		return Inconclusive, fmt.Sprintf("preflight target changed or cannot be reverified: %v", err)
	}
	t = scope.tables()
	var sql string
	args := []any{tenant, turn, sha}
	dml := true
	switch attack {
	case AttackRewriteEvent:
		sql = fmt.Sprintf(`UPDATE %s SET body = body || ' ' WHERE tenant_id=$1::uuid AND turn_id=$2::uuid`, t.Events)
		args = args[:2]
	case AttackDeleteEvent:
		sql = fmt.Sprintf(`DELETE FROM %s WHERE tenant_id=$1::uuid AND turn_id=$2::uuid`, t.Events)
		args = args[:2]
	case AttackRewriteObject:
		sql = fmt.Sprintf(`UPDATE %s SET bytes = overlay(bytes placing '\x00'::bytea from 1 for 1) WHERE tenant_id=$1::uuid AND sha256=$2`, t.Objects)
		args = []any{tenant, sha}
	case AttackDeleteObject:
		sql = fmt.Sprintf(`DELETE FROM %s WHERE tenant_id=$1::uuid AND sha256=$2`, t.Objects)
		args = []any{tenant, sha}
	case AttackDeleteTurn:
		sql = fmt.Sprintf(`DELETE FROM %s WHERE tenant_id=$1::uuid AND turn_id=$2::uuid`, t.Turns)
		args = args[:2]
	case AttackTruncate:
		sql, args, dml = fmt.Sprintf(`TRUNCATE %s, %s, %s CASCADE`, t.Events, t.Objects, t.Turns), nil, false
	case AttackDisableGuards:
		sql, args, dml = fmt.Sprintf(`ALTER TABLE %s DISABLE TRIGGER ALL`, t.Events), nil, false
	case AttackDropTable:
		sql, args, dml = fmt.Sprintf(`DROP TABLE %s CASCADE`, t.Events), nil, false
	case AttackGrantSelf:
		// A GRANT by a non-owner only warns; the effect is what matters, so this
		// attack is judged by the privilege actually held afterwards.
		return p.grantAttempt(ctx)
	case AttackAssumeOwner:
		if p.AsRole != "" {
			// SET ROLE rights come from the SESSION user, which here is the
			// privileged connection that switched roles, so the result would say
			// nothing about the credential. Only a direct login can be judged.
			return Inconclusive, "role-switch attack is meaningless under AsRole; qualify a direct login credential"
		}
		if !validRoleIdent(scope.events.owner) {
			return Inconclusive, "owner role unknown"
		}
		sql, args, dml = `SET LOCAL ROLE `+pgx.Identifier{scope.events.owner}.Sanitize(), nil, false
	case AttackDropSchema:
		sql, args, dml = `DROP SCHEMA `+pgx.Identifier{scope.events.schema}.Sanitize()+` CASCADE`, nil, false
	case AttackIndirectAuthority:
		return p.indirectAttempt(ctx)
	default:
		return Inconclusive, "unknown attack"
	}
	tx, err := p.begin(ctx)
	if err != nil {
		return Inconclusive, err.Error()
	}
	defer rollbackProbe(tx) //nolint:errcheck
	if err := scope.checkRuntime(ctx, tx); err != nil {
		return Inconclusive, "runtime target changed: " + err.Error()
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if e := rollbackProbe(tx); e != nil {
		return Inconclusive, "transaction rollback failed: " + e.Error()
	}
	return classify(err, tag.RowsAffected(), dml)
}

func classify(err error, rows int64, dml bool) (Outcome, string) {
	if err == nil {
		if dml && rows == 0 {
			return Inconclusive, "statement succeeded but matched no rows (nothing was tested)"
		}
		return Allowed, "statement succeeded"
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch {
		case pe.Code == "42501":
			return Refused, "privilege refused: " + pe.Message
		case pe.Code == "P0001" && strings.Contains(pe.Message, "append-only evidence"):
			return Refused, "guard trigger refused: " + pe.Message
		}
		return Inconclusive, fmt.Sprintf("unrelated error %s: %s", pe.Code, pe.Message)
	}
	return Inconclusive, "non-database error: " + err.Error()
}
