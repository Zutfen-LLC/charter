package evidence

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

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
	AttackRewriteEvent  = "rewrite event"
	AttackDeleteEvent   = "delete event"
	AttackRewriteObject = "rewrite object"
	AttackDeleteObject  = "delete object"
	AttackDeleteTurn    = "delete turn"
	AttackTruncate      = "truncate"
	AttackDisableGuards = "disable protections"
	AttackDropTable     = "drop table"
	AttackGrantSelf     = "grant self destructive privileges"
	AttackAssumeOwner   = "assume owner role"
)

// AllAttacks is the required set.
var AllAttacks = []string{AttackRewriteEvent, AttackDeleteEvent, AttackRewriteObject, AttackDeleteObject,
	AttackDeleteTurn, AttackTruncate, AttackDisableGuards, AttackDropTable, AttackGrantSelf, AttackAssumeOwner}

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
	got := map[string]Outcome{}
	for _, f := range r.Findings {
		got[f.Attack] = f.Outcome
	}
	for _, a := range AllAttacks {
		if got[a] != Refused {
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

	owner string
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
func (p *PGProber) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := p.DB.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	to := p.Timeout
	if to == 0 {
		to = 5 * time.Second
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL statement_timeout = %d`, to.Milliseconds())); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("setup: %w", err)
	}
	if p.AsRole != "" {
		if !identRe.MatchString(p.AsRole) {
			_ = tx.Rollback(ctx)
			return nil, errors.New("invalid AsRole")
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+p.AsRole); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("SET ROLE %s failed: %w", p.AsRole, err)
		}
	}
	var cu string
	if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&cu); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("identity query: %w", err)
	}
	if p.expected() == "" || cu != p.expected() {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("credential identity is %q, expected %q", cu, p.expected())
	}
	return tx, nil
}

func (p *PGProber) Preflight(ctx context.Context, tenant, turn, sha string) error {
	if p.DB == nil || p.Admin == nil {
		return errors.New("prober needs the credential under test and an admin connection")
	}
	t := p.tables()
	if !t.valid() {
		return errors.New("invalid table names")
	}
	// 1. the targets exist (checked with the privileged connection).
	var ev, ob, tu int
	if err := p.Admin.QueryRow(ctx, fmt.Sprintf(`SELECT
		(SELECT count(*) FROM %s WHERE tenant_id=$1::uuid AND turn_id=$2::uuid),
		(SELECT count(*) FROM %s WHERE tenant_id=$1::uuid AND sha256=$3),
		(SELECT count(*) FROM %s WHERE tenant_id=$1::uuid AND turn_id=$2::uuid)`, t.Events, t.Objects, t.Turns),
		tenant, turn, sha).Scan(&ev, &ob, &tu); err != nil {
		return fmt.Errorf("target lookup: %w", err)
	}
	if ev == 0 || ob == 0 || tu == 0 {
		return fmt.Errorf("target absent (events=%d objects=%d turns=%d)", ev, ob, tu)
	}
	if err := p.Admin.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = to_regclass($1)`, t.Events).Scan(&p.owner); err != nil || p.owner == "" {
		return fmt.Errorf("owner lookup: %v", err)
	}
	// 2. the credential is who we think it is, and 3. it can do ordinary work
	// (positive control: the same kind of statements the attacks use succeed on
	// a scratch table, so a refusal below is about the evidence, not about a
	// credential that cannot do anything).
	tx, err := p.begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	for _, q := range []string{`CREATE TEMP TABLE _ctl_probe(x int) ON COMMIT DROP`, `INSERT INTO _ctl_probe VALUES (1)`,
		`UPDATE _ctl_probe SET x = 2`, `DELETE FROM _ctl_probe`} {
		if tag, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("positive control failed on %q: %w", q, err)
		} else if strings.HasPrefix(q, "UPDATE") && tag.RowsAffected() != 1 {
			return errors.New("positive control matched no rows")
		}
	}
	return nil
}

func (p *PGProber) Attempt(ctx context.Context, attack, tenant, turn, sha string) (Outcome, string) {
	t := p.tables()
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
		if p.owner == "" || !identRe.MatchString(p.owner) {
			return Inconclusive, "owner role unknown"
		}
		sql, args, dml = `SET LOCAL ROLE `+p.owner, nil, false
	default:
		return Inconclusive, "unknown attack"
	}
	tx, err := p.begin(ctx)
	if err != nil {
		return Inconclusive, err.Error()
	}
	defer tx.Rollback(ctx) //nolint:errcheck // ALWAYS rolled back, even if the attack worked
	tag, err := tx.Exec(ctx, sql, args...)
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

func (p *PGProber) grantAttempt(ctx context.Context) (Outcome, string) {
	t := p.tables()
	who := p.expected()
	tx, err := p.begin(ctx)
	if err != nil {
		return Inconclusive, err.Error()
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// The grant may merely warn (non-owner with a grant option) or fail outright
	// (no privileges at all). Either way read the privileges actually held; a
	// savepoint keeps a failed GRANT from aborting the check that follows.
	if sp, err := tx.Begin(ctx); err == nil {
		if _, gerr := sp.Exec(ctx, fmt.Sprintf(`GRANT UPDATE, DELETE, TRUNCATE ON %s TO %s`, t.Events, who)); gerr != nil {
			_ = sp.Rollback(ctx)
		} else {
			_ = sp.Commit(ctx)
		}
	}
	var upd, del, trunc bool
	if err := tx.QueryRow(ctx, `SELECT has_table_privilege(current_user, $1, 'UPDATE'),
		has_table_privilege(current_user, $1, 'DELETE'), has_table_privilege(current_user, $1, 'TRUNCATE')`, t.Events).
		Scan(&upd, &del, &trunc); err != nil {
		return Inconclusive, "privilege query failed: " + err.Error()
	}
	if upd || del || trunc {
		return Allowed, fmt.Sprintf("privileges held after self-grant: update=%v delete=%v truncate=%v", upd, del, trunc)
	}
	return Refused, "no destructive privilege held after self-grant attempt"
}
