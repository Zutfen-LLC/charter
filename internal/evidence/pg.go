package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PG is the PostgreSQL evidence backend. Evidence lives in its own tables
// (migration 0003), separate from every workspace/search table; protection is
// privileges plus triggers and is NOT retention-enforced storage.
type PG struct{ DB *pgxpool.Pool }

const pgKind = "postgres-append-only"

func (PG) Info() BackendInfo {
	return BackendInfo{Kind: pgKind, RetentionEnforced: false,
		Notice: "Append-only via privileges and triggers in the same PostgreSQL as the workspace; a database owner or superuser can still alter it. Not WORM, retention not enforced, not qualified for preservation."}
}

// begin opens a transaction whose commit is a durable write: it forces
// synchronous_commit on for this transaction regardless of session defaults and
// refuses to proceed if the server runs with fsync off. The level it returns is
// the one recorded in receipts.
func (b PG) begin(ctx context.Context) (pgx.Tx, string, error) {
	tx, err := b.DB.Begin(ctx)
	if err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL synchronous_commit = on`); err != nil {
		_ = tx.Rollback(ctx)
		return nil, "", err
	}
	var fsync, sc string
	if err := tx.QueryRow(ctx, `SELECT current_setting('fsync'), current_setting('synchronous_commit')`).Scan(&fsync, &sc); err != nil {
		_ = tx.Rollback(ctx)
		return nil, "", err
	}
	if fsync != "on" || sc == "off" {
		_ = tx.Rollback(ctx)
		return nil, "", fmt.Errorf("%w: fsync=%s synchronous_commit=%s", ErrNotDurable, fsync, sc)
	}
	return tx, "postgres:fsync=" + fsync + ",synchronous_commit=" + sc, nil
}

func receipt(level string, parts map[string]any) Receipt {
	parts["backend"], parts["level"] = pgKind, level
	c, _ := Canonical(parts) // only strings and safe ints: cannot fail
	return Receipt{Backend: pgKind, Level: level, ID: SHA256(c)}
}

func putObject(ctx context.Context, tx pgx.Tx, tenant string, data []byte) (string, error) {
	sha := SHA256(data)
	_, err := tx.Exec(ctx, `INSERT INTO evidence_objects(tenant_id, sha256, length, bytes)
		VALUES ($1::uuid, $2, $3, $4) ON CONFLICT (tenant_id, sha256) DO NOTHING`, tenant, sha, len(data), data)
	return sha, err
}

func (b PG) PutObject(ctx context.Context, tenant string, data []byte) (Receipt, error) {
	tx, level, err := b.begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	sha, err := putObject(ctx, tx, tenant, data)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Receipt{}, err
	}
	return receipt(level, map[string]any{"tenant_id": tenant, "object": sha, "bytes": len(data)}), nil
}

func (b PG) Admit(ctx context.Context, a Admission, first Event, objects [][]byte) (AdmitResult, error) {
	body, err := checkedBody(first)
	if err != nil {
		return AdmitResult{}, err
	}
	if str(first, "tenant_id") != a.TenantID || str(first, "turn_id") != a.TurnID || str(first, "type") != "turn_received" {
		return AdmitResult{}, errors.New("evidence: admission does not match its first event")
	}
	tx, level, err := b.begin(ctx)
	if err != nil {
		return AdmitResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var turn string
	err = tx.QueryRow(ctx, `INSERT INTO evidence_turns
		(turn_id, tenant_id, project_id, matter_id, custodian_id, idempotency_key, input_sha256)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7)
		ON CONFLICT (tenant_id, project_id, custodian_id, idempotency_key) DO NOTHING
		RETURNING turn_id::text`,
		a.TurnID, a.TenantID, a.ProjectID, a.MatterID, a.CustodianID, a.IdempotencyKey, a.InputSHA256).Scan(&turn)
	if errors.Is(err, pgx.ErrNoRows) { // key already used: an idempotent replay
		var sha string
		if err := tx.QueryRow(ctx, `SELECT turn_id::text, input_sha256 FROM evidence_turns
			WHERE tenant_id=$1::uuid AND project_id=$2::uuid AND custodian_id=$3::uuid AND idempotency_key=$4`,
			a.TenantID, a.ProjectID, a.CustodianID, a.IdempotencyKey).Scan(&turn, &sha); err != nil {
			return AdmitResult{}, err
		}
		if sha != a.InputSHA256 {
			return AdmitResult{}, ErrIdempotencyMismatch
		}
		return AdmitResult{TurnID: turn, Created: false}, nil
	}
	if err != nil {
		return AdmitResult{}, err
	}
	for _, o := range objects {
		if _, err := putObject(ctx, tx, a.TenantID, o); err != nil {
			return AdmitResult{}, err
		}
	}
	if err := insertEvent(ctx, tx, first, body); err != nil {
		return AdmitResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AdmitResult{}, err
	}
	return AdmitResult{TurnID: turn, Created: true, Receipt: eventReceipt(level, first)}, nil
}

func eventReceipt(level string, e Event) Receipt {
	return receipt(level, map[string]any{"tenant_id": str(e, "tenant_id"), "turn_id": str(e, "turn_id"),
		"seq": e["seq"], "event_hash": str(e, "event_hash")})
}

// checkedBody refuses anything that is not a correctly sealed event.
func checkedBody(e Event) ([]byte, error) {
	h, err := EventHash(e)
	if err != nil {
		return nil, err
	}
	if h != str(e, "event_hash") {
		return nil, errors.New("evidence: event is not sealed (event_hash mismatch)")
	}
	return Marshal(e)
}

func insertEvent(ctx context.Context, tx pgx.Tx, e Event, body []byte) error {
	seq, ok := integer(e["seq"])
	if !ok {
		return errors.New("evidence: event has no seq")
	}
	var prev *string
	if p, ok := e["prev_hash"].(string); ok {
		prev = &p
	}
	_, err := tx.Exec(ctx, `INSERT INTO evidence_events(turn_id, tenant_id, seq, type, prev_hash, event_hash, body)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7)`,
		str(e, "turn_id"), str(e, "tenant_id"), seq, str(e, "type"), prev, str(e, "event_hash"), string(body))
	return err
}

func (b PG) Append(ctx context.Context, e Event) (Receipt, error) {
	body, err := checkedBody(e)
	if err != nil {
		return Receipt{}, err
	}
	seq, _ := integer(e["seq"])
	tx, level, err := b.begin(ctx)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Serialize with the chain trigger and any concurrent writer of this turn.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 4001))`, str(e, "turn_id")); err != nil {
		return Receipt{}, err
	}
	var have string
	err = tx.QueryRow(ctx, `SELECT event_hash FROM evidence_events WHERE turn_id=$1::uuid AND tenant_id=$2::uuid AND seq=$3`,
		str(e, "turn_id"), str(e, "tenant_id"), seq).Scan(&have)
	switch {
	case err == nil && have == str(e, "event_hash"):
		return eventReceipt(level, e), nil // idempotent replay: already durable
	case err == nil:
		return Receipt{}, ErrConflict
	case !errors.Is(err, pgx.ErrNoRows):
		return Receipt{}, err
	}
	if err := insertEvent(ctx, tx, e, body); err != nil {
		return Receipt{}, mapChainErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Receipt{}, err
	}
	return eventReceipt(level, e), nil
}

func mapChainErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "P0001" {
		if pe.Message == "evidence chain: turn is terminal" {
			return ErrTerminal
		}
		return fmt.Errorf("%w: %s", ErrConflict, pe.Message)
	}
	return err
}

func (b PG) Load(ctx context.Context, tenant, turn string) ([]Event, error) {
	rows, err := b.DB.Query(ctx, `SELECT body FROM evidence_events
		WHERE turn_id=$1::uuid AND tenant_id=$2::uuid ORDER BY seq`, turn, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		e, err := ParseEvent([]byte(body))
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (b PG) Object(ctx context.Context, tenant, sha string) ([]byte, error) {
	var data []byte
	err := b.DB.QueryRow(ctx, `SELECT bytes FROM evidence_objects WHERE tenant_id=$1::uuid AND sha256=$2`, tenant, sha).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return data, err
}

func (b PG) OpenTurns(ctx context.Context, before time.Time) ([]TurnRef, error) {
	rows, err := b.DB.Query(ctx, `SELECT t.tenant_id::text, t.turn_id::text FROM evidence_turns t
		WHERE t.admitted_at < $1 AND NOT EXISTS (
		  SELECT 1 FROM evidence_events e WHERE e.turn_id = t.turn_id AND e.type IN ('turn_completed','turn_interrupted'))
		ORDER BY t.admitted_at`, before)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TurnRef
	for rows.Next() {
		var r TurnRef
		if err := rows.Scan(&r.TenantID, &r.TurnID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
