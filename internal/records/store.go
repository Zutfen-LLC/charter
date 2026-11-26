package records

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// canonP canonicalizes a principal like store's unexported canon: every
// lifecycle operation refuses a malformed id spelling fail-closed.
func canonP(p store.Principal) (store.Principal, bool) {
	u, ok1 := store.CanonicalID(p.UserID)
	t, ok2 := store.CanonicalID(p.TenantID)
	if !ok1 || !ok2 {
		return p, false
	}
	p.UserID, p.TenantID = u, t
	return p, true
}

var (
	ErrForbidden      = store.ErrForbidden
	ErrNotFound       = store.ErrNotFound
	ErrConflict       = errors.New("records: conflicting lifecycle state")
	ErrRetry          = errors.New("records: retry the lifecycle operation")
	ErrBlockedStorage = errors.New("records: disposal blocked by storage protection")
)

// StoreHooks are deterministic synchronization barriers for the concurrency
// tests: they fire inside the lifecycle transaction, while its locks are
// held, so a test can freeze one operation at an exact point and let a racing
// operation commit (or block) around it. Production leaves them nil.
type StoreHooks struct {
	// AtEpochLock fires just after the matter epoch row is locked.
	AtEpochLock func(stage, tenantID, matterID string)
	// AtItemLock fires just after a retention item row is locked.
	AtItemLock func(stage, tenantID, turnID string)
}

// Store is the PostgreSQL lifecycle store. All mutations follow the
// administrative protocol of internal/store: one transaction, the tenant row
// locked first, the actor's records role re-verified from committed state
// inside the lock, then the invariant checks and the mutation with its audit
// row in the same transaction.
type Store struct {
	DB    *pgxpool.Pool
	Hooks StoreHooks
}

func (s *Store) hookEpoch(stage, tenantID, matterID string) {
	if s.Hooks.AtEpochLock != nil {
		s.Hooks.AtEpochLock(stage, tenantID, matterID)
	}
}

func (s *Store) hookItem(stage, tenantID, turnID string) {
	if s.Hooks.AtItemLock != nil {
		s.Hooks.AtItemLock(stage, tenantID, turnID)
	}
}

// audit writes one append-only audit_log row inside the caller's transaction.
// A nil actor records a service-initiated action (recovery, reconciliation).
func audit(ctx context.Context, tx pgx.Tx, tenantID string, actorID *string, action string, detail any) error {
	b, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO audit_log(tenant_id, actor_id, action, detail) VALUES ($1,$2,$3,$4)`, tenantID, actorID, action, b)
	return err
}

// beginTx opens a transaction, locks the tenant row and re-verifies the actor
// is an active records_officer (or tenant_admin for the roles named in allow).
func (s *Store) beginTx(ctx context.Context, p store.Principal, role string, fn func(pgx.Tx) error) error {
	p, ok := canonP(p)
	if !ok {
		return ErrForbidden
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var locked bool
	if err := tx.QueryRow(ctx, `SELECT true FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, p.TenantID).Scan(&locked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrForbidden
		}
		return err
	}
	var ok2 bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_roles r JOIN users u ON u.id=r.user_id AND u.tenant_id=r.tenant_id
		WHERE r.user_id=$1 AND r.tenant_id=$2 AND r.role=$3 AND u.disabled_at IS NULL)`, p.UserID, p.TenantID, role).Scan(&ok2); err != nil {
		return err
	}
	if !ok2 {
		return ErrForbidden
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// lockEpoch inserts the matter's epoch row if absent and returns the current
// epoch with the row LOCKED FOR UPDATE (via the UPDATE). Callers hold this
// lock across every irreversible storage operation; hold placement and
// release take the next epoch under the same lock, which is the ADR 0001
// conditional-delete fence.
func lockEpoch(ctx context.Context, tx pgx.Tx, tenantID, matterID string, bump bool) (int64, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO matter_hold_epochs(tenant_id, matter_id, epoch) VALUES ($1,$2,0)
		ON CONFLICT (tenant_id, matter_id) DO NOTHING`, tenantID, matterID); err != nil {
		return 0, err
	}
	if bump {
		var e int64
		if err := tx.QueryRow(ctx, `UPDATE matter_hold_epochs SET epoch = epoch + 1 WHERE tenant_id=$1 AND matter_id=$2 RETURNING epoch`, tenantID, matterID).Scan(&e); err != nil {
			return 0, err
		}
		return e, nil
	}
	var e int64
	if err := tx.QueryRow(ctx, `SELECT epoch FROM matter_hold_epochs WHERE tenant_id=$1 AND matter_id=$2 FOR UPDATE`, tenantID, matterID).Scan(&e); err != nil {
		return 0, err
	}
	return e, nil
}

// ActiveHolds loads every hold of the tenant whose state still fences
// disposal (pending, effective or failed) for one matter, with custodian
// scope. Matching itself is done in Go with the ADR predicate so the Go, the
// Python reference model and the fixtures cannot drift apart.
func ActiveHolds(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, tenantID, matterID string) ([]*Hold, error) {
	rows, err := q.Query(ctx, `SELECT h.id::text, h.tenant_id::text, h.matter_id::text, h.state, h.epoch,
		h.window_start, h.window_end, h.reason, h.placed_by::text, h.placed_at,
		COALESCE(array_agg(hc.custodian_id::text) FILTER (WHERE hc.custodian_id IS NOT NULL), '{}')
		FROM holds h LEFT JOIN hold_custodians hc ON hc.hold_id = h.id
		WHERE h.tenant_id=$1 AND h.matter_id=$2 AND h.state IN ('pending','effective','failed')
		GROUP BY h.id, h.tenant_id, h.matter_id, h.state, h.epoch, h.window_start, h.window_end, h.reason, h.placed_by, h.placed_at
		ORDER BY h.epoch`, tenantID, matterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Hold
	for rows.Next() {
		h := &Hold{}
		var custodians []string
		if err := rows.Scan(&h.ID, &h.TenantID, &h.MatterID, &h.State, &h.Epoch, &h.WindowStart, &h.WindowEnd, &h.Reason, &h.PlacedBy, &h.PlacedAt, &custodians); err != nil {
			return nil, err
		}
		h.CustodianIDs = custodians
		out = append(out, h)
	}
	return out, rows.Err()
}

// Held reports whether an item is held (ADR: derived, never stamped).
func Held(holds []*Hold, matterID, custodianID string, recordedAt time.Time) bool {
	for _, h := range holds {
		if Matches(h, matterID, custodianID, recordedAt) {
			return true
		}
	}
	return false
}

// PlaceHold commits the hold's epoch and durable record (state pending) and
// restores matching disposal_pending/purging items to active. It returns the
// created-or-existing hold; protection establishment is a separate phase
// (Establishment) so the two-phase ADR ordering is explicit: the epoch commit
// is the acknowledgment boundary that fences disposal, and effective is
// acknowledged only after protection is verified.
func (s *Store) PlaceHold(ctx context.Context, p store.Principal, scope Scope, reason, idempotencyKey string) (*Hold, error) {
	p, ok := canonP(p)
	if !ok {
		return nil, ErrForbidden
	}
	if reason == "" || len(reason) > 2000 || idempotencyKey == "" || len(idempotencyKey) > 128 {
		return nil, ErrNotFound
	}
	matterID, valid := store.CanonicalID(scope.MatterID)
	if !valid {
		return nil, ErrNotFound
	}
	var custodians []string
	for _, c := range scope.CustodianIDs {
		id, okc := store.CanonicalID(c)
		if !okc {
			return nil, ErrNotFound
		}
		custodians = append(custodians, id)
	}
	if err := validateScope(ctx, s.DB, p, matterID, custodians); err != nil {
		return nil, err
	}
	created := &Hold{}
	err := s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		// Idempotent retry: the same officer key returns the durable hold
		// with its current state; it never places a second hold.
		var existing string
		err := tx.QueryRow(ctx, `SELECT id::text FROM holds WHERE tenant_id=$1 AND idempotency_key=$2`, p.TenantID, idempotencyKey).Scan(&existing)
		if err == nil {
			h, herr := loadHold(ctx, tx, existing)
			if herr != nil {
				return herr
			}
			*created = *h
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		epoch, err := lockEpoch(ctx, tx, p.TenantID, matterID, true)
		if err != nil {
			return err
		}
		s.hookEpoch("place", p.TenantID, matterID)
		id, err := newHoldID(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO holds(id, tenant_id, matter_id, reason, window_start, window_end, state, epoch, placed_by, idempotency_key, report)
			VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9,'{}'::jsonb)`,
			id, p.TenantID, matterID, reason, scope.WindowStart, scope.WindowEnd, epoch, p.UserID, idempotencyKey); err != nil {
			var pk *pgconn.PgError
			if errors.As(err, &pk) && pk.Code == "23505" {
				// A concurrent placement with the same idempotency key won
				// the unique race (it committed while this transaction was
				// waiting on the epoch row): return the durable winner.
				h, herr := loadHoldByIdempotency(ctx, tx, p.TenantID, idempotencyKey)
				if herr != nil {
					return herr
				}
				*created = *h
				return nil
			}
			return err
		}
		for _, c := range custodians {
			if _, err := tx.Exec(ctx, `INSERT INTO hold_custodians(hold_id, tenant_id, custodian_id) VALUES ($1,$2,$3)`, id, p.TenantID, c); err != nil {
				return err
			}
		}
		// Hold wins over an in-flight disposal: MATCHING pending/purging
		// items return to active in the same transaction that commits the
		// epoch (state machines cases B and F). The custodian and window
		// predicates mirror ADR matching so an unrelated scoped hold bumps
		// the epoch without restoring anything it does not cover.
		tag, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL
			WHERE tenant_id=$1 AND matter_id=$2 AND state IN ('disposal_pending','purging')
			AND ($3::uuid[] IS NULL OR custodian_id = ANY($3))
			AND ($4::timestamptz IS NULL OR recorded_at >= $4)
			AND ($5::timestamptz IS NULL OR recorded_at < $5)`,
			p.TenantID, matterID, custodianSlice(custodians), scope.WindowStart, scope.WindowEnd)
		if err != nil {
			return err
		}
		// Items already disposed are a recorded gap, never a silent miss.
		var gapCount int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM retention_items WHERE tenant_id=$1 AND matter_id=$2 AND state='disposed'`, p.TenantID, matterID).Scan(&gapCount); err != nil {
			return err
		}
		if err := audit(ctx, tx, p.TenantID, &p.UserID, "hold.place", map[string]any{
			"hold_id": id, "matter_id": matterID, "custodian_ids": custodians,
			"epoch": epoch, "reason": reason, "restored_items": tag.RowsAffected(), "disposed_items_in_matter": gapCount,
		}); err != nil {
			return err
		}
		h, herr := loadHold(ctx, tx, id)
		if herr != nil {
			return herr
		}
		*created = *h
		return nil
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// validateScope fails closed on cross-tenant identifiers: the matter must map
// to a project of the caller's tenant and every custodian must be a user of
// that tenant. A matter or custodian that only exists in another tenant is
// refused like a nonexistent one.
func validateScope(ctx context.Context, db *pgxpool.Pool, p store.Principal, matterID string, custodians []string) error {
	var ok bool
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE tenant_id=$1 AND matter_id=$2)`, p.TenantID, matterID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	for _, c := range custodians {
		if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2)`, p.TenantID, c).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
	}
	return nil
}

// custodianSlice maps an empty (all custodians) scope to SQL NULL.
func custodianSlice(custodians []string) []string {
	if len(custodians) == 0 {
		return nil
	}
	return custodians
}

func loadHoldByIdempotency(ctx context.Context, tx pgx.Tx, tenantID, key string) (*Hold, error) {
	var id string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM holds WHERE tenant_id=$1 AND idempotency_key=$2`, tenantID, key).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return loadHold(ctx, tx, id)
}

func newHoldID(ctx context.Context, tx pgx.Tx) (string, error) {
	var id string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}

func loadHold(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, id string) (*Hold, error) {
	h := &Hold{}
	var report []byte
	err := q.QueryRow(ctx, `SELECT id::text, tenant_id::text, matter_id::text, reason, window_start, window_end, state, epoch,
		release_epoch, placed_by::text, placed_at, effective_at, released_by::text, released_at, release_reason, idempotency_key, report
		FROM holds WHERE id=$1`, id).
		Scan(&h.ID, &h.TenantID, &h.MatterID, &h.Reason, &h.WindowStart, &h.WindowEnd, &h.State, &h.Epoch,
			&h.ReleaseEpoch, &h.PlacedBy, &h.PlacedAt, &h.EffectiveAt, &h.ReleasedBy, &h.ReleasedAt, &h.ReleaseReason, &h.IdempotencyKey, &report)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(report, &h.Report); err != nil {
		return nil, fmt.Errorf("records: hold report: %w", err)
	}
	rows, err := q.Query(ctx, `SELECT custodian_id::text FROM hold_custodians WHERE hold_id=$1 ORDER BY custodian_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	h.CustodianIDs = nil
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		h.CustodianIDs = append(h.CustodianIDs, c)
	}
	return h, rows.Err()
}

// GetHold loads one hold of the tenant.
func (s *Store) GetHold(ctx context.Context, p store.Principal, id string) (*Hold, error) {
	p, ok := canonP(p)
	id, valid := store.CanonicalID(id)
	if !ok || !valid {
		return nil, ErrNotFound
	}
	h, err := loadHold(ctx, s.DB, id)
	if err != nil {
		return nil, err
	}
	if h.TenantID != p.TenantID {
		return nil, ErrNotFound
	}
	return h, nil
}

// ListHolds lists the tenant's holds, most recent first.
func (s *Store) ListHolds(ctx context.Context, p store.Principal) ([]*Hold, error) {
	p, ok := canonP(p)
	if !ok {
		return nil, ErrForbidden
	}
	rows, err := s.DB.Query(ctx, `SELECT id::text FROM holds WHERE tenant_id=$1 ORDER BY placed_at DESC, id`, p.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*Hold, 0, len(ids))
	for _, id := range ids {
		h, err := loadHold(ctx, s.DB, id)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// MarkEffective records verified protection (separate phase of placement).
func (s *Store) MarkEffective(ctx context.Context, holdID string, report Report) error {
	return s.writeHoldState(context.Background(), holdID, func(tx pgx.Tx) error {
		b, err := json.Marshal(report)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE holds SET state='effective', effective_at=now(), report=$2
			WHERE id=$1 AND state IN ('pending','failed')`, holdID, b)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			// Idempotent completion: a concurrent placement of the SAME
			// idempotency key already established and verified protection.
			// A released hold can never become effective again.
			var state string
			if err := tx.QueryRow(ctx, `SELECT state FROM holds WHERE id=$1`, holdID).Scan(&state); err != nil {
				return err
			}
			if state != HoldEffective {
				return ErrConflict
			}
		}
		return audit(ctx, tx, holdTenant(ctx, tx, holdID), nil, "hold.effective", map[string]any{"hold_id": holdID, "items": len(report.Items), "uncovered": len(report.Uncovered)})
	})
}

// MarkFailed records a failed establishment (retryable; the fence stands).
func (s *Store) MarkFailed(ctx context.Context, holdID string, report Report, detail string) error {
	return s.writeHoldState(context.Background(), holdID, func(tx pgx.Tx) error {
		report.Error = detail
		b, err := json.Marshal(report)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE holds SET state='failed', report=$2 WHERE id=$1 AND state IN ('pending','failed')`, holdID, b)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			var state string
			if err := tx.QueryRow(ctx, `SELECT state FROM holds WHERE id=$1`, holdID).Scan(&state); err != nil {
				return err
			}
			if state != HoldFailed {
				return ErrConflict
			}
		}
		return audit(ctx, tx, holdTenant(ctx, tx, holdID), nil, "hold.establishment_failed", map[string]any{"hold_id": holdID, "detail": detail})
	})
}

func (s *Store) writeHoldState(ctx context.Context, holdID string, fn func(pgx.Tx) error) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func holdTenant(ctx context.Context, tx pgx.Tx, holdID string) string {
	var t string
	_ = tx.QueryRow(ctx, `SELECT tenant_id::text FROM holds WHERE id=$1`, holdID).Scan(&t)
	return t
}

// ReleaseHold removes only this hold's claim: the epoch is bumped and the
// state becomes released in one transaction, so any disposal that observes
// the new epoch no longer counts this hold, while evidence protected by other
// active holds stays held (overlapping-hold rule). Storage cleanup (clearing
// legal holds no longer needed) is a separate, conservative phase.
func (s *Store) ReleaseHold(ctx context.Context, p store.Principal, holdID, reason string) (*Hold, error) {
	p, ok := canonP(p)
	holdID, valid := store.CanonicalID(holdID)
	if !ok || !valid {
		return nil, ErrNotFound
	}
	released := &Hold{}
	err := s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		h, err := loadHold(ctx, tx, holdID)
		if err != nil {
			return err
		}
		if h.TenantID != p.TenantID {
			return ErrNotFound
		}
		if h.State == HoldReleased {
			// Idempotent release: return the durable outcome.
			*released = *h
			return nil
		}
		if h.State != HoldEffective && h.State != HoldPending && h.State != HoldFailed {
			return ErrConflict
		}
		epoch, err := lockEpoch(ctx, tx, p.TenantID, h.MatterID, true)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE holds SET state='released', release_epoch=$2, released_by=$3, released_at=now(), release_reason=$4 WHERE id=$1 AND state <> 'released'`,
			holdID, epoch, p.UserID, reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		if err := audit(ctx, tx, p.TenantID, &p.UserID, "hold.release", map[string]any{
			"hold_id": holdID, "matter_id": h.MatterID, "epoch": epoch, "reason": reason,
		}); err != nil {
			return err
		}
		out, err := loadHold(ctx, tx, holdID)
		if err != nil {
			return err
		}
		*released = *out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return released, nil
}

// ChangeScope rewrites the hold's scope under a new epoch. Widening protects
// newly in-scope turns; narrowing never removes protection still required by
// the remaining scope or by any other hold (the release-cleanup phase
// reference-counts before clearing any legal hold).
func (s *Store) ChangeScope(ctx context.Context, p store.Principal, holdID string, scope Scope, reason string) (*Hold, error) {
	p, ok := canonP(p)
	holdID, valid := store.CanonicalID(holdID)
	if !ok || !valid || reason == "" {
		return nil, ErrNotFound
	}
	if scope.MatterID != "" {
		// The matter of a hold is immutable: a scope change naming another
		// matter is a substitution attempt and fails closed.
		if m, valid := store.CanonicalID(scope.MatterID); !valid {
			return nil, ErrNotFound
		} else if holdOf, err := s.GetHold(ctx, p, holdID); err != nil {
			return nil, err
		} else if m != holdOf.MatterID {
			return nil, ErrNotFound
		}
	}
	changed := &Hold{}
	err := s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		h, err := loadHold(ctx, tx, holdID)
		if err != nil {
			return err
		}
		if h.TenantID != p.TenantID || h.State == HoldReleased {
			return ErrNotFound
		}
		epoch, err := lockEpoch(ctx, tx, p.TenantID, h.MatterID, true)
		if err != nil {
			return err
		}
		var custodians []string
		for _, c := range scope.CustodianIDs {
			id, okc := store.CanonicalID(c)
			if !okc {
				return ErrNotFound
			}
			custodians = append(custodians, id)
		}
		for _, c := range custodians {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE tenant_id=$1 AND id=$2)`, p.TenantID, c).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE holds SET window_start=$2, window_end=$3, reason=reason || E'\n' || $4 WHERE id=$1`,
			holdID, scope.WindowStart, scope.WindowEnd, reason); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM hold_custodians WHERE hold_id=$1`, holdID); err != nil {
			return err
		}
		for _, c := range custodians {
			if _, err := tx.Exec(ctx, `INSERT INTO hold_custodians(hold_id, tenant_id, custodian_id) VALUES ($1,$2,$3)`, holdID, p.TenantID, c); err != nil {
				return err
			}
		}
		// A widened scope restores matching pending/purging items; a narrowed
		// one leaves protection removal to the conservative cleanup phase.
		if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL
			WHERE tenant_id=$1 AND matter_id=$2 AND state IN ('disposal_pending','purging')
			AND ($3::uuid[] IS NULL OR custodian_id = ANY($3))
			AND ($4::timestamptz IS NULL OR recorded_at >= $4)
			AND ($5::timestamptz IS NULL OR recorded_at < $5)`,
			p.TenantID, h.MatterID, custodianSlice(custodians), scope.WindowStart, scope.WindowEnd); err != nil {
			return err
		}
		// The changed hold needs establishment again before it may report
		// effective for the new scope.
		if _, err := tx.Exec(ctx, `UPDATE holds SET state='pending' WHERE id=$1 AND state='effective'`, holdID); err != nil {
			return err
		}
		if err := audit(ctx, tx, p.TenantID, &p.UserID, "hold.change", map[string]any{
			"hold_id": holdID, "epoch": epoch, "custodian_ids": custodians, "reason": reason,
		}); err != nil {
			return err
		}
		out, err := loadHold(ctx, tx, holdID)
		if err != nil {
			return err
		}
		*changed = *out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return changed, nil
}

// Item is one retention lifecycle catalog row.
type Item struct {
	TenantID, TurnID, MatterID, ProjectID, CustodianID string
	RecordedAt, ExpiresAt                              time.Time
	State                                              string
	ObservedEpoch                                      *int64
	PendingSince                                       *time.Time
	SweepBy, PurgeBy                                   *string
	TombstonedAt, PurgedAt                             *time.Time
}

// SweepPolicy is the tenant's retention configuration.
type SweepPolicy struct {
	RetentionSeconds int64
	GraceSeconds     int64
}

const (
	defaultRetentionSeconds = 90 * 24 * 3600
	defaultGraceSeconds     = 7 * 24 * 3600
)

// Policy loads the tenant's retention policy with synthetic-drill defaults.
func (s *Store) Policy(ctx context.Context, tenantID string) (SweepPolicy, error) {
	var r, g *int64
	err := s.DB.QueryRow(ctx, `SELECT retention_seconds, grace_seconds FROM retention_policies WHERE tenant_id=$1`, tenantID).Scan(&r, &g)
	if errors.Is(err, pgx.ErrNoRows) {
		return SweepPolicy{RetentionSeconds: defaultRetentionSeconds, GraceSeconds: defaultGraceSeconds}, nil
	}
	if err != nil {
		return SweepPolicy{}, err
	}
	p := SweepPolicy{RetentionSeconds: defaultRetentionSeconds, GraceSeconds: defaultGraceSeconds}
	if r != nil && *r >= 1 {
		p.RetentionSeconds = *r
	}
	if g != nil && *g >= 0 {
		p.GraceSeconds = *g
	}
	return p, nil
}

// SetPolicy installs the tenant retention policy (records officer).
func (s *Store) SetPolicy(ctx context.Context, p store.Principal, retentionSeconds, graceSeconds int64) error {
	if retentionSeconds < 1 || graceSeconds < 0 {
		return ErrNotFound
	}
	return s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO retention_policies(tenant_id, retention_seconds, grace_seconds, set_by)
			VALUES ($1,$2,$3,$4) ON CONFLICT (tenant_id) DO UPDATE SET retention_seconds=$2, grace_seconds=$3, set_by=$4, set_at=now()`,
			p.TenantID, retentionSeconds, graceSeconds, p.UserID); err != nil {
			return err
		}
		return audit(ctx, tx, p.TenantID, &p.UserID, "retention.policy", map[string]any{"retention_seconds": retentionSeconds, "grace_seconds": graceSeconds})
	})
}

// CatalogTurn upserts one turn into the lifecycle catalog from the
// authoritative backend identity (never from workspace tables). The first
// sighting fixes retention_expires_at from the then-current policy.
func (s *Store) CatalogTurn(ctx context.Context, tenantID string, t evidence.TurnIdentity, policy SweepPolicy) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO retention_items(tenant_id, turn_id, matter_id, project_id, custodian_id, recorded_at, retention_expires_at, state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'active') ON CONFLICT (tenant_id, turn_id) DO NOTHING`,
		tenantID, t.TurnID, t.MatterID, t.ProjectID, t.CustodianID, t.RecordedAt, t.RecordedAt.Add(time.Duration(policy.RetentionSeconds)*time.Second))
	return err
}

// Sweep marks eligible items disposal_pending: retention expired AND not
// held, per matter epoch observed under the same lock. It returns the number
// newly marked. Concurrent sweeps are idempotent (only active items move).
func (s *Store) Sweep(ctx context.Context, p store.Principal, turns []evidence.TurnIdentity, policy SweepPolicy) (int, error) {
	p, ok := canonP(p)
	if !ok {
		return 0, ErrForbidden
	}
	now := time.Now()
	marked := 0
	for _, t := range turns {
		if err := s.CatalogTurn(ctx, p.TenantID, t, policy); err != nil {
			return marked, err
		}
		err := s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
			var state string
			var expires time.Time
			if err := tx.QueryRow(ctx, `SELECT state, retention_expires_at FROM retention_items WHERE tenant_id=$1 AND turn_id=$2 FOR UPDATE`,
				p.TenantID, t.TurnID).Scan(&state, &expires); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return nil
				}
				return err
			}
			if state != ItemActive || now.Before(expires) {
				return nil
			}
			s.hookItem("sweep", p.TenantID, t.TurnID)
			epoch, err := lockEpoch(ctx, tx, p.TenantID, t.MatterID, false)
			if err != nil {
				return err
			}
			s.hookEpoch("sweep", p.TenantID, t.MatterID)
			holds, err := ActiveHolds(ctx, tx, p.TenantID, t.MatterID)
			if err != nil {
				return err
			}
			if Held(holds, t.MatterID, t.CustodianID, t.RecordedAt) {
				return nil
			}
			if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposal_pending', observed_epoch=$3, pending_since=$4, sweep_by=$5
				WHERE tenant_id=$1 AND turn_id=$2 AND state='active'`, p.TenantID, t.TurnID, epoch, now, p.UserID); err != nil {
				return err
			}
			marked++
			return audit(ctx, tx, p.TenantID, &p.UserID, "retention.sweep", map[string]any{"turn_id": t.TurnID, "matter_id": t.MatterID, "observed_epoch": epoch})
		})
		if err != nil {
			return marked, err
		}
	}
	return marked, nil
}

// Items lists the tenant's lifecycle catalog (records metadata only). The
// HTTP layer authorizes records officers; this read is tenant-scoped by the
// caller's canonical tenant id.
func (s *Store) Items(ctx context.Context, p store.Principal) ([]Item, error) {
	tenantID, valid := store.CanonicalID(p.TenantID)
	if !valid {
		return nil, ErrForbidden
	}
	return s.itemsOfTenant(ctx, tenantID)
}

func (s *Store) itemsOfTenant(ctx context.Context, tenantID string) ([]Item, error) {
	rows, err := s.DB.Query(ctx, `SELECT tenant_id::text, turn_id::text, matter_id::text, project_id::text, custodian_id::text,
		recorded_at, retention_expires_at, state, observed_epoch, pending_since, sweep_by::text, purge_by::text, tombstoned_at, purged_at
		FROM retention_items WHERE tenant_id=$1 ORDER BY recorded_at, turn_id`, tenantID)
	return scanItems(rows, err)
}

func scanItems(rows pgx.Rows, err error) ([]Item, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.TenantID, &it.TurnID, &it.MatterID, &it.ProjectID, &it.CustodianID,
			&it.RecordedAt, &it.ExpiresAt, &it.State, &it.ObservedEpoch, &it.PendingSince, &it.SweepBy, &it.PurgeBy, &it.TombstonedAt, &it.PurgedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// BeginPurge is the tombstoning half of disposal: re-evaluates holds under
// the matter epoch, marks the item purging (unreadable; bytes retained) with
// the epoch it observed, and requires a records officer OTHER than the one
// whose sweep requested disposal (separation of duties).
func (s *Store) BeginPurge(ctx context.Context, p store.Principal, turnID string, verifyBytes func(context.Context, string) (bool, error)) (string, error) {
	p, ok := canonP(p)
	turnID, valid := store.CanonicalID(turnID)
	if !ok || !valid {
		return "", ErrNotFound
	}
	outcome := ""
	err := s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		var it Item
		if err := tx.QueryRow(ctx, `SELECT tenant_id::text, turn_id::text, matter_id::text, custodian_id::text, recorded_at, state, pending_since, sweep_by::text
			FROM retention_items WHERE tenant_id=$1 AND turn_id=$2 FOR UPDATE`, p.TenantID, turnID).
			Scan(&it.TenantID, &it.TurnID, &it.MatterID, &it.CustodianID, &it.RecordedAt, &it.State, &it.PendingSince, &it.SweepBy); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if it.State == ItemPurging {
			outcome = "already_purging"
			return nil
		}
		if it.State != ItemDisposalPending {
			outcome = "not_eligible"
			return nil
		}
		if it.SweepBy != nil && *it.SweepBy == p.UserID {
			return ErrForbidden
		}
		policy, err := s.policyTx(ctx, tx, p.TenantID)
		if err != nil {
			return err
		}
		if it.PendingSince == nil || time.Since(*it.PendingSince) < time.Duration(policy.GraceSeconds)*time.Second {
			outcome = "grace_not_elapsed"
			return nil
		}
		epoch, err := lockEpoch(ctx, tx, p.TenantID, it.MatterID, false)
		if err != nil {
			return err
		}
		s.hookEpoch("begin_purge", p.TenantID, it.MatterID)
		holds, err := ActiveHolds(ctx, tx, p.TenantID, it.MatterID)
		if err != nil {
			return err
		}
		if Held(holds, it.MatterID, it.CustodianID, it.RecordedAt) {
			if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL WHERE tenant_id=$1 AND turn_id=$2`,
				p.TenantID, turnID); err != nil {
				return err
			}
			outcome = "restored_active"
			return audit(ctx, tx, p.TenantID, &p.UserID, "purge.begin", map[string]any{"turn_id": turnID, "outcome": outcome})
		}
		if verifyBytes != nil {
			present, err := verifyBytes(ctx, turnID)
			if err != nil {
				return err
			}
			if !present {
				// Bytes are gone although the item was never disposed: an
				// ambiguous earlier purge attempt. Never tombstone a lie.
				if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposed', purged_at=now() WHERE tenant_id=$1 AND turn_id=$2 AND state='disposal_pending'`,
					p.TenantID, turnID); err != nil {
					return err
				}
				outcome = "disposed_ambiguous"
				return audit(ctx, tx, p.TenantID, &p.UserID, "purge.begin", map[string]any{"turn_id": turnID, "outcome": outcome})
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='purging', observed_epoch=$3, tombstoned_at=now(), purge_by=$4
			WHERE tenant_id=$1 AND turn_id=$2 AND state='disposal_pending'`, p.TenantID, turnID, epoch, p.UserID); err != nil {
			return err
		}
		outcome = "purging"
		return audit(ctx, tx, p.TenantID, &p.UserID, "purge.begin", map[string]any{"turn_id": turnID, "matter_id": it.MatterID, "observed_epoch": epoch})
	})
	return outcome, err
}

func (s *Store) policyTx(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantID string) (SweepPolicy, error) {
	var r, g *int64
	err := q.QueryRow(ctx, `SELECT retention_seconds, grace_seconds FROM retention_policies WHERE tenant_id=$1`, tenantID).Scan(&r, &g)
	if errors.Is(err, pgx.ErrNoRows) {
		return SweepPolicy{RetentionSeconds: defaultRetentionSeconds, GraceSeconds: defaultGraceSeconds}, nil
	}
	if err != nil {
		return SweepPolicy{}, err
	}
	p := SweepPolicy{RetentionSeconds: defaultRetentionSeconds, GraceSeconds: defaultGraceSeconds}
	if r != nil && *r >= 1 {
		p.RetentionSeconds = *r
	}
	if g != nil && *g >= 0 {
		p.GraceSeconds = *g
	}
	return p, nil
}

// FinishPurgeTx runs the conditional delete transaction: the matter's epoch
// row is locked FOR UPDATE, the item row is locked, and the epoch is compared
// with the value begin_purge observed. deleter performs the irreversible
// storage deletes INSIDE this transaction (under the epoch lock). A deleter
// error rolls the whole transaction back; an outcome of "restored_active",
// "stale_retry", "disposed" or "blocked" is committed with its audit row.
func (s *Store) FinishPurgeTx(ctx context.Context, actor *store.Principal, tenantID, turnID string,
	deleter func(context.Context, Item) (map[string]string, error), verifyBytes func(context.Context, string) (bool, error), outcome *string) error {
	run := func(tx pgx.Tx) error {
		it := Item{}
		err := tx.QueryRow(ctx, `SELECT tenant_id::text, turn_id::text, matter_id::text, project_id::text, custodian_id::text,
			recorded_at, retention_expires_at, state, observed_epoch FROM retention_items WHERE tenant_id=$1 AND turn_id=$2 FOR UPDATE`,
			tenantID, turnID).
			Scan(&it.TenantID, &it.TurnID, &it.MatterID, &it.ProjectID, &it.CustodianID, &it.RecordedAt, &it.ExpiresAt, &it.State, &it.ObservedEpoch)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if actor != nil && it.TenantID != actor.TenantID {
			return ErrNotFound
		}
		if it.State != ItemPurging {
			*outcome = "not_purging"
			return nil
		}
		epoch, err := lockEpoch(ctx, tx, it.TenantID, it.MatterID, false)
		if err != nil {
			return err
		}
		s.hookEpoch("finish_purge", it.TenantID, it.MatterID)
		holds, err := ActiveHolds(ctx, tx, it.TenantID, it.MatterID)
		if err != nil {
			return err
		}
		if it.ObservedEpoch == nil {
			return ErrConflict
		}
		if epoch != *it.ObservedEpoch {
			// A hold or release committed since begin_purge: re-evaluate,
			// never delete blind (state machines case G).
			if Held(holds, it.MatterID, it.CustodianID, it.RecordedAt) {
				present := true
				if verifyBytes != nil {
					present, err = verifyBytes(ctx, it.TurnID)
					if err != nil {
						return err
					}
				}
				if !present {
					// Bytes are already gone (an earlier delete attempt
					// committed at the storage but not here): the restore
					// must not claim they exist.
					if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposed', purged_at=now() WHERE tenant_id=$1 AND turn_id=$2`,
						it.TenantID, it.TurnID); err != nil {
						return err
					}
					*outcome = "disposed_ambiguous"
					return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome, "epoch": epoch, "observed": *it.ObservedEpoch})
				}
				if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL, purge_by=NULL WHERE tenant_id=$1 AND turn_id=$2`,
					it.TenantID, it.TurnID); err != nil {
					return err
				}
				*outcome = "restored_active"
				return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome, "epoch": epoch, "observed": *it.ObservedEpoch})
			}
			if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposal_pending', observed_epoch=$3, pending_since=now(), tombstoned_at=NULL, purge_by=NULL WHERE tenant_id=$1 AND turn_id=$2`,
				it.TenantID, it.TurnID, epoch); err != nil {
				return err
			}
			*outcome = "stale_retry"
			return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome, "epoch": epoch, "observed": *it.ObservedEpoch})
		}
		if Held(holds, it.MatterID, it.CustodianID, it.RecordedAt) {
			// A hold now matches even though the epoch is unchanged (a
			// pending hold never bumped the epoch it was placed under):
			// restore, never delete.
			if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL, purge_by=NULL WHERE tenant_id=$1 AND turn_id=$2`,
				it.TenantID, it.TurnID); err != nil {
				return err
			}
			*outcome = "restored_active"
			return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome})
		}
		results, err := deleter(ctx, it)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposed', purged_at=now() WHERE tenant_id=$1 AND turn_id=$2 AND state='purging'`,
			it.TenantID, it.TurnID); err != nil {
			return err
		}
		*outcome = "disposed"
		return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome, "versions": results})
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if actor != nil {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT true FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, actor.TenantID).Scan(&locked); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrForbidden
			}
			return err
		}
		var ok2 bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenant_roles r JOIN users u ON u.id=r.user_id AND u.tenant_id=r.tenant_id
			WHERE r.user_id=$1 AND r.tenant_id=$2 AND r.role=$3 AND u.disabled_at IS NULL)`, actor.UserID, actor.TenantID, store.RoleRecordsOfficer).Scan(&ok2); err != nil {
			return err
		}
		if !ok2 {
			return ErrForbidden
		}
	}
	if err := run(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func actorID(p *store.Principal) *string {
	if p == nil {
		return nil
	}
	return &p.UserID
}

// MarkReleaseCleanup records which version cleanups remain pending after a
// release (conservative: pending means over-protection).
func (s *Store) MarkReleaseCleanup(ctx context.Context, holdID string, pending []VersionRef) error {
	return s.writeHoldState(ctx, holdID, func(tx pgx.Tx) error {
		h, err := loadHold(ctx, tx, holdID)
		if err != nil {
			return err
		}
		h.Report.ReleaseCleanupPending = pending
		b, err := json.Marshal(h.Report)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE holds SET report=$2 WHERE id=$1`, holdID, b); err != nil {
			return err
		}
		return nil
	})
}

// HoldsInState loads every hold (all tenants; the control plane is
// single-instance under the fence) whose state is one of the given states.
func (s *Store) HoldsInState(ctx context.Context, states ...string) ([]*Hold, error) {
	rows, err := s.DB.Query(ctx, `SELECT id::text FROM holds WHERE state = ANY($1) ORDER BY placed_at, id`, states)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]*Hold, 0, len(ids))
	for _, id := range ids {
		h, err := loadHold(ctx, s.DB, id)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// ItemsInState loads lifecycle items in the given states (all tenants).
func (s *Store) ItemsInState(ctx context.Context, states ...string) ([]Item, error) {
	rows, err := s.DB.Query(ctx, `SELECT tenant_id::text, turn_id::text, matter_id::text, project_id::text, custodian_id::text,
		recorded_at, retention_expires_at, state, observed_epoch, pending_since, sweep_by::text, purge_by::text, tombstoned_at, purged_at
		FROM retention_items WHERE state = ANY($1) ORDER BY recorded_at, turn_id`, states)
	return scanItems(rows, err)
}

// MarkDisposedAmbiguous completes the disposal of an item whose bytes are
// verifiably gone although the lifecycle never committed the disposal (the
// crash window between the storage delete and the transaction commit). The
// hold reports pick the gap up as disposed_before_hold at the next
// establishment; this never claims a physical deletion that did not happen.
func (s *Store) MarkDisposedAmbiguous(ctx context.Context, it Item) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tag, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposed', purged_at=now() WHERE tenant_id=$1 AND turn_id=$2 AND state IN ('disposal_pending','purging')`,
		it.TenantID, it.TurnID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	if err := audit(ctx, tx, it.TenantID, nil, "purge.ambiguous_disposed", map[string]any{"turn_id": it.TurnID, "matter_id": it.MatterID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
