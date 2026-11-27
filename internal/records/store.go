package records

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
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
	ErrForbidden = store.ErrForbidden
	ErrNotFound  = store.ErrNotFound
	ErrConflict  = errors.New("records: conflicting lifecycle state")
	ErrRetry     = errors.New("records: retry the lifecycle operation")
	// ErrStaleEstablishment marks a two-phase protection establishment
	// whose hold transitioned between the durable claim commit and the
	// native mutation: the claims are reconciled by that transition and
	// the native set must not proceed. Retryable.
	ErrStaleEstablishment = fmt.Errorf("%w: stale hold establishment", ErrRetry)
	ErrBlockedStorage     = errors.New("records: disposal blocked by storage protection")
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

// lockProtection inserts the tenant's protection fence row if absent and
// locks it FOR UPDATE. Every native protection mutation (legal-hold set and
// clear), every disposal version delete and every capture-side reference
// acquisition holds this lock across its storage operations, so protection
// removal and establishment can never use incompatible snapshots: a newer
// protection claim is either visible to the clear decision (it committed
// before the lock was taken) or serialized after the clear (its set happens
// once the lock is released). Global lock order is
// tenants -> tenant_protection -> retention_items -> matter_hold_epochs;
// every path acquires in that order only.
func lockProtection(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_protection(tenant_id) VALUES ($1)
		ON CONFLICT (tenant_id) DO NOTHING`, tenantID); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM tenant_protection WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&exists); err != nil {
		return err
	}
	return nil
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

// samePlacementIntent reports whether a retry carries the EXACT authorized
// placement intent of the admitted hold: matter, custodian selection, time
// window, reason and placing officer (C07 round-2 finding 5). A reused
// idempotency key with a changed intent fails explicitly instead of
// acknowledging the unrelated existing hold.
func samePlacementIntent(h *Hold, matterID string, custodians []string, scope Scope, reason, actorID string) bool {
	if h == nil || h.MatterID != matterID || h.Reason != reason || h.PlacedBy != actorID {
		return false
	}
	if !equalCanonicalSet(h.CustodianIDs, custodians) {
		return false
	}
	if !sameWindow(h.WindowStart, scope.WindowStart) || !sameWindow(h.WindowEnd, scope.WindowEnd) {
		return false
	}
	return true
}

func sameWindow(a, b *time.Time) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == nil {
		return true
	}
	// Compare at the durable timestamptz resolution (microseconds): values
	// differing only below the storage resolution are indistinguishable in
	// the admitted intent.
	return a.Truncate(time.Microsecond).Equal(b.Truncate(time.Microsecond))
}

func equalCanonicalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]string(nil), a...)
	sb := append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
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
		// Idempotent retry: the same officer key with the SAME authorized
		// placement intent returns the durable hold with its current state;
		// it never places a second hold, and a CHANGED intent fails
		// explicitly instead of acknowledging an unrelated existing hold
		// (C07 round-2 finding 5).
		var existing string
		err := tx.QueryRow(ctx, `SELECT id::text FROM holds WHERE tenant_id=$1 AND idempotency_key=$2`, p.TenantID, idempotencyKey).Scan(&existing)
		if err == nil {
			h, herr := loadHold(ctx, tx, existing)
			if herr != nil {
				return herr
			}
			if !samePlacementIntent(h, matterID, custodians, scope, reason, p.UserID) {
				return fmt.Errorf("%w: idempotency key %q is bound to a different placement intent", ErrConflict, idempotencyKey)
			}
			*created = *h
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Lock order discipline: retention_items row locks are taken BEFORE
		// the matter epoch row (the same order as sweep/begin_purge/
		// finish_purge), so placement can never deadlock against a purge
		// holding an item row and waiting for the epoch. The restore stays
		// in the same transaction as the epoch commit, so the hold-wins
		// linearization is unchanged.
		//
		// Hold wins over an in-flight disposal: MATCHING pending/purging
		// items return to active in the same transaction that commits the
		// epoch (state machines cases B and F). The custodian and window
		// predicates mirror ADR matching so an unrelated scoped hold bumps
		// the epoch without restoring anything it does not cover.
		itemsFreed, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL
			WHERE tenant_id=$1 AND matter_id=$2 AND state IN ('disposal_pending','purging')
			AND ($3::uuid[] IS NULL OR custodian_id = ANY($3))
			AND ($4::timestamptz IS NULL OR recorded_at >= $4)
			AND ($5::timestamptz IS NULL OR recorded_at < $5)`,
			p.TenantID, matterID, custodianSlice(custodians), scope.WindowStart, scope.WindowEnd)
		if err != nil {
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
				// waiting on the epoch row): return the durable winner
				// only when it admitted the SAME placement intent.
				h, herr := loadHoldByIdempotency(ctx, tx, p.TenantID, idempotencyKey)
				if herr != nil {
					return herr
				}
				if !samePlacementIntent(h, matterID, custodians, scope, reason, p.UserID) {
					return fmt.Errorf("%w: idempotency key %q is bound to a different placement intent", ErrConflict, idempotencyKey)
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
		// Items already disposed are a recorded gap, never a silent miss.
		var gapCount int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM retention_items WHERE tenant_id=$1 AND matter_id=$2 AND state='disposed'`, p.TenantID, matterID).Scan(&gapCount); err != nil {
			return err
		}
		if err := audit(ctx, tx, p.TenantID, &p.UserID, "hold.place", map[string]any{
			"hold_id": id, "matter_id": matterID, "custodian_ids": custodians,
			"epoch": epoch, "reason": reason, "restored_items": itemsFreed.RowsAffected(), "disposed_items_in_matter": gapCount,
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

// holdOfTx loads one hold by id inside a transaction (state re-validation
// for two-phase protection establishment).
func holdOfTx(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, tenantID, id string) (*Hold, error) {
	h, err := loadHold(ctx, q, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if h.TenantID != tenantID {
		return nil, ErrConflict
	}
	return h, nil
}

// holdsOfTx loads every hold of the tenant (any state) inside a
// transaction.
func holdsOfTx(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, tenantID string) ([]*Hold, error) {
	rows, err := q.Query(ctx, `SELECT id::text FROM holds WHERE tenant_id=$1 ORDER BY epoch`, tenantID)
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
	var out []*Hold
	for _, id := range ids {
		h, err := loadHold(ctx, q, id)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
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
// It is the single authoritative acceptance rule of the effective
// transition: a report with any uncovered record is refused here - no
// caller can acknowledge incomplete protection - and the transition is
// bound to the exact scope revision (the hold's epoch) the establishment
// verified, so a stale establishment completing after a scope change can
// never mark a newer scope effective. The audit row is written only on the
// actual transition (idempotent completion writes nothing).
func (s *Store) MarkEffective(ctx context.Context, holdID string, report Report, wantEpoch int64) error {
	if len(report.Uncovered) > 0 {
		// Incomplete protection is never successful activation: the hold
		// stays pending/failed (its disposal fence stands) and the caller
		// records the failure.
		return fmt.Errorf("%w: %d uncovered records block the effective transition", ErrConflict, len(report.Uncovered))
	}
	err := s.writeHoldState(context.Background(), holdID, func(tx pgx.Tx) error {
		b, err := json.Marshal(report)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE holds SET state='effective', effective_at=now(), report=$2
			WHERE id=$1 AND state IN ('pending','failed') AND epoch=$3`, holdID, b, wantEpoch)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			// Either a concurrent placement of the SAME idempotency key
			// already established and verified protection (idempotent
			// completion - no audit, no report overwrite), or the scope
			// revision moved under us (a stale establishment): only the
			// first is success. A released hold can never become effective.
			var state string
			var epoch int64
			if err := tx.QueryRow(ctx, `SELECT state, epoch FROM holds WHERE id=$1`, holdID).Scan(&state, &epoch); err != nil {
				return err
			}
			if state != HoldEffective || epoch != wantEpoch {
				return ErrConflict
			}
			return nil
		}
		return audit(ctx, tx, holdTenant(ctx, tx, holdID), nil, "hold.effective", map[string]any{
			"hold_id": holdID, "items": len(report.Items), "uncovered": len(report.Uncovered), "scope_epoch": wantEpoch,
			"protected_versions": len(report.ProtectedVersions),
		})
	})
	if err != nil {
		return err
	}
	return nil
}

// MarkFailed records a failed establishment (retryable; the fence stands).
// Like MarkEffective it is bound to the scope revision it attempted, so a
// stale failure cannot overwrite the state of a newer scope.
func (s *Store) MarkFailed(ctx context.Context, holdID string, report Report, detail string, wantEpoch int64) error {
	return s.writeHoldState(context.Background(), holdID, func(tx pgx.Tx) error {
		report.Error = detail
		b, err := json.Marshal(report)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE holds SET state='failed', report=$2 WHERE id=$1 AND state IN ('pending','failed') AND epoch=$3`, holdID, b, wantEpoch)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			var state string
			var epoch int64
			if err := tx.QueryRow(ctx, `SELECT state, epoch FROM holds WHERE id=$1`, holdID).Scan(&state, &epoch); err != nil {
				return err
			}
			if state != HoldFailed || epoch != wantEpoch {
				return ErrConflict
			}
			return nil
		}
		return audit(ctx, tx, holdTenant(ctx, tx, holdID), nil, "hold.establishment_failed", map[string]any{"hold_id": holdID, "detail": detail, "scope_epoch": wantEpoch})
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
		// A widened scope restores matching pending/purging items; a narrowed
		// one leaves protection removal to the conservative cleanup phase.
		// Item row locks are taken BEFORE the matter epoch row (global lock
		// order), in the same transaction as the scope change.
		if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL
			WHERE tenant_id=$1 AND matter_id=$2 AND state IN ('disposal_pending','purging')
			AND ($3::uuid[] IS NULL OR custodian_id = ANY($3))
			AND ($4::timestamptz IS NULL OR recorded_at >= $4)
			AND ($5::timestamptz IS NULL OR recorded_at < $5)`,
			p.TenantID, h.MatterID, custodianSlice(custodians), scope.WindowStart, scope.WindowEnd); err != nil {
			return err
		}
		epoch, err := lockEpoch(ctx, tx, p.TenantID, h.MatterID, true)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE holds SET window_start=$2, window_end=$3, reason=reason || E'\n' || $4, epoch=$5 WHERE id=$1`,
			holdID, scope.WindowStart, scope.WindowEnd, reason, epoch); err != nil {
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
		// The changed hold needs establishment again before it may report
		// effective for the new scope. Binding holds.epoch to the new matter
		// epoch makes that epoch the scope revision: an establishment that
		// verified the PRIOR scope cannot complete the transition (its
		// MarkEffective no longer matches), so a stale establishment can
		// never mark a newer scope effective.
		if _, err := tx.Exec(ctx, `UPDATE holds SET state='pending' WHERE id=$1 AND state IN ('effective','pending','failed')`, holdID); err != nil {
			return err
		}
		priorWindow := map[string]any{}
		if h.WindowStart != nil {
			priorWindow["start"] = h.WindowStart.UTC().Format(time.RFC3339Nano)
		}
		if h.WindowEnd != nil {
			priorWindow["end"] = h.WindowEnd.UTC().Format(time.RFC3339Nano)
		}
		newWindow := map[string]any{}
		if scope.WindowStart != nil {
			newWindow["start"] = scope.WindowStart.UTC().Format(time.RFC3339Nano)
		}
		if scope.WindowEnd != nil {
			newWindow["end"] = scope.WindowEnd.UTC().Format(time.RFC3339Nano)
		}
		if err := audit(ctx, tx, p.TenantID, &p.UserID, "hold.change", map[string]any{
			"hold_id": holdID, "matter_id": h.MatterID, "epoch": epoch, "reason": reason,
			"prior_scope": map[string]any{"custodian_ids": h.CustodianIDs, "window": priorWindow, "scope_epoch": h.Epoch},
			"new_scope":   map[string]any{"custodian_ids": custodians, "window": newWindow, "scope_epoch": epoch},
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

// TerminalCheck reports whether a turn's capture reached a terminal event;
// nil means the caller cannot verify terminality and every candidate fails
// closed (never marked). Disposal eligibility requires a verified terminal
// capture state: an admitted, actively executing turn must never be swept
// into disposal by ordinary expiry (C07 review finding 6A).
type TerminalCheck func(context.Context, evidence.TurnIdentity) (bool, error)

// Sweep marks eligible items disposal_pending: retention expired AND not
// held AND capture terminal, per matter epoch observed under the same lock.
// It returns the number newly marked. Concurrent sweeps are idempotent
// (only active items move).
func (s *Store) Sweep(ctx context.Context, p store.Principal, turns []evidence.TurnIdentity, policy SweepPolicy, terminal TerminalCheck) (int, error) {
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
			if terminal == nil {
				// No verified terminal state: fail closed, never mark.
				return nil
			}
			done, err := terminal(ctx, t)
			if err != nil {
				// Unknown capture state: fail closed for this turn.
				return nil
			}
			if !done {
				// In-flight capture: ordinary expiry must not destroy it.
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

// FinishPurgePlanTx is the plan phase of the conditional delete: it commits
// the durable exact-version disposal plan BEFORE any irreversible deletion,
// so an interrupted deletion resumes from the plan without requiring
// already-deleted enumeration metadata (the admission marker can be gone)
// and every planned version receives a verified disposition (C07 review
// finding 5). The plan is created only while the item is still a valid purge
// candidate under the same locks the delete phase takes; any re-evaluation
// or restore outcome is left to the delete phase unchanged.
func (s *Store) FinishPurgePlanTx(ctx context.Context, actor *store.Principal, tenantID, turnID string,
	enumerate func(context.Context) ([]evidence.VersionRef, error), outcome *string) error {
	run := func(tx pgx.Tx) error {
		it := Item{}
		err := tx.QueryRow(ctx, `SELECT tenant_id::text, turn_id::text, matter_id::text, custodian_id::text,
			recorded_at, state, observed_epoch
			FROM retention_items WHERE tenant_id=$1 AND turn_id=$2 FOR UPDATE`, tenantID, turnID).
			Scan(&it.TenantID, &it.TurnID, &it.MatterID, &it.CustodianID, &it.RecordedAt, &it.State, &it.ObservedEpoch)
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
			// not_purging: nothing to plan; the delete phase reports it.
			return nil
		}
		epoch, err := lockEpoch(ctx, tx, it.TenantID, it.MatterID, false)
		if err != nil {
			return err
		}
		holds, err := ActiveHolds(ctx, tx, it.TenantID, it.MatterID)
		if err != nil {
			return err
		}
		if it.ObservedEpoch == nil || epoch != *it.ObservedEpoch || Held(holds, it.MatterID, it.CustodianID, it.RecordedAt) {
			// A hold or release committed since begin_purge, or the item is
			// not a valid candidate: leave re-evaluation to the delete phase.
			return nil
		}
		var planned int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2`, tenantID, turnID).Scan(&planned); err != nil {
			return err
		}
		if planned > 0 {
			return nil // already planned (idempotent phase)
		}
		enumRefs, err := enumerate(ctx)
		if err != nil {
			return err
		}
		if len(enumRefs) == 0 {
			return fmt.Errorf("%w: no enumerable versions to plan", ErrConflict)
		}
		var refs []VersionRef
		for _, r := range enumRefs {
			refs = append(refs, VersionRef{Key: r.Key, Version: r.Version})
		}
		return InsertPlan(ctx, tx, tenantID, turnID, refs, epoch)
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if actor != nil {
		if err := s.lockActor(ctx, tx, *actor); err != nil {
			return err
		}
	}
	if err := run(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// lockActor re-verifies the acting records officer inside the caller's
// transaction (tenants row lock first: the global lock order).
func (s *Store) lockActor(ctx context.Context, tx pgx.Tx, actor store.Principal) error {
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
	return nil
}

// FinishPurgeTx runs the conditional delete transaction: the tenant
// protection fence is locked, the item row is locked, the matter's epoch row
// is locked FOR UPDATE, and the epoch is compared with the value begin_purge
// observed. deleter performs the irreversible storage deletes INSIDE this
// transaction (under the protection fence and the epoch lock), so a
// concurrent capture cannot acquire a reference to an exact version between
// the shared-reference snapshot and its deletion (C07 review finding 6B).
// The per-version outcomes returned by the deleter are recorded as the
// disposal plan's verified dispositions in the same transaction. A deleter
// error rolls the whole transaction back; an outcome of "restored_active",
// "restored_active_partial", "stale_retry", "disposed" or "blocked" is
// committed with its audit row.
//
// verifyVersions classifies each planned version's physical presence
// ("present" / "absent"; an error is unknown) by ACTUAL STORAGE READBACK.
// A restore to active over a plan with outstanding entries is performed
// only with verified completeness: a prior physical delete may have
// committed while the disposition transaction rolled back, and partial
// physical deletion must never be represented as intact active evidence
// (C07 round-2 finding 4).
func (s *Store) FinishPurgeTx(ctx context.Context, actor *store.Principal, tenantID, turnID string,
	deleter func(context.Context, Item) (map[string]string, error), verifyBytes func(context.Context, string) (bool, error),
	verifyVersions func(context.Context, []PlanRow) (map[string]string, error), outcome *string) error {
	run := func(tx pgx.Tx) error {
		// The protection fence serializes the deletes with every protection
		// mutation and every capture-side reference acquisition of this
		// tenant, and is taken BEFORE the item row lock so the global order
		// (tenants -> tenant_protection -> retention_items ->
		// matter_hold_epochs) holds on every path (a capture's reference
		// fence takes tenants -> tenant_protection; taking the item row
		// first here would invert the order).
		if err := lockProtection(ctx, tx, tenantID); err != nil {
			return err
		}
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
			// The plan is destroyed only for a turn whose disposal COMPLETED
			// (every planned version has a verified disposition). A restored
			// or still-pending item KEEPS its durable exact-version
			// identity: a partial physical deletion must never lose the
			// only remaining inventory (C07 round-2 finding 4).
			if it.State == ItemDisposed {
				if err := DeletePlan(ctx, tx, it.TenantID, it.TurnID); err != nil {
					return err
				}
			}
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
		// restoreActive returns a purging item to active because a hold now
		// matches. When a durable plan exists, restoration requires VERIFIED
		// completeness (actual storage readback per planned version): a
		// prior delete may have committed at the storage while this
		// transaction's predecessor rolled back. Partial deletion is
		// restored with the loss recorded in the plan (the exact-version
		// inventory is never destroyed); only verified completeness may
		// clear the plan; a fully vanished record is completed as disposed
		// (never active evidence that does not exist). An unknown presence
		// outcome refuses the restore (the item stays purging, retryable).
		restoreActive := func() error {
			plan, err := planOfTx(ctx, tx, it.TenantID, it.TurnID)
			if err != nil {
				return err
			}
			if len(plan) == 0 {
				// No durable plan (legacy shape): nothing to verify.
				if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL, purge_by=NULL WHERE tenant_id=$1 AND turn_id=$2`,
					it.TenantID, it.TurnID); err != nil {
					return err
				}
				*outcome = "restored_active"
				return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome})
			}
			presence, err := verifyVersions(ctx, plan)
			if err != nil {
				return fmt.Errorf("%w: restore verification: %v", ErrConflict, err)
			}
			// Completeness counts EVERY planned version, including rows
			// already dispositioned gone (e.g. by the hold's own partial
			// coverage): a durable record of loss is a loss, not
			// intactness.
			missing := []string{}
			gone := 0
			for _, row := range plan {
				if row.Disposition == "deleted" || row.Disposition == "absent" {
					gone++
					missing = append(missing, row.Key+"|"+row.Version)
					continue
				}
				if presence[row.Key+"|"+row.Version] == "absent" {
					gone++
					missing = append(missing, row.Key+"|"+row.Version)
					if err := UpdatePlanDisposition(ctx, tx, it.TenantID, it.TurnID, row.Key, row.Version, "absent"); err != nil {
						return err
					}
				}
			}
			if len(plan) > 0 && gone == len(plan) {
				// Every planned version is verifiably gone: the restore
				// must not claim active evidence exists.
				if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposed', purged_at=now() WHERE tenant_id=$1 AND turn_id=$2`,
					it.TenantID, it.TurnID); err != nil {
					return err
				}
				*outcome = "disposed_ambiguous"
				return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{
					"turn_id": it.TurnID, "outcome": *outcome, "missing_versions": missing,
				})
			}
			if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='active', observed_epoch=NULL, pending_since=NULL, tombstoned_at=NULL, purge_by=NULL WHERE tenant_id=$1 AND turn_id=$2`,
				it.TenantID, it.TurnID); err != nil {
				return err
			}
			if gone > 0 {
				// Partial restoration: the loss is recorded and the plan
				// keeps the durable version identity and dispositions; a
				// later release and disposal remain recoverable.
				*outcome = "restored_active_partial"
				return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{
					"turn_id": it.TurnID, "outcome": *outcome, "missing_versions": missing,
				})
			}
			// Verified complete: the exact-version inventory is intact.
			if err := DeletePlan(ctx, tx, it.TenantID, it.TurnID); err != nil {
				return err
			}
			*outcome = "restored_active"
			return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome, "verified_versions": len(plan)})
		}
		if epoch != *it.ObservedEpoch {
			// A hold or release committed since begin_purge: re-evaluate,
			// never delete blind (state machines case G).
			if Held(holds, it.MatterID, it.CustodianID, it.RecordedAt) {
				present := true
				plan, err := planOfTx(ctx, tx, it.TenantID, it.TurnID)
				if err != nil {
					return err
				}
				if len(plan) > 0 {
					// The plan is authoritative exact-version identity:
					// verify its completeness by storage readback instead
					// of trusting turn-level presence (a plan with
					// outstanding entries is not proof the bytes remain).
					if err := restoreActive(); err != nil {
						return err
					}
					return nil
				}
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
				if err := restoreActive(); err != nil {
					return err
				}
				return nil
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
			if err := restoreActive(); err != nil {
				return err
			}
			return nil
		}
		results, err := deleter(ctx, it)
		if err != nil {
			return err
		}
		// Each planned version receives its verified disposition in the
		// same transaction that marks the item disposed.
		for id, disp := range results {
			key, version, ok := splitVersionID(id)
			if !ok {
				continue
			}
			if err := UpdatePlanDisposition(ctx, tx, it.TenantID, it.TurnID, key, version, disp); err != nil {
				return err
			}
		}
		var planned, dispositioned int
		if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE disposition <> 'planned') FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2`,
			it.TenantID, it.TurnID).Scan(&planned, &dispositioned); err != nil {
			return err
		}
		if planned != dispositioned {
			// Every exact planned version must have a verified disposition
			// before the disposal may be claimed complete.
			return fmt.Errorf("%w: disposal plan incomplete: %d/%d versions dispositioned", ErrConflict, dispositioned, planned)
		}
		if _, err := tx.Exec(ctx, `UPDATE retention_items SET state='disposed', purged_at=now() WHERE tenant_id=$1 AND turn_id=$2 AND state='purging'`,
			it.TenantID, it.TurnID); err != nil {
			return err
		}
		*outcome = "disposed"
		return audit(ctx, tx, it.TenantID, actorID(actor), "purge.finish", map[string]any{"turn_id": it.TurnID, "outcome": *outcome, "versions": results, "planned_versions": planned})
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if actor != nil {
		if err := s.lockActor(ctx, tx, *actor); err != nil {
			return err
		}
	}
	if err := run(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// splitVersionID splits a deleter outcome key ("key|version") back into its
// parts. Version IDs may themselves contain '|', so the LAST separator is
// the split point.
func splitVersionID(id string) (key, version string, ok bool) {
	i := strings.LastIndex(id, "|")
	if i <= 0 || i == len(id)-1 {
		return "", "", false
	}
	return id[:i], id[i+1:], true
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

// ---- Durable protection ownership ledger (hold_version_claims) ----

// VersionClaim is one exact version a hold's establishment caused to be
// protected. The ledger is the crash-safe derivation of what release
// cleanup and recovery must clear: never only a historical coverage report.
type VersionClaim struct {
	TenantID, HoldID, Key, Version, State string
}

// UpsertClaim records protection intent for one exact version BEFORE the
// storage mutation is acknowledged (state pending; idempotent).
func UpsertClaim(ctx context.Context, tx pgx.Tx, tenantID, holdID string, v VersionRef) error {
	_, err := tx.Exec(ctx, `INSERT INTO hold_version_claims(tenant_id, hold_id, key, version, state)
		VALUES ($1,$2,$3,$4,'pending') ON CONFLICT (hold_id, key, version) DO NOTHING`,
		tenantID, holdID, v.Key, v.Version)
	return err
}

// MarkClaimProtected records verified native protection (readback ON).
// It REQUIRES the claim row to have been updated: protection completion
// on a missing claim row is an error, so every native protection
// mutation keeps a durable owner established beforehand (C07 round-2
// finding 6).
func MarkClaimProtected(ctx context.Context, tx pgx.Tx, holdID string, v VersionRef) error {
	tag, err := tx.Exec(ctx, `UPDATE hold_version_claims SET state='protected', verified_at=now()
		WHERE hold_id=$1 AND key=$2 AND version=$3`, holdID, v.Key, v.Version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: protection completion for hold %s on %s|%s has no durable claim row", ErrConflict, holdID, v.Key, v.Version)
	}
	return nil
}

// ClaimsOfHold enumerates the hold's outstanding protection claims.
func (s *Store) ClaimsOfHold(ctx context.Context, holdID string) ([]VersionClaim, error) {
	return claimsOfHold(ctx, s.DB, holdID)
}

func claimsOfHold(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, holdID string) ([]VersionClaim, error) {
	rows, err := q.Query(ctx, `SELECT tenant_id::text, hold_id::text, key, version, state
		FROM hold_version_claims WHERE hold_id=$1 AND state IN ('pending','protected','releasing')
		ORDER BY key, version`, holdID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VersionClaim
	for rows.Next() {
		var c VersionClaim
		if err := rows.Scan(&c.TenantID, &c.HoldID, &c.Key, &c.Version, &c.State); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteClaim removes a claim whose legal hold is verified OFF and no longer
// required. The audit trail (written by the caller) keeps the history.
func DeleteClaim(ctx context.Context, tx pgx.Tx, holdID string, v VersionRef) error {
	_, err := tx.Exec(ctx, `DELETE FROM hold_version_claims WHERE hold_id=$1 AND key=$2 AND version=$3`,
		holdID, v.Key, v.Version)
	return err
}

// MarkClaimReleasing records clear intent before the storage mutation
// (crash window: retry idempotently).
func MarkClaimReleasing(ctx context.Context, tx pgx.Tx, holdID string, v VersionRef) error {
	_, err := tx.Exec(ctx, `UPDATE hold_version_claims SET state='releasing' WHERE hold_id=$1 AND key=$2 AND version=$3`,
		holdID, v.Key, v.Version)
	return err
}

// ---- Durable disposal plans (disposal_plans) ----

// PlanRow is one exact planned version with its verified disposition.
type PlanRow struct {
	TenantID, TurnID, Key, Version, Disposition string
	PlanEpoch                                   *int64
}

// InsertPlan durably records the exact-version disposal plan BEFORE any
// irreversible deletion (committed by the plan phase of the finish).
func InsertPlan(ctx context.Context, tx pgx.Tx, tenantID, turnID string, refs []VersionRef, epoch int64) error {
	for _, v := range refs {
		if _, err := tx.Exec(ctx, `INSERT INTO disposal_plans(tenant_id, turn_id, key, version, disposition, plan_epoch)
			VALUES ($1,$2,$3,$4,'planned',$5) ON CONFLICT (turn_id, key, version) DO NOTHING`,
			tenantID, turnID, v.Key, v.Version, epoch); err != nil {
			return err
		}
	}
	return nil
}

// PlanOf loads the turn's disposal plan.
func (s *Store) PlanOf(ctx context.Context, tenantID, turnID string) ([]PlanRow, error) {
	rows, err := s.DB.Query(ctx, `SELECT tenant_id::text, turn_id::text, key, version, disposition, plan_epoch
		FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2 ORDER BY key, version`, tenantID, turnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPlanRows(rows)
}

// planOfTx loads the turn's disposal plan inside a transaction (restore
// verification runs under the delete-phase locks).
func planOfTx(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, tenantID, turnID string) ([]PlanRow, error) {
	rows, err := q.Query(ctx, `SELECT tenant_id::text, turn_id::text, key, version, disposition, plan_epoch
		FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2 ORDER BY key, version`, tenantID, turnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPlanRows(rows)
}

// MarkPlanAbsent records STORAGE-VERIFIED physical absence of one planned
// version observed outside a disposal transaction (hold coverage of a
// partially disposed record): the plan keeps its durable version identity,
// the disposition stays attributable, and the audit row records the loss.
func (s *Store) MarkPlanAbsent(ctx context.Context, tenantID, turnID string, v VersionRef) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE disposal_plans SET disposition='absent'
		WHERE tenant_id=$1 AND turn_id=$2 AND key=$3 AND version=$4 AND disposition IN ('planned','protected')`,
		tenantID, turnID, v.Key, v.Version); err != nil {
		return err
	}
	if err := audit(ctx, tx, tenantID, nil, "plan.absent_verified", map[string]any{
		"turn_id": turnID, "key": v.Key, "version": v.Version,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AuditProtectionRepairFailed durably records that recovery could not
// complete the protection repair of an effective hold: the failure stays
// attributable and the next recovery retries it (an effective hold is
// never downgraded).
func (s *Store) AuditProtectionRepairFailed(ctx context.Context, tenantID, holdID, detail string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := audit(ctx, tx, tenantID, nil, "hold.protection_repair_failed", map[string]any{
		"hold_id": holdID, "detail": detail,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetRepairState durably records a protection-repair state transition of
// an EFFECTIVE hold TOGETHER WITH its attributable audit row in ONE
// transaction: pending (uncovered records whose protection could not be
// verified), failed (establishment error detail) or verified (both
// cleared - resolution). The state and its audit evidence commit
// ATOMICALLY (an audit insert failure rolls the state change back, so
// repair state can never exist without its audit event), and an UNCHANGED
// state is an idempotent no-op that writes nothing (repeated recovery of
// the same condition never duplicates audit evidence; every genuine
// transition is still recorded exactly once, and the append-only audit
// trail keeps the historical failure and pending evidence). The write
// merges into the stored report (Items, gaps and other fields are
// preserved) and is BOUND to the hold's current scope epoch: a stale
// recovery result completing after a scope change can never overwrite the
// newer scope's coverage information. It returns whether a transition was
// written.
func (s *Store) SetRepairState(ctx context.Context, tenantID, holdID string, pending []string, repairErr string, wantEpoch int64) (bool, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var id string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM holds WHERE id=$1 AND epoch=$2 FOR UPDATE`, holdID, wantEpoch).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("%w: repair state for hold %s is bound to a superseded scope revision", ErrStaleEstablishment, holdID)
		}
		return false, err
	}
	h, err := loadHold(ctx, tx, holdID)
	if err != nil {
		return false, err
	}
	if repairErr == h.Report.RepairError && sameStringSet(pending, h.Report.RepairPending) {
		// Unchanged repair state: an idempotent no-op.
		return false, nil
	}
	h.Report.RepairPending = pending
	h.Report.RepairError = repairErr
	b, err := json.Marshal(h.Report)
	if err != nil {
		return false, err
	}
	action, detail := "hold.protection_repair_complete", map[string]any{
		"hold_id": holdID,
	}
	switch {
	case repairErr != "":
		action, detail = "hold.protection_repair_failed", map[string]any{
			"hold_id": holdID, "detail": repairErr,
		}
	case len(pending) > 0:
		action, detail = "hold.protection_repair_pending", map[string]any{
			"hold_id": holdID, "uncovered": pending,
		}
	}
	if err := audit(ctx, tx, tenantID, nil, action, detail); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE holds SET report=$2 WHERE id=$1`, holdID, b); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// sameStringSet reports whether two lists hold the same distinct strings
// (order-insensitive): the repair state's identity is its condition, not
// the enumeration order of the coverage pass.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, s := range a {
		seen[s] = struct{}{}
	}
	if len(seen) != len(a) {
		return false
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			return false
		}
	}
	return true
}

func scanPlanRows(rows pgx.Rows) ([]PlanRow, error) {
	var out []PlanRow
	for rows.Next() {
		var r PlanRow
		if err := rows.Scan(&r.TenantID, &r.TurnID, &r.Key, &r.Version, &r.Disposition, &r.PlanEpoch); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdatePlanDisposition records the verified disposition of one exact
// planned version (deleted / absent / retained_shared / protected).
func UpdatePlanDisposition(ctx context.Context, tx pgx.Tx, tenantID, turnID, key, version, disposition string) error {
	_, err := tx.Exec(ctx, `UPDATE disposal_plans SET disposition=$5 WHERE tenant_id=$1 AND turn_id=$2 AND key=$3 AND version=$4`,
		tenantID, turnID, key, version, disposition)
	return err
}

// DeletePlan drops the plan of a turn whose disposal was restored or never
// authorized to complete.
func DeletePlan(ctx context.Context, tx pgx.Tx, tenantID, turnID string) error {
	_, err := tx.Exec(ctx, `DELETE FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2`, tenantID, turnID)
	return err
}

// HasLivePlan reports whether a plan with unfinished rows exists.
func (s *Store) HasLivePlan(ctx context.Context, tenantID, turnID string) (bool, error) {
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2 AND disposition IN ('planned','protected')`,
		tenantID, turnID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// auditCleanupComplete durably records a completed release cleanup with its
// attribution (actor nil = recovery).
func auditCleanupComplete(ctx context.Context, tx pgx.Tx, tenantID string, actor *string, holdID string, cleared int) error {
	return audit(ctx, tx, tenantID, actor, "hold.cleanup_complete", map[string]any{
		"hold_id": holdID, "cleared_versions": cleared,
	})
}

// AuditPresencePartial durably records an unresolved partial presence
// observation (never converted into a disposal claim).
func (s *Store) auditPresencePartial(ctx context.Context, tenantID, turnID, detail string) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := audit(ctx, tx, tenantID, nil, "presence.partial", map[string]any{
		"turn_id": turnID, "detail": detail,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
