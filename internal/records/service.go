package records

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
)

// RecordsStorage is the storage-native protection primitive set, held by a
// records-scoped credential. The serving runtime credential deliberately
// lacks every one of these permissions (C04 qualification controls
// runtime_cannot_change_legal_hold, runtime_delete_exact); protection and
// disposal are therefore unreachable from the serving identity alone.
type RecordsStorage interface {
	LegalHold(ctx context.Context, key, version string) (string, error)
	SetLegalHold(ctx context.Context, key, version string, on bool) error
	DeleteVersion(ctx context.Context, key, version string) error
}

// Hooks supports deterministic concurrency tests: every named point is
// invoked where the production path would otherwise rely on timing.
type Hooks struct {
	// BeforeEpochCommit runs inside the placement transaction just before
	// commit, after the epoch is assigned (barrier for hold-vs-purge races).
	BeforeEpochCommit func(stage string)
	// BeforeStorageDelete runs immediately before each irreversible version
	// delete inside the conditional-delete transaction.
	BeforeStorageDelete func(key, version string)
	// AfterStorageDelete runs immediately after each version delete.
	AfterStorageDelete func(key, version string, err error)
	// StorageFault, when set, injects a failure into a storage operation.
	// stage is "protect", "readback", "delete" or "cleanup".
	StorageFault func(stage string) error
}

// Service is the C07 lifecycle composition: the PG lifecycle store, the
// authoritative evidence backend, and (when the deployment qualifies it) the
// records-scoped storage transport for native legal holds and versioned
// deletes. A nil Storage means storage-native protection is unavailable:
// holds stay pending (never silently effective) and disposal is refused.
type Service struct {
	Store    *Store
	Backend  evidence.Backend
	Storage  RecordsStorage
	Retained bool // Backend is the retained S3 Object Lock profile
	Logf     func(string, ...any)
	Hooks    Hooks
}

func (s *Service) logf(format string, a ...any) {
	if s.Logf != nil {
		s.Logf(format, a...)
	}
}

func (s *Service) inventory(ctx context.Context, tenantID string) ([]evidence.TurnIdentity, error) {
	inv, ok := evidence.TurnsInventory(s.Backend)
	if !ok {
		return nil, errors.New("records: backend cannot enumerate turns")
	}
	return inv.InventoryTurns(ctx, tenantID)
}

// disposalRefs enumerates the turn's versions for disposal: expired
// retention is tolerated (disposal is exactly what operates on expired
// evidence); the storage still refuses to delete any protected version.
func (s *Service) disposalRefs(ctx context.Context, tenantID, turnID string) ([]evidence.VersionRef, error) {
	if d, ok := evidence.DisposalVersionsOf(s.Backend); ok {
		return d.TurnDisposalRefs(ctx, tenantID, turnID)
	}
	v, ok := evidence.VersionsOf(s.Backend)
	if !ok {
		return nil, errors.New("records: backend cannot enumerate versions")
	}
	return v.TurnVersionRefs(ctx, tenantID, turnID)
}

// namespaceRefs enumerates a turn's versions without chain verification
// (fallback for the shared-reference scan over a sibling whose verified
// enumeration is unavailable).
func (s *Service) namespaceRefs(ctx context.Context, tenantID, turnID string) ([]evidence.VersionRef, error) {
	n, ok := evidence.NamespaceVersionsOf(s.Backend)
	if !ok {
		return nil, errors.New("records: backend cannot enumerate turn namespaces")
	}
	return n.TurnNamespaceRefs(ctx, tenantID, turnID)
}

// Presence classifies an observation of a turn's exact versions. It exists
// so that a storage failure can never become proof of disposal (C07 review
// finding 4): only the durable disposal plan can verify full physical
// absence, and unknown observations retain conservative state.
type Presence int

const (
	// PresenceUnknown: the authoritative enumeration failed (storage
	// outage, authorization failure, timeout, inconsistent metadata).
	// Nothing may be concluded.
	PresenceUnknown Presence = iota
	// PresencePresent: versions are verifiably enumerable.
	PresencePresent
	// PresencePartial: the enumeration root is gone (or the plan shows
	// unfinished work) while other versions may survive: absence of the
	// full set cannot be proven.
	PresencePartial
	// PresenceAbsent: every exact planned version is verified gone by the
	// durable disposal plan (deleted or already absent).
	PresenceAbsent
)

func (p Presence) String() string {
	switch p {
	case PresencePresent:
		return "present"
	case PresencePartial:
		return "partial"
	case PresenceAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// classifyPresence resolves the turn's byte presence from the durable
// disposal plan first (authoritative exact-version verification) and from
// live enumeration otherwise. It never converts an enumeration error into
// absence.
func (s *Service) classifyPresence(ctx context.Context, tenantID, turnID string) (Presence, string) {
	if s.Retained {
		plan, err := s.Store.PlanOf(ctx, tenantID, turnID)
		if err != nil {
			return PresenceUnknown, fmt.Sprintf("plan load: %v", err)
		}
		if len(plan) > 0 {
			done := true
			for _, r := range plan {
				switch r.Disposition {
				case "deleted", "absent":
				default:
					done = false
				}
			}
			if done {
				return PresenceAbsent, "plan-verified full disposal"
			}
			return PresencePresent, "disposal plan still has live versions"
		}
	}
	refs, err := s.disposalRefs(ctx, tenantID, turnID)
	if err != nil {
		if errors.Is(err, evidence.ErrNotFound) {
			// The enumeration root (admission) is gone: without a plan,
			// full physical absence cannot be proven - other versions of
			// the turn may survive (partial).
			return PresencePartial, "enumeration root absent"
		}
		return PresenceUnknown, err.Error()
	}
	if len(refs) == 0 {
		return PresencePartial, "no enumerable versions"
	}
	return PresencePresent, ""
}

// versionPresent is the conservative legacy projection of classifyPresence
// used where a boolean is required: unknown and partial observations report
// PRESENT, because absence claims require authoritative exact-version
// verification.
func (s *Service) versionPresent(ctx context.Context, tenantID, turnID string) bool {
	p, _ := s.classifyPresence(ctx, tenantID, turnID)
	return p != PresenceAbsent
}

// withProtection runs fn inside a transaction holding the tenant protection
// fence: every native legal-hold mutation (set and clear) executes under
// it, so removal and establishment can never use incompatible snapshots.
func (s *Service) withProtection(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	tx, err := s.Store.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := lockProtection(ctx, tx, tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AcquireReferenceFence is the capture-side half of the protection fence:
// the recorder holds it around every evidence write that acquires a
// reference to content-addressed object versions (turn admission, event
// append, object staging). A disposal's version deletes hold the same
// tenant lock, so a new reference can never be acquired between a
// disposal's shared-reference snapshot and its irreversible deletion of the
// exact required version (C07 review finding 6B). The PG backend has no
// storage deletes, so it is a no-op there.
func (s *Service) AcquireReferenceFence(ctx context.Context, tenantID string) (func(context.Context) error, error) {
	if !s.Retained || s.Store == nil {
		return func(context.Context) error { return nil }, nil
	}
	tx, err := s.Store.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if err := lockProtection(ctx, tx, tenantID); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	return func(ctx context.Context) error {
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		return nil
	}, nil
}

// HoldApplies implements evidence.TurnLifecycleGuard: it reads COMMITTED
// hold state on the lifecycle store (a separate session from the evidence
// write transaction, which is exactly what the two-phase activation boundary
// requires: a placement commits its epoch before this read can see it, and
// the placement's own post-commit scan covers everything admitted earlier).
func (s *Service) HoldApplies(ctx context.Context, tenant, matter, custodian string, recordedAt time.Time) (bool, error) {
	holds, err := ActiveHolds(ctx, s.Store.DB, tenant, matter)
	if err != nil {
		return false, err
	}
	return Held(holds, matter, custodian, recordedAt), nil
}

// EnsureProtected establishes and verifies storage-native protection for
// every version of the turn published so far, on behalf of EVERY active hold
// matching the turn (future matching work admitted after activation). It is
// idempotent and fails closed: any version that cannot be protected or
// verified is an error. Protection intent is durably claimed BEFORE the
// storage mutation, so release cleanup and recovery have a complete
// crash-safe derivation of the protection this admission caused (C07 review
// finding 3).
func (s *Service) EnsureProtected(ctx context.Context, tenant, matter, custodian, turn string, recordedAt time.Time) error {
	if !s.Retained {
		// The PostgreSQL profile has no storage-native protection to apply;
		// the hold's protection there is the lifecycle fence itself, which
		// the guard's HoldApplies answer already carries.
		return nil
	}
	if s.Storage == nil {
		return errors.New("records: storage-native protection unavailable")
	}
	refs, err := s.disposalRefs(ctx, tenant, turn)
	if err != nil {
		return fmt.Errorf("records: enumerate versions: %w", err)
	}
	if len(refs) == 0 {
		return errors.New("records: no versions published for the turn")
	}
	holds, err := ActiveHolds(ctx, s.Store.DB, tenant, matter)
	if err != nil {
		return err
	}
	// Phase 1: commit the protection claims durably BEFORE any native
	// mutation, so a crash between the two phases leaves recoverable pending
	// claims instead of untracked native protection (adversarial review).
	if err := s.withProtection(ctx, tenant, func(tx pgx.Tx) error {
		for _, h := range holds {
			if h.State == HoldReleased {
				continue
			}
			if !Matches(h, matter, custodian, recordedAt) {
				continue
			}
			for _, r := range refs {
				if err := UpsertClaim(ctx, tx, tenant, h.ID, VersionRef(r)); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	// Phase 2: native mutation + readback + claim completion under the
	// fence, with the holds' committed state re-loaded first: claims of a
	// hold that was released in between are never re-set natively.
	return s.withProtection(ctx, tenant, func(tx pgx.Tx) error {
		current, err := holdsOfTx(ctx, tx, tenant)
		if err != nil {
			return err
		}
		applicable := map[string]bool{}
		for _, h := range current {
			if h.State == HoldReleased || !Matches(h, matter, custodian, recordedAt) {
				continue
			}
			applicable[h.ID] = true
		}
		if len(applicable) == 0 {
			return nil
		}
		for _, r := range refs {
			v := VersionRef(r)
			if s.Hooks.StorageFault != nil {
				if err := s.Hooks.StorageFault("protect"); err != nil {
					return err
				}
			}
			if err := s.Storage.SetLegalHold(ctx, v.Key, v.Version, true); err != nil {
				return fmt.Errorf("records: protect %s: %w", v.Key, err)
			}
			if s.Hooks.StorageFault != nil {
				if err := s.Hooks.StorageFault("readback"); err != nil {
					return err
				}
			}
			state, err := s.Storage.LegalHold(ctx, v.Key, v.Version)
			if err != nil || state != "ON" {
				return fmt.Errorf("records: protection readback failed for %s: %v", v.Key, err)
			}
			for id := range applicable {
				if err := MarkClaimProtected(ctx, tx, id, v); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Place runs the full placement: the durable epoch+record transaction, then
// protection establishment over the authoritative inventory, then the
// effective transition. The response reports the final state; effective is
// acknowledged only after every in-scope version is verified protected, and
// the effective transition itself (MarkEffective) refuses any report with
// uncovered records and binds to the scope revision it verified.
func (s *Service) Place(ctx context.Context, p store.Principal, scope Scope, reason, idempotencyKey string) (*Hold, error) {
	h, err := s.Store.PlaceHold(ctx, p, scope, reason, idempotencyKey)
	if err != nil {
		return nil, err
	}
	switch h.State {
	case HoldEffective, HoldReleased:
		return h, nil // idempotent retry of a completed lifecycle
	}
	report, err := s.establish(ctx, h)
	if err == nil && len(report.Uncovered) > 0 {
		// Incomplete protection is not successful activation: a matching
		// record whose versions could not be verified keeps the hold from
		// being acknowledged as effective.
		err = fmt.Errorf("uncovered records: %d", len(report.Uncovered))
	}
	if err != nil {
		if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error(), h.Epoch); merr != nil {
			s.logf("records: hold %s failure recording: %v", h.ID, merr)
		}
		return nil, fmt.Errorf("%w: protection establishment: %v", ErrRetry, err)
	}
	if err := s.Store.MarkEffective(ctx, h.ID, report, h.Epoch); err != nil {
		// A concurrent scope change moved the scope revision: the
		// establishment result is stale. The hold stays pending (its
		// disposal fence stands) and a retry re-establishes it.
		if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error(), h.Epoch); merr != nil {
			s.logf("records: hold %s failure recording: %v", h.ID, merr)
		}
		return nil, fmt.Errorf("%w: protection establishment: %v", ErrRetry, err)
	}
	return s.Store.GetHold(ctx, p, h.ID)
}

// establish applies and verifies protection for every in-scope turn from the
// authoritative backend inventory (never a workspace index), building the
// durable coverage report and the durable version-claim ledger. Disposed
// turns are recorded as gaps - both those still enumerable and those that
// already left the live inventory (the catalog's disposed rows); items whose
// versions cannot be verified are uncovered (the hold cannot become
// effective while any remain, enforced at the MarkEffective transition).
func (s *Service) establish(ctx context.Context, h *Hold) (Report, error) {
	report := Report{ScopeEpoch: h.Epoch}
	turns, err := s.inventory(ctx, h.TenantID)
	if err != nil {
		return report, err
	}
	policy, err := s.Store.Policy(ctx, h.TenantID)
	if err != nil {
		return report, err
	}
	items := s.retentionIndex(ctx, h.TenantID)
	live := map[string]bool{}
	for _, t := range turns {
		live[t.TurnID] = true
	}
	// Historical gap reporting: turns already disposed and no longer
	// enumerable from live storage still appear in the coverage report
	// (C07 review finding 5) - derived from the durable lifecycle catalog,
	// never from workspace tables.
	for _, it := range items {
		if it.State != ItemDisposed || live[it.TurnID] {
			continue
		}
		if Matches(h, it.MatterID, it.CustodianID, it.RecordedAt) {
			report.DisposedBeforeHold = append(report.DisposedBeforeHold, it.TurnID)
		}
	}
	for _, t := range turns {
		if !Matches(h, t.MatterID, t.CustodianID, t.RecordedAt) {
			continue
		}
		if err := s.Store.CatalogTurn(ctx, h.TenantID, t, policy); err != nil {
			return report, err
		}
		item, known := items[t.TurnID]
		if known && item.State == ItemDisposed {
			report.DisposedBeforeHold = append(report.DisposedBeforeHold, t.TurnID)
			continue
		}
		// Version enumeration only exists for the retained profile; the
		// PostgreSQL profile's protection is the lifecycle fence itself.
		// Enumeration tolerates expired retention: a hold placed after the
		// retention deadline still protects the remaining bytes with a
		// storage legal hold (flagged as already_expired in the report).
		var refs []evidence.VersionRef
		if s.Retained {
			refs, err = s.disposalRefs(ctx, h.TenantID, t.TurnID)
			if err != nil || len(refs) == 0 {
				report.Uncovered = append(report.Uncovered, t.TurnID)
				continue
			}
			if s.Storage == nil {
				report.Uncovered = append(report.Uncovered, t.TurnID)
				continue
			}
			// Protection intent is committed durably BEFORE the native
			// mutation: if the process dies after SetLegalHold but before
			// the claim ledger commits, the native protection would be ON
			// with no ledger entry able to find and eventually clear it (an
			// unbounded retention leak). With pending claims committed
			// first, a crash converges: recovery re-establishes (the claims
			// are re-protected idempotently) or a release reconcile clears
			// them. The native mutation and its readback run under the
			// tenant protection fence, and the fence transaction re-loads
			// the hold's state first: a hold released between the two phases
			// never has its claims re-set natively (adversarial review).
			if err := s.withProtection(ctx, h.TenantID, func(tx pgx.Tx) error {
				for _, r := range refs {
					if err := UpsertClaim(ctx, tx, h.TenantID, h.ID, VersionRef(r)); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return report, err
			}
			if err := s.withProtection(ctx, h.TenantID, func(tx pgx.Tx) error {
				current, err := holdOfTx(ctx, tx, h.TenantID, h.ID)
				if err != nil {
					return err
				}
				// The hold's state may have PROGRESSED legitimately between
				// the two phases (pending -> effective by a concurrent
				// idempotent placement of the same hold): the protection
				// owner is unchanged. Stale means released (claims are being
				// reconciled by the release) or scope-changed (a newer epoch
				// owns the scope; that epoch's establishment covers it).
				if current == nil || current.State == HoldReleased || current.Epoch != h.Epoch {
					return ErrStaleEstablishment
				}
				for _, r := range refs {
					if s.Hooks.StorageFault != nil {
						if ferr := s.Hooks.StorageFault("protect"); ferr != nil {
							return ferr
						}
					}
					if err := s.Storage.SetLegalHold(ctx, r.Key, r.Version, true); err != nil {
						return fmt.Errorf("protect %s: %w", r.Key, err)
					}
					if s.Hooks.StorageFault != nil {
						if ferr := s.Hooks.StorageFault("readback"); ferr != nil {
							return ferr
						}
					}
					state, err := s.Storage.LegalHold(ctx, r.Key, r.Version)
					if err != nil || state != "ON" {
						return fmt.Errorf("protection readback failed for %s: %v", r.Key, err)
					}
					if err := MarkClaimProtected(ctx, tx, h.ID, VersionRef(r)); err != nil {
						return err
					}
					report.ProtectedVersions = append(report.ProtectedVersions, VersionRef(r))
				}
				return nil
			}); err != nil {
				return report, err
			}
		}
		expires := t.RecordedAt.Add(time.Duration(policy.RetentionSeconds) * time.Second)
		if known {
			expires = item.ExpiresAt
		}
		report.Items = append(report.Items, ReportedItem{
			TurnID: t.TurnID, Custodian: t.CustodianID, RecordedAt: t.RecordedAt,
			AlreadyExpired: time.Now().After(expires), ExpiresAt: expires, Versions: len(refs),
		})
	}
	return report, nil
}

// retentionIndex loads the tenant's lifecycle catalog as a map.
func (s *Service) retentionIndex(ctx context.Context, tenantID string) map[string]Item {
	items, err := s.Store.itemsOfTenant(ctx, tenantID)
	if err != nil {
		s.logf("records: catalog load: %v", err)
		return map[string]Item{}
	}
	out := make(map[string]Item, len(items))
	for _, it := range items {
		out[it.TurnID] = it
	}
	return out
}

// Release removes the hold's claim, then conservatively clears the storage
// legal holds that no remaining protection requires - derived from the
// durable version-claim ledger (never only the historical coverage report),
// under the tenant protection fence, so a newer hold's protection can never
// be cleared by a stale snapshot. Cleanup failures leave the claims in
// place (over-protection, never under-protection) and are retried by
// reconciliation.
func (s *Service) Release(ctx context.Context, p store.Principal, holdID, reason string) (*Hold, error) {
	before, err := s.Store.GetHold(ctx, p, holdID)
	if err != nil {
		return nil, err
	}
	h, err := s.Store.ReleaseHold(ctx, p, holdID, reason)
	if err != nil {
		return nil, err
	}
	if before.State == HoldReleased {
		// Idempotent retry still converges the outstanding cleanup claims.
		if err := s.reconcileClaims(ctx, h, &p.UserID); err != nil {
			s.logf("records: hold %s release cleanup retry: %v", holdID, err)
		}
		return s.Store.GetHold(ctx, p, holdID)
	}
	if err := s.reconcileClaims(ctx, h, &p.UserID); err != nil {
		s.logf("records: hold %s release cleanup: %v", holdID, err)
	}
	pending, err := s.claimsPending(ctx, h.ID)
	if err != nil {
		s.logf("records: hold %s cleanup pending load: %v", holdID, err)
	}
	if len(pending) > 0 {
		if merr := s.Store.MarkReleaseCleanup(ctx, holdID, pending); merr != nil {
			s.logf("records: cleanup pending recording: %v", merr)
		}
	}
	return s.Store.GetHold(ctx, p, holdID)
}

// claimsPending projects the hold's outstanding claims as the legacy report
// field.
func (s *Service) claimsPending(ctx context.Context, holdID string) ([]VersionRef, error) {
	claims, err := s.Store.ClaimsOfHold(ctx, holdID)
	if err != nil {
		return nil, err
	}
	var out []VersionRef
	for _, c := range claims {
		out = append(out, VersionRef{Key: c.Key, Version: c.Version})
	}
	return out, nil
}

// reconcileClaims clears the legal hold of every claimed version that no
// remaining protection requires: a version keeps its legal hold while ANY
// turn that references it is still held by an active hold (pending,
// effective or failed - pending and failed claims continue fencing) or is
// not disposed. Shared content-addressed objects are therefore never
// released while another protected record still requires the same bytes.
// The decision and the clear run under the tenant protection fence in one
// transaction, so no establishment can interleave (C07 review finding 1).
// actor is nil on the recovery path.
func (s *Service) reconcileClaims(ctx context.Context, h *Hold, actor *string) error {
	if !s.Retained || s.Storage == nil {
		return nil
	}
	return s.withProtection(ctx, h.TenantID, func(tx pgx.Tx) error {
		claims, err := claimsOfHold(ctx, tx, h.ID)
		if err != nil {
			return err
		}
		if len(claims) == 0 {
			return nil
		}
		claimed := map[VersionRef]bool{}
		for _, c := range claims {
			claimed[VersionRef{Key: c.Key, Version: c.Version}] = true
		}
		required, err := s.requiredVersions(ctx, tx, h.TenantID, claimed)
		if err != nil {
			return err
		}
		cleared := 0
		for _, c := range claims {
			v := VersionRef{Key: c.Key, Version: c.Version}
			if required[v] {
				continue
			}
			if s.Hooks.StorageFault != nil {
				if ferr := s.Hooks.StorageFault("cleanup"); ferr != nil {
					continue
				}
			}
			if err := s.Storage.SetLegalHold(ctx, v.Key, v.Version, false); err != nil {
				continue
			}
			state, err := s.Storage.LegalHold(ctx, v.Key, v.Version)
			if err != nil || state == "ON" {
				continue
			}
			if err := DeleteClaim(ctx, tx, h.ID, v); err != nil {
				return err
			}
			cleared++
		}
		remaining, err := claimsOfHold(ctx, tx, h.ID)
		if err != nil {
			return err
		}
		if len(remaining) == 0 && cleared > 0 {
			return auditCleanupComplete(ctx, tx, h.TenantID, actor, h.ID, cleared)
		}
		return nil
	})
}

// requiredVersions maps each claimed version to whether any turn that
// references it is still required by an active hold (any matter of the
// tenant: cross-matter references to shared content-addressed versions
// count). Enumeration is disposal-tolerant, so expired references still
// fence (C07 review finding 3D).
func (s *Service) requiredVersions(ctx context.Context, tx pgx.Tx, tenantID string, claimed map[VersionRef]bool) (map[VersionRef]bool, error) {
	out := map[VersionRef]bool{}
	turns, err := s.inventory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items := s.retentionIndex(ctx, tenantID)
	for _, t := range turns {
		item, known := items[t.TurnID]
		if known && item.State == ItemDisposed {
			continue
		}
		holds, err := ActiveHolds(ctx, tx, tenantID, t.MatterID)
		if err != nil {
			return nil, err
		}
		needed := false
		for _, h := range holds {
			if h.State == HoldReleased {
				continue
			}
			if Matches(h, t.MatterID, t.CustodianID, t.RecordedAt) {
				needed = true
				break
			}
		}
		if !needed {
			continue
		}
		refs, err := s.disposalRefs(ctx, tenantID, t.TurnID)
		if err != nil && !errors.Is(err, evidence.ErrNotFound) {
			// Unverifiable enumeration of a REQUIRED turn: fall back to the
			// namespace enumeration. If even that is unavailable, fail
			// closed (a release must never clear protection on unknown
			// references).
			fallback, ferr := s.namespaceRefs(ctx, tenantID, t.TurnID)
			if ferr != nil {
				return nil, fmt.Errorf("records: required-version scan: turn %s: %w (fallback: %v)", t.TurnID, err, ferr)
			}
			refs = fallback
		} else if errors.Is(err, evidence.ErrNotFound) {
			continue
		}
		for _, r := range refs {
			if claimed[VersionRef(r)] {
				out[VersionRef(r)] = true
			}
		}
	}
	return out, nil
}

// Inventory enumerates the tenant's turns from the authoritative backend.
func (s *Service) Inventory(ctx context.Context, p store.Principal) ([]evidence.TurnIdentity, error) {
	p, ok := canonP(p)
	if !ok {
		return nil, ErrForbidden
	}
	return s.inventory(ctx, p.TenantID)
}

// Sweep marks eligible items disposal_pending with the verified terminal
// capture state required for disposal eligibility: an admitted, actively
// executing turn is never swept, and a turn whose terminal state cannot be
// verified fails closed (C07 review finding 6A).
func (s *Service) Sweep(ctx context.Context, p store.Principal) (int, error) {
	p, ok := canonP(p)
	if !ok {
		return 0, ErrForbidden
	}
	turns, err := s.inventory(ctx, p.TenantID)
	if err != nil {
		return 0, err
	}
	policy, err := s.Store.Policy(ctx, p.TenantID)
	if err != nil {
		return 0, err
	}
	// Every admitted turn is cataloged (records metadata is complete);
	// terminality is a MARK-TIME check inside the sweep transaction
	// (fail closed), so an in-flight turn is cataloged but never marked.
	return s.Store.Sweep(ctx, p, turns, policy, s.terminalCheck)
}

// terminalCheck adapts the backend's terminality probe to the store's
// sweep-time check.
func (s *Service) terminalCheck(ctx context.Context, t evidence.TurnIdentity) (bool, error) {
	probe, ok := evidence.TerminalOf(s.Backend)
	if !ok {
		return false, errors.New("records: backend cannot verify terminal capture state")
	}
	return probe.TurnTerminal(ctx, t.TenantID, t.TurnID)
}

// VersionPresent reports whether the turn's versions are present or their
// presence is unresolved (conservative: absence requires plan verification).
func (s *Service) VersionPresent(ctx context.Context, tenantID, turnID string) bool {
	return s.versionPresent(ctx, tenantID, turnID)
}

// PresenceClassified reports the turn's classified byte presence.
func (s *Service) PresenceClassified(ctx context.Context, tenantID, turnID string) Presence {
	p, _ := s.classifyPresence(ctx, tenantID, turnID)
	return p
}

// ItemHeld reports whether the records officer's tenant holds the item.
func (s *Service) ItemHeld(ctx context.Context, p store.Principal, turnID string) (bool, Item, error) {
	p, ok := canonP(p)
	turnID, valid := store.CanonicalID(turnID)
	if !ok || !valid {
		return false, Item{}, ErrNotFound
	}
	items, err := s.Store.itemsOfTenant(ctx, p.TenantID)
	if err != nil {
		return false, Item{}, err
	}
	for _, it := range items {
		if it.TurnID != turnID {
			continue
		}
		holds, err := ActiveHolds(ctx, s.Store.DB, p.TenantID, it.MatterID)
		if err != nil {
			return false, Item{}, err
		}
		return Held(holds, it.MatterID, it.CustodianID, it.RecordedAt), it, nil
	}
	return false, Item{}, ErrNotFound
}

// Reestablish runs protection establishment for a pending hold (scope change
// or recovery) and records the outcome. The effective transition refuses
// uncovered records at the durable transition and binds to the hold's scope
// revision, so a stale establishment (prior scope) cannot complete.
func (s *Service) Reestablish(ctx context.Context, h *Hold) (Report, error) {
	report, err := s.establish(ctx, h)
	if err != nil {
		if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error(), h.Epoch); merr != nil {
			s.logf("records: hold %s failure recording: %v", h.ID, merr)
		}
		return report, err
	}
	if len(report.Uncovered) > 0 {
		err := fmt.Errorf("%d uncovered records block the effective transition", len(report.Uncovered))
		if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error(), h.Epoch); merr != nil {
			s.logf("records: hold %s failure recording: %v", h.ID, merr)
		}
		return report, fmt.Errorf("%w: %v", ErrConflict, err)
	}
	if err := s.Store.MarkEffective(ctx, h.ID, report, h.Epoch); err != nil {
		if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error(), h.Epoch); merr != nil {
			s.logf("records: hold %s failure recording: %v", h.ID, merr)
		}
		return report, err
	}
	return report, nil
}
