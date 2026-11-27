package records

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
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
	// Head probes ONE exact version's physical presence. It is the ONLY
	// authoritative presence probe: the legal-hold lookup is unusable for
	// presence because the retained storage 404s it for versions that
	// carry no object-lock metadata (indistinguishable there from a
	// missing version). nil = present, ErrObjectAbsent = gone, any other
	// error = unknown (fail closed).
	Head(ctx context.Context, key, version string) error
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
	// BeforeApplicableReload runs at the start of the second phase of
	// EnsureProtected (the claims-commit transaction), before the
	// applicable hold set is re-loaded inside the protection fence: the
	// deterministic interleave point for a hold that becomes applicable
	// between the two phases (C07 round-2 finding 6).
	BeforeApplicableReload func()
	// BeforeNativeProtect runs BETWEEN the claims-commit transaction and
	// the native-mutation transaction of EnsureProtected's second phase,
	// before the protection fence is re-taken: the deterministic interleave
	// point for holds that change (placed, released, scope-revised)
	// between committed ownership preparation and the native phase (C07
	// round-3 finding 2), and the point from which committed ledger
	// visibility is provable from an independent database connection
	// before the first native mutation.
	BeforeNativeProtect func()
}

// maxEnsureProtectedAttempts bounds the claims-commit/native-mutation retry
// loop of EnsureProtected: repeated changes in the applicable hold set
// retry a bounded number of times and then fail closed WITHOUT any native
// mutation (an unbounded retry loop would never converge under a churn
// storm; the turn fails closed and the next pass converges).
const maxEnsureProtectedAttempts = 5

// errClaimsChanged is the internal retry sentinel of EnsureProtected: an
// applicable hold lacks a committed ownership claim for a version about to
// be natively protected, so the claims-commit phase must run again before
// any native mutation.
var errClaimsChanged = errors.New("records: applicable holds changed before the native mutation")

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
// enumeration is unavailable), with its completeness classification.
func (s *Service) namespaceRefs(ctx context.Context, tenantID, turnID string) (evidence.NamespaceEnumeration, error) {
	n, ok := evidence.NamespaceVersionsOf(s.Backend)
	if !ok {
		return evidence.NamespaceEnumeration{}, errors.New("records: backend cannot enumerate turn namespaces")
	}
	return n.TurnNamespaceRefs(ctx, tenantID, turnID)
}

// refSetResolution classifies how a turn's exact-version reference set was
// resolved for a fencing decision (C07 round-2 finding 3).
type refSetResolution int

const (
	// refSetVerified: the live verified enumeration succeeded, or the
	// namespace fallback enumerated completely.
	refSetVerified refSetResolution = iota
	// refSetPlan: the durable disposal plan supplied the exact version
	// identity (known partial references backed by durable state).
	refSetPlan
	// refSetAbsent: authoritatively nothing is left under the turn's
	// namespaces; the turn is not a live reference source.
	refSetAbsent
	// refSetUnknown: transient or permanent verification failure. The
	// caller must refuse the irreversible deletion or protection removal.
	refSetUnknown
)

// turnReferenceSet resolves the reference set of one turn for
// shared-reference fencing and required-version decisions. The verified
// enumeration is authoritative; when it is unavailable, a durable disposal
// plan supplies the exact version identity; the namespace fallback is used
// only when it enumerates COMPLETELY. An unknown reference set is never
// silently treated as an absent one.
// turnReferenceSet resolves the turn's authoritative reference set. The
// runner is the caller's connection: callers executing inside an open
// transaction pass it so the plan lookup reuses the transaction's
// connection (pool exhaustion under concurrent finishes would otherwise
// deadlock - C07 round-3 CI follow-up).
func (s *Service) turnReferenceSet(ctx context.Context, q queryRunner, tenantID, turnID string) ([]evidence.VersionRef, refSetResolution, error) {
	refs, err := s.disposalRefs(ctx, tenantID, turnID)
	if err == nil {
		return refs, refSetVerified, nil
	}
	// Durable reference information first: a disposal plan committed before
	// any deletion holds the turn's complete exact-version identity, so
	// known partial disposal stays recoverable without wedging unrelated
	// valid operations.
	if plan, perr := s.Store.planOf(ctx, q, tenantID, turnID); perr == nil && len(plan) > 0 {
		var out []evidence.VersionRef
		for _, row := range plan {
			if row.Disposition == OutcomeDeleted || row.Disposition == OutcomeAbsent {
				continue // already gone: not a live reference
			}
			out = append(out, evidence.VersionRef{Key: row.Key, Version: row.Version})
		}
		if len(out) > 0 {
			return out, refSetPlan, nil
		}
	}
	enum, nerr := s.namespaceRefs(ctx, tenantID, turnID)
	if nerr == nil {
		if enum.Complete {
			return enum.Refs, refSetVerified, nil
		}
		return nil, refSetUnknown, fmt.Errorf("records: turn %s: namespace references incomplete (verified enumeration: %v)", turnID, err)
	}
	if errors.Is(nerr, evidence.ErrNotFound) {
		return nil, refSetAbsent, nil
	}
	return nil, refSetUnknown, fmt.Errorf("records: turn %s: verified enumeration: %w (namespace: %v)", turnID, err, nerr)
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
func (s *Service) classifyPresence(ctx context.Context, q queryRunner, tenantID, turnID string) (Presence, string) {
	if s.Retained {
		// Runner-aware: in-transaction callers (the finisher's callbacks)
		// pass their transaction so the plan lookup reuses its connection.
		plan, err := s.Store.planOf(ctx, q, tenantID, turnID)
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
	p, _ := s.classifyPresence(ctx, s.Store.DB, tenantID, turnID)
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
//
// Phase 2 is TWO transactions (C07 round-3 finding 2): the claims-commit
// transaction durably commits the ownership claims of every newly
// applicable hold FIRST; the native-mutation transaction then re-loads the
// applicable holds, revalidates that every one of them has a COMMITTED
// claim row for every version (a successful UPDATE inside an open
// transaction is not proof of durable ownership), and only then performs
// SetLegalHold, readback and claim completion. A crash or rollback after
// the native mutation therefore always leaves a committed (pending or
// protected) claim that release cleanup and recovery can converge. Holds
// that change between the two transactions re-run the claims-commit phase
// a bounded number of times and then fail closed with no native mutation.
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
	// Phase 2a: commit the ownership claims of every newly applicable hold
	// (a hold released in between never receives claims here); phase 2b:
	// revalidate and mutate natively. Repeated applicability changes retry
	// the pair a bounded number of times (errClaimsChanged), then fail
	// closed without any native mutation.
	for attempt := 0; ; attempt++ {
		if attempt >= maxEnsureProtectedAttempts {
			return fmt.Errorf("records: applicable holds kept changing across %d attempts; no native mutation was performed (retry closed)", maxEnsureProtectedAttempts)
		}
		if err := s.withProtection(ctx, tenant, func(tx pgx.Tx) error {
			if attempt == 0 && s.Hooks.BeforeApplicableReload != nil {
				s.Hooks.BeforeApplicableReload()
			}
			current, err := holdsOfTx(ctx, tx, tenant)
			if err != nil {
				return err
			}
			for _, h := range current {
				if h.State == HoldReleased || !Matches(h, matter, custodian, recordedAt) {
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
		// The deterministic interleave point between committed ownership
		// preparation and the native mutation (no fence is held here).
		if s.Hooks.BeforeNativeProtect != nil {
			s.Hooks.BeforeNativeProtect()
		}
		err := s.withProtection(ctx, tenant, func(tx pgx.Tx) error {
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
			// Durable ownership revalidation: every applicable hold must
			// already have a COMMITTED claim row for every version about to
			// be natively protected (claims committed by phase 1/2a are
			// visible to this new transaction; a hold that became
			// applicable after the claims commit is not). A missing claim
			// restarts the claims-commit phase - the native mutation never
			// runs ahead of durable ownership.
			for id := range applicable {
				for _, r := range refs {
					var claimed bool
					if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM hold_version_claims WHERE hold_id=$1 AND key=$2 AND version=$3)`, id, r.Key, r.Version).Scan(&claimed); err != nil {
						return err
					}
					if !claimed {
						return errClaimsChanged
					}
				}
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
		if errors.Is(err, errClaimsChanged) {
			continue
		}
		return err
	}
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

// establish applies and verifies protection for every in-scope turn from
// the AUTHORITATIVE union of the live evidence inventory, the durable
// lifecycle catalog and the durable disposal plans (C07 round-2 finding
// 1), building the durable coverage report and the durable version-claim
// ledger. Disposed turns are recorded as gaps - both those still
// enumerable and those that already left the live inventory (the catalog's
// disposed rows); turns whose live enumeration root is gone but whose
// disposal plan still holds live rows are PARTIALLY DISPOSED: their
// remaining versions are protected and the loss is explicitly reported;
// records that cannot be verified at all (root gone, no plan) are
// uncovered and block the effective transition.
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
	items, err := s.Store.itemsOfTenant(ctx, h.TenantID)
	if err != nil {
		// A catalog-loading error is never an empty catalog: coverage
		// determination refuses to acknowledge on silently incomplete
		// inventory (C07 round-2 finding 1).
		return report, fmt.Errorf("records: lifecycle catalog: %w", err)
	}
	index := make(map[string]Item, len(items))
	for _, it := range items {
		index[it.TurnID] = it
	}
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
		item, known := index[t.TurnID]
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
			vrefs := make([]VersionRef, len(refs))
			for i, r := range refs {
				vrefs[i] = VersionRef(r)
			}
			if err := s.protectForHold(ctx, h, vrefs, &report); err != nil {
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
	// Matching catalog records that are NOT in the live inventory (the
	// enumeration root was deleted mid-disposal, or a restored record whose
	// root is gone): the durable disposal plan supplies the exact-version
	// identity. Without a plan the record is unverifiable: it is reported
	// uncovered and blocks the effective transition. Records are never
	// silently omitted because their normal enumeration root is missing.
	for _, it := range items {
		if live[it.TurnID] || it.State == ItemDisposed {
			continue
		}
		if !Matches(h, it.MatterID, it.CustodianID, it.RecordedAt) {
			continue
		}
		if err := s.coverPlanTurn(ctx, h, it, &report); err != nil {
			return report, err
		}
	}
	return report, nil
}

// coverPlanTurn establishes hold coverage for a matching catalog record
// whose live enumeration root is gone, from the durable disposal plan (the
// exact-version inventory committed before any irreversible deletion).
// Planned versions verified physically absent are recorded as an explicit
// partial loss; the remaining versions receive the same verified native
// protection as any live record. No plan means unverifiable: uncovered.
func (s *Service) coverPlanTurn(ctx context.Context, h *Hold, it Item, report *Report) error {
	if !s.Retained {
		// The PostgreSQL profile has no disposal plans (disposal is
		// refused there); a catalog record without a live enumeration root
		// cannot be verified.
		report.Uncovered = append(report.Uncovered, it.TurnID)
		return nil
	}
	if s.Storage == nil {
		report.Uncovered = append(report.Uncovered, it.TurnID)
		return nil
	}
	plan, err := s.Store.PlanOf(ctx, h.TenantID, it.TurnID)
	if err != nil {
		return err
	}
	if len(plan) == 0 {
		report.Uncovered = append(report.Uncovered, it.TurnID)
		return nil
	}
	var protect []VersionRef
	missing := 0
	for _, row := range plan {
		switch row.Disposition {
		case OutcomeDeleted, OutcomeAbsent:
			// Already dispositioned gone: still a LOSS for coverage
			// reporting (a durable record of loss is a loss, not
			// intactness - C07 round-3 finding 3), counted like a
			// storage-verified missing version.
			missing++
			continue
		}
		if herr := s.Storage.Head(ctx, row.Key, row.Version); herr != nil {
			if errors.Is(herr, s3transport.ErrObjectAbsent) {
				// Storage-verified partial loss: the plan keeps its durable
				// version identity and the loss stays attributable.
				missing++
				if merr := s.Store.MarkPlanAbsent(ctx, h.TenantID, it.TurnID, VersionRef{Key: row.Key, Version: row.Version}); merr != nil {
					return merr
				}
				continue
			}
			// The presence probe itself failed: coverage is unknown for
			// this record; the establishment fails (retryable) rather than
			// acknowledging silently incomplete coverage.
			return fmt.Errorf("records: plan presence probe %s: %w", row.Key, herr)
		}
		protect = append(protect, VersionRef{Key: row.Key, Version: row.Version})
	}
	if len(protect) > 0 {
		if err := s.protectForHold(ctx, h, protect, report); err != nil {
			return err
		}
	}
	report.PartiallyDisposed = append(report.PartiallyDisposed, it.TurnID)
	report.Items = append(report.Items, ReportedItem{
		TurnID: it.TurnID, Custodian: it.CustodianID, RecordedAt: it.RecordedAt,
		AlreadyExpired: time.Now().After(it.ExpiresAt), ExpiresAt: it.ExpiresAt,
		Versions: len(protect), PartiallyDisposed: true, MissingVersions: missing,
	})
	return nil
}

// protectForHold is the two-phase protection establishment for one exact
// version set on behalf of one hold: protection intent (claims) is
// committed durably BEFORE the native mutation - if the process dies after
// SetLegalHold but before the claim ledger commits, the native protection
// would be ON with no ledger entry able to find and eventually clear it
// (an unbounded retention leak). With pending claims committed first, a
// crash converges: recovery re-establishes (the claims are re-protected
// idempotently) or a release reconcile clears them. The native mutation
// and its readback run under the tenant protection fence, and the fence
// transaction re-loads the hold's state first: a hold released between the
// two phases never has its claims re-set natively (adversarial review).
func (s *Service) protectForHold(ctx context.Context, h *Hold, refs []VersionRef, report *Report) error {
	if err := s.withProtection(ctx, h.TenantID, func(tx pgx.Tx) error {
		for _, r := range refs {
			if err := UpsertClaim(ctx, tx, h.TenantID, h.ID, r); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return s.withProtection(ctx, h.TenantID, func(tx pgx.Tx) error {
		current, err := holdOfTx(ctx, tx, h.TenantID, h.ID)
		if err != nil {
			return err
		}
		// The hold's state may have PROGRESSED legitimately between the
		// two phases (pending -> effective by a concurrent idempotent
		// placement of the same hold): the protection owner is unchanged.
		// Stale means released (claims are being reconciled by the
		// release) or scope-changed (a newer epoch owns the scope; that
		// epoch's establishment covers it).
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
			if err := MarkClaimProtected(ctx, tx, h.ID, r); err != nil {
				return err
			}
			report.ProtectedVersions = append(report.ProtectedVersions, r)
		}
		return nil
	})
}

// retentionIndex loads the tenant's lifecycle catalog as a map. A catalog
// load failure is an error, never an empty catalog (C07 round-2 finding 1).
func (s *Service) retentionIndex(ctx context.Context, q queryRunner, tenantID string) (map[string]Item, error) {
	items, err := s.Store.itemsOf(ctx, q, tenantID)
	if err != nil {
		s.logf("records: catalog load: %v", err)
		return nil, err
	}
	out := make(map[string]Item, len(items))
	for _, it := range items {
		out[it.TurnID] = it
	}
	return out, nil
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
// count). The scan runs over the union of live turns and non-disposed
// catalog records (C07 round-2 finding 1), and reference resolution is
// fail-closed: a required turn whose reference set cannot be established
// is an ERROR - the release must never clear protection on unknown
// references (C07 round-2 finding 3).
func (s *Service) requiredVersions(ctx context.Context, tx pgx.Tx, tenantID string, claimed map[VersionRef]bool) (map[VersionRef]bool, error) {
	out := map[VersionRef]bool{}
	turns, err := s.inventory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	// The index and reference resolution reuse the caller's transaction
	// connection (see turnReferenceSet).
	items, err := s.retentionIndex(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	for _, t := range turns {
		live[t.TurnID] = true
	}
	scan := func(matterID, custodianID string, recordedAt time.Time, turnID string, known bool, state string) error {
		if known && state == ItemDisposed {
			return nil
		}
		holds, err := ActiveHolds(ctx, tx, tenantID, matterID)
		if err != nil {
			return err
		}
		needed := false
		for _, h := range holds {
			if h.State == HoldReleased {
				continue
			}
			if Matches(h, matterID, custodianID, recordedAt) {
				needed = true
				break
			}
		}
		if !needed {
			return nil
		}
		refs, res, rerr := s.turnReferenceSet(ctx, tx, tenantID, turnID)
		switch res {
		case refSetVerified, refSetPlan:
			for _, r := range refs {
				if claimed[VersionRef(r)] {
					out[VersionRef(r)] = true
				}
			}
			return nil
		case refSetAbsent:
			return nil
		default:
			// Unverifiable enumeration of a REQUIRED turn: never clear
			// protection on unknown references.
			return fmt.Errorf("records: required-version scan: turn %s: %w", turnID, rerr)
		}
	}
	for _, t := range turns {
		item, known := items[t.TurnID]
		if err := scan(t.MatterID, t.CustodianID, t.RecordedAt, t.TurnID, known, item.State); err != nil {
			return nil, err
		}
	}
	// Non-live, non-disposed catalog records still reference their
	// remaining planned versions: expiry-tolerant, plan-backed fencing.
	for _, it := range items {
		if live[it.TurnID] || it.State == ItemDisposed {
			continue
		}
		if err := scan(it.MatterID, it.CustodianID, it.RecordedAt, it.TurnID, true, it.State); err != nil {
			return nil, err
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
// verified fails closed (C07 review finding 6A). The sweep covers the
// union of live inventory turns and ACTIVE catalog records whose live
// enumeration root is gone (a partially disposed record restored to active
// stays disposable through its durable catalog identity - C07 round-2
// finding 4).
func (s *Service) Sweep(ctx context.Context, p store.Principal) (int, error) {
	p, ok := canonP(p)
	if !ok {
		return 0, ErrForbidden
	}
	turns, err := s.inventory(ctx, p.TenantID)
	if err != nil {
		return 0, err
	}
	live := map[string]bool{}
	for _, t := range turns {
		live[t.TurnID] = true
	}
	items, err := s.Store.itemsOfTenant(ctx, p.TenantID)
	if err != nil {
		return 0, err
	}
	for _, it := range items {
		if live[it.TurnID] || it.State != ItemActive {
			continue
		}
		turns = append(turns, evidence.TurnIdentity{
			TenantID: it.TenantID, ProjectID: it.ProjectID, MatterID: it.MatterID,
			CustodianID: it.CustodianID, TurnID: it.TurnID, RecordedAt: it.RecordedAt,
		})
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
// sweep-time check, with DURABLE plan-backed proof of previously verified
// terminality (C07 round-3 finding 3). A disposal plan is committed only
// by the authorized disposal lifecycle for an item whose sweep-time
// terminality was already VERIFIED (active -> disposal_pending requires a
// terminal probe; begin_purge and the plan phase require disposal_pending
// and purging under the matter epoch), the plan is bound to the exact
// (tenant, turn) identity, and terminality is monotonic once observed -
// so a non-empty durable plan is POSITIVE durable evidence of previously
// verified terminality, never an inference from missing evidence: the live
// probe's "non-terminal" or failure after the terminal event data or
// marker was deleted mid-disposal is missing evidence, not
// counterevidence. A turn WITHOUT a plan (an in-flight capture, or any
// never-disposed turn) is decided by the live probe alone and fails
// closed on verification errors - nothing may infer terminality from a
// missing probe answer.
func (s *Service) terminalCheck(ctx context.Context, tx pgx.Tx, t evidence.TurnIdentity) (bool, error) {
	var (
		terminal bool
		perr     error
		probed   bool
	)
	if probe, ok := evidence.TerminalOf(s.Backend); ok {
		probed = true
		terminal, perr = probe.TurnTerminal(ctx, t.TenantID, t.TurnID)
	} else {
		perr = errors.New("records: backend cannot verify terminal capture state")
	}
	if perr == nil && terminal {
		return true, nil
	}
	if s.Retained {
		// The plan lookup reuses the sweep transaction's connection (the
		// check runs inside it): no second pooled acquisition while the
		// item lock is held (C07 round-3 CI follow-up).
		if plan, err := s.Store.planOf(ctx, tx, t.TenantID, t.TurnID); err == nil && len(plan) > 0 {
			// Durable proof of previously verified terminality, bound to
			// this exact turn's authorized disposal lifecycle.
			return true, nil
		}
	}
	if !probed || perr != nil {
		// No verified terminal state: fail closed, never mark.
		return false, perr
	}
	return terminal, nil
}

// VersionPresent reports whether the turn's versions are present or their
// presence is unresolved (conservative: absence requires plan verification).
func (s *Service) VersionPresent(ctx context.Context, tenantID, turnID string) bool {
	return s.versionPresent(ctx, tenantID, turnID)
}

// PresenceClassified reports the turn's classified byte presence.
func (s *Service) PresenceClassified(ctx context.Context, tenantID, turnID string) Presence {
	p, _ := s.classifyPresence(ctx, s.Store.DB, tenantID, turnID)
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
