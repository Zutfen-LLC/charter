package records

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
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

func (s *Service) versionRefs(ctx context.Context, tenantID, turnID string) ([]evidence.VersionRef, error) {
	v, ok := evidence.VersionsOf(s.Backend)
	if !ok {
		return nil, errors.New("records: backend cannot enumerate versions")
	}
	return v.TurnVersionRefs(ctx, tenantID, turnID)
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

// versionPresent reports whether the turn's versions still enumerate from
// authoritative storage (conservative reconciliation of ambiguous deletes).
// Expired retention is fine here: presence, not durability.
func (s *Service) versionPresent(ctx context.Context, tenantID, turnID string) bool {
	if !s.Retained {
		return true
	}
	_, err := s.disposalRefs(ctx, tenantID, turnID)
	return err == nil
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
// every version of the turn published so far. It is idempotent and fails
// closed: any version that cannot be protected or verified is an error.
func (s *Service) EnsureProtected(ctx context.Context, tenant, turn string) error {
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
	for _, r := range refs {
		if s.Hooks.StorageFault != nil {
			if err := s.Hooks.StorageFault("protect"); err != nil {
				return err
			}
		}
		if err := s.Storage.SetLegalHold(ctx, r.Key, r.Version, true); err != nil {
			return fmt.Errorf("records: protect %s: %w", r.Key, err)
		}
		if s.Hooks.StorageFault != nil {
			if err := s.Hooks.StorageFault("readback"); err != nil {
				return err
			}
		}
		state, err := s.Storage.LegalHold(ctx, r.Key, r.Version)
		if err != nil || state != "ON" {
			return fmt.Errorf("records: protection readback failed for %s: %v", r.Key, err)
		}
	}
	return nil
}

// Place runs the full placement: the durable epoch+record transaction, then
// protection establishment over the authoritative inventory, then the
// effective transition. The response reports the final state; effective is
// acknowledged only after every in-scope version is verified protected.
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
		if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error()); merr != nil {
			s.logf("records: hold %s failure recording: %v", h.ID, merr)
		}
		return nil, fmt.Errorf("%w: protection establishment: %v", ErrRetry, err)
	}
	if err := s.Store.MarkEffective(ctx, h.ID, report); err != nil {
		return nil, err
	}
	return s.Store.GetHold(ctx, p, h.ID)
}

// establish applies and verifies protection for every in-scope turn from the
// authoritative backend inventory (never a workspace index), building the
// durable coverage report. Already-disposed items are recorded as gaps;
// items whose versions cannot be verified are uncovered (the hold cannot
// become effective while any remain).
func (s *Service) establish(ctx context.Context, h *Hold) (Report, error) {
	report := Report{}
	turns, err := s.inventory(ctx, h.TenantID)
	if err != nil {
		return report, err
	}
	policy, err := s.Store.Policy(ctx, h.TenantID)
	if err != nil {
		return report, err
	}
	items := s.retentionIndex(ctx, h.TenantID)
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
		}
		if s.Retained {
			if s.Storage == nil {
				report.Uncovered = append(report.Uncovered, t.TurnID)
				continue
			}
			for _, r := range refs {
				if s.Hooks.StorageFault != nil {
					if ferr := s.Hooks.StorageFault("protect"); ferr != nil {
						return report, ferr
					}
				}
				if err := s.Storage.SetLegalHold(ctx, r.Key, r.Version, true); err != nil {
					return report, fmt.Errorf("protect %s: %w", r.Key, err)
				}
				if s.Hooks.StorageFault != nil {
					if ferr := s.Hooks.StorageFault("readback"); ferr != nil {
						return report, ferr
					}
				}
				state, err := s.Storage.LegalHold(ctx, r.Key, r.Version)
				if err != nil || state != "ON" {
					return report, fmt.Errorf("protection readback failed for %s: %v", r.Key, err)
				}
				report.ProtectedVersions = append(report.ProtectedVersions, VersionRef(r))
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
// legal holds that no remaining protection requires. Cleanup failures are
// recorded as pending (over-protection, never under-protection) and are
// retried by reconciliation.
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
		return h, nil // idempotent retry
	}
	pending, err := s.cleanupRelease(ctx, before)
	if err != nil || len(pending) > 0 {
		s.logf("records: hold %s release cleanup pending (%d versions): %v", holdID, len(pending), err)
		if merr := s.Store.MarkReleaseCleanup(ctx, holdID, pending); merr != nil {
			s.logf("records: cleanup pending recording: %v", merr)
		}
	}
	return s.Store.GetHold(ctx, p, holdID)
}

// cleanupRelease clears the legal hold of every version that no remaining
// protection requires: a version keeps its legal hold while ANY turn that
// references it is still held by another active hold or is not disposed.
// Shared content-addressed objects are therefore never released while
// another protected record still requires the same bytes.
func (s *Service) cleanupRelease(ctx context.Context, h *Hold) ([]VersionRef, error) {
	if !s.Retained || s.Storage == nil {
		if len(h.Report.ProtectedVersions) > 0 {
			return h.Report.ProtectedVersions, nil // cleanup impossible, stays pending
		}
		return nil, nil
	}
	// Remaining holders: every other active hold matching a referencing turn.
	remaining, err := s.remainingHolders(ctx, h)
	if err != nil {
		return h.Report.ProtectedVersions, err
	}
	var pending []VersionRef
	for _, v := range h.Report.ProtectedVersions {
		if remaining[v] {
			continue
		}
		if s.Hooks.StorageFault != nil {
			if ferr := s.Hooks.StorageFault("cleanup"); ferr != nil {
				pending = append(pending, v)
				continue
			}
		}
		if err := s.Storage.SetLegalHold(ctx, v.Key, v.Version, false); err != nil {
			pending = append(pending, v)
			continue
		}
		state, err := s.Storage.LegalHold(ctx, v.Key, v.Version)
		if err != nil || state == "ON" {
			pending = append(pending, v)
		}
	}
	return pending, nil
}

// remainingHolders maps each protected version to whether any other turn
// still requires it: a referencing turn whose catalog state is not disposed
// and that is held by an active hold OTHER than the released one.
func (s *Service) remainingHolders(ctx context.Context, released *Hold) (map[VersionRef]bool, error) {
	out := map[VersionRef]bool{}
	protected := map[VersionRef]bool{}
	for _, v := range released.Report.ProtectedVersions {
		protected[v] = true
	}
	turns, err := s.inventory(ctx, released.TenantID)
	if err != nil {
		return nil, err
	}
	items := s.retentionIndex(ctx, released.TenantID)
	for _, t := range turns {
		item, known := items[t.TurnID]
		if known && item.State == ItemDisposed {
			continue
		}
		holds, err := ActiveHolds(ctx, s.Store.DB, released.TenantID, t.MatterID)
		if err != nil {
			return nil, err
		}
		needed := false
		for _, h := range holds {
			if h.ID == released.ID || h.State == HoldReleased {
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
		refs, err := s.versionRefs(ctx, released.TenantID, t.TurnID)
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			if protected[VersionRef(r)] {
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

// VersionPresent reports whether the turn's versions still enumerate.
func (s *Service) VersionPresent(ctx context.Context, tenantID, turnID string) bool {
	return s.versionPresent(ctx, tenantID, turnID)
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
// or recovery) and records the outcome.
func (s *Service) Reestablish(ctx context.Context, h *Hold) (Report, error) {
	report, err := s.establish(ctx, h)
	if err != nil {
		if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error()); merr != nil {
			s.logf("records: hold %s failure recording: %v", h.ID, merr)
		}
		return report, err
	}
	if err := s.Store.MarkEffective(ctx, h.ID, report); err != nil {
		return report, err
	}
	return report, nil
}
