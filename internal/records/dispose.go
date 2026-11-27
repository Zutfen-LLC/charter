package records

import (
	"context"
	"errors"
	"fmt"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// Version disposal outcomes (per exact version).
const (
	OutcomeDeleted        = "deleted"
	OutcomeAbsent         = "absent" // already gone; idempotent completion
	OutcomeRetainedShared = "retained_shared"
	OutcomeProtected      = "protected" // storage refused: retention or legal hold active
)

// FinishPurge is the conditional delete. It runs in two durable phases:
//
//   - The plan phase commits the exact-version disposal plan BEFORE any
//     irreversible deletion, so an interrupted deletion resumes from the
//     plan without requiring already-deleted enumeration metadata and every
//     planned version receives a verified disposition (C07 review finding 5).
//
//   - The delete phase holds the tenant protection fence and the matter's
//     hold epoch across the irreversible storage deletes (the conditional
//     delete fence of ADR 0001 section 7): a hold that commits after the
//     delete commits observes a disposed item (recorded gap), a hold
//     acknowledged before the delete commits always wins, and a concurrent
//     capture cannot acquire a reference to an exact version between the
//     shared-reference snapshot and its deletion (C07 review finding 6B).
//
// actor is nil on the service-initiated recovery path: the fencing is
// identical, and recovery is independent of user authorization (the purge was
// already approved by a records officer at begin_purge).
func (s *Service) FinishPurge(ctx context.Context, actor *store.Principal, turnID string) (string, map[string]string, error) {
	if !s.Retained {
		return "", nil, fmt.Errorf("%w: this evidence backend does not support disposal", ErrBlockedStorage)
	}
	if s.Storage == nil {
		return "", nil, fmt.Errorf("%w: records storage transport unavailable", ErrBlockedStorage)
	}
	tenantID := ""
	if actor != nil {
		p, ok := canonP(*actor)
		if !ok {
			return "", nil, ErrForbidden
		}
		*actor = p
		tenantID = p.TenantID
	} else {
		// Recovery path (no actor): resolve the item's tenant from durable
		// state; the fencing is identical.
		if err := s.Store.DB.QueryRow(ctx, `SELECT tenant_id::text FROM retention_items WHERE turn_id=$1 AND state='purging' LIMIT 1`, turnID).Scan(&tenantID); err != nil {
			return "", nil, ErrNotFound
		}
	}
	outcomes := map[string]string{}
	outcome := ""
	// Phase 1: the durable plan (committed before any delete).
	if err := s.Store.FinishPurgePlanTx(ctx, actor, tenantID, turnID, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return s.disposalRefs(ctx, tenantID, turnID)
	}, &outcome); err != nil {
		return outcome, outcomes, err
	}
	// Phase 2: the fenced conditional delete.
	err := s.Store.FinishPurgeTx(ctx, actor, tenantID, turnID, func(ctx context.Context, it Item) (map[string]string, error) {
		plan, err := s.Store.PlanOf(ctx, it.TenantID, it.TurnID)
		if err != nil {
			return nil, err
		}
		var refs []VersionRef
		if len(plan) > 0 {
			for _, r := range plan {
				if r.Disposition == OutcomeDeleted || r.Disposition == OutcomeAbsent {
					// Already dispositioned (idempotent completion).
					outcomes[r.Key+"|"+r.Version] = r.Disposition
					continue
				}
				refs = append(refs, VersionRef{Key: r.Key, Version: r.Version})
			}
		} else {
			// No plan (legacy path): enumerate now, before any deletion.
			enumRefs, enumErr := s.disposalRefs(ctx, it.TenantID, it.TurnID)
			if enumErr != nil {
				return nil, fmt.Errorf("enumerate versions: %w", enumErr)
			}
			for _, r := range enumRefs {
				refs = append(refs, VersionRef(r))
			}
		}
		shared, err := s.sharedReferences(ctx, it)
		if err != nil {
			return nil, err
		}
		blocked := false
		for _, r := range refs {
			v := VersionRef(r)
			if shared[v] {
				outcomes[v.Key+"|"+v.Version] = OutcomeRetainedShared
				continue
			}
			if s.Hooks.BeforeStorageDelete != nil {
				s.Hooks.BeforeStorageDelete(v.Key, v.Version)
			}
			err := s.Storage.DeleteVersion(ctx, v.Key, v.Version)
			if s.Hooks.AfterStorageDelete != nil {
				s.Hooks.AfterStorageDelete(v.Key, v.Version, err)
			}
			switch {
			case err == nil:
				outcomes[v.Key+"|"+v.Version] = OutcomeDeleted
			case errors.Is(err, s3transport.ErrObjectAbsent):
				outcomes[v.Key+"|"+v.Version] = OutcomeAbsent
			case errors.Is(err, s3transport.ErrObjectProtected):
				outcomes[v.Key+"|"+v.Version] = OutcomeProtected
				blocked = true
			default:
				return nil, fmt.Errorf("delete %s: %w", v.Key, err)
			}
		}
		if blocked {
			return nil, ErrBlockedStorage
		}
		return outcomes, nil
	}, func(ctx context.Context, turnID string) (bool, error) {
		p, detail := s.classifyPresence(ctx, tenantID, turnID)
		switch p {
		case PresencePresent, PresencePartial:
			return true, nil
		case PresenceAbsent:
			return false, nil
		default:
			return false, fmt.Errorf("records: presence unresolved (%s)", detail)
		}
	}, &outcome)
	if err != nil {
		return outcome, outcomes, err
	}
	return outcome, outcomes, nil
}

// sharedReferences reports which of the turn's versions are also referenced
// by another turn that is not disposed: those bytes must survive this
// disposal. The scan runs inside the delete transaction under the tenant
// protection fence, so a capture cannot acquire a new reference to the same
// exact version between this snapshot and the deletion.
func (s *Service) sharedReferences(ctx context.Context, it Item) (map[VersionRef]bool, error) {
	turns, err := s.inventory(ctx, it.TenantID)
	if err != nil {
		return nil, err
	}
	items := s.retentionIndex(ctx, it.TenantID)
	mine, err := s.disposalRefs(ctx, it.TenantID, it.TurnID)
	if err != nil {
		planRefs := s.planRefs(ctx, it)
		if len(planRefs) > 0 {
			// The enumeration root may already be gone mid-plan; the plan
			// remains the authoritative version set.
			mine = planRefs
		} else {
			return nil, err
		}
	}
	own := map[VersionRef]bool{}
	for _, r := range mine {
		own[VersionRef(r)] = true
	}
	shared := map[VersionRef]bool{}
	for _, t := range turns {
		if t.TurnID == it.TurnID {
			continue
		}
		if item, known := items[t.TurnID]; known && item.State == ItemDisposed {
			continue
		}
		enumRefs, err := s.disposalRefs(ctx, it.TenantID, t.TurnID)
		if err != nil {
			return nil, err
		}
		for _, r := range enumRefs {
			if own[VersionRef(r)] {
				shared[VersionRef(r)] = true
			}
		}
	}
	return shared, nil
}

// planRefs projects the turn's disposal plan as its exact version set.
func (s *Service) planRefs(ctx context.Context, it Item) []evidence.VersionRef {
	plan, err := s.Store.PlanOf(ctx, it.TenantID, it.TurnID)
	if err != nil {
		return nil
	}
	var out []evidence.VersionRef
	for _, r := range plan {
		out = append(out, evidence.VersionRef{Key: r.Key, Version: r.Version})
	}
	return out
}

// Recover reconciles every incomplete or ambiguous lifecycle operation from
// durable state plus the authoritative backend: pending/failed holds are
// re-established (the effective transition refuses uncovered records and
// binds to the scope revision), released and narrowed holds' outstanding
// protection claims are reconciled (cleanup converges), purging items are
// completed from their durable disposal plans, and presence observations are
// classified so a storage outage can never become proof of disposal. It
// never consults workspace tables, and it is idempotent.
func (s *Service) Recover(ctx context.Context) error {
	// 1. Holds still awaiting verified protection.
	pending, err := s.Store.HoldsInState(ctx, HoldPending, HoldFailed)
	if err != nil {
		return err
	}
	for _, h := range pending {
		if h.State == HoldReleased {
			continue
		}
		if _, err := s.Reestablish(ctx, h); err != nil {
			s.logf("records: recover hold %s: %v", h.ID, err)
		}
	}
	// 2. Outstanding protection claims of EVERY hold (released holds and
	// narrowed scopes alike): cleanup converges from the durable claim
	// ledger, with recovery attribution.
	holds, err := s.Store.HoldsInState(ctx, HoldPending, HoldFailed, HoldEffective, HoldReleased)
	if err != nil {
		return err
	}
	for _, h := range holds {
		claims, err := s.Store.ClaimsOfHold(ctx, h.ID)
		if err != nil {
			s.logf("records: recover claims of hold %s: %v", h.ID, err)
			continue
		}
		if len(claims) == 0 {
			continue
		}
		if err := s.reconcileClaims(ctx, h, nil); err != nil {
			s.logf("records: hold %s cleanup still pending: %v", h.ID, err)
		}
		if pending, err := s.claimsPending(ctx, h.ID); err == nil {
			if merr := s.Store.MarkReleaseCleanup(ctx, h.ID, pending); merr != nil {
				s.logf("records: cleanup recording: %v", merr)
			}
		}
	}
	// 3. Purging items: complete the conditional delete from the durable
	// plan (deterministic recovery of the interrupted operation; the
	// fencing is identical).
	purging, err := s.Store.ItemsInState(ctx, ItemPurging)
	if err != nil {
		return err
	}
	for _, it := range purging {
		if _, _, err := s.FinishPurge(ctx, nil, it.TurnID); err != nil {
			s.logf("records: recover purge %s: %v", it.TurnID, err)
		}
	}
	// 4. Disposal-pending or purging items whose bytes may have vanished:
	// only PLAN-VERIFIED absence may complete a disposal; unknown and
	// partial observations retain conservative state (never a disposal
	// claim without proof of physical absence).
	ambiguous, err := s.Store.ItemsInState(ctx, ItemDisposalPending, ItemPurging)
	if err != nil {
		return err
	}
	for _, it := range ambiguous {
		p, detail := s.classifyPresence(ctx, it.TenantID, it.TurnID)
		switch p {
		case PresenceAbsent:
			if err := s.Store.MarkDisposedAmbiguous(ctx, it); err != nil {
				s.logf("records: ambiguous disposal %s: %v", it.TurnID, err)
			}
		case PresencePartial:
			s.logf("records: presence of %s is partial (%s); state retained", it.TurnID, detail)
			if err := s.Store.auditPresencePartial(ctx, it.TenantID, it.TurnID, detail); err != nil {
				s.logf("records: presence audit %s: %v", it.TurnID, err)
			}
		case PresenceUnknown:
			s.logf("records: presence of %s is unresolved (%s); state retained", it.TurnID, detail)
		default:
			// Present: nothing to reconcile.
		}
	}
	return nil
}
