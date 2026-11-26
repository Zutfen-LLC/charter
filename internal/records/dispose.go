package records

import (
	"context"
	"errors"
	"fmt"

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

// FinishPurge is the conditional delete: it succeeds only if the matter's
// hold epoch is still the value begin_purge observed. The epoch row is
// locked FOR UPDATE for the whole transaction, including the irreversible
// storage deletes, so a hold that commits after the delete commits observes
// a disposed item (recorded gap), and a hold acknowledged before the delete
// commits always wins (ADR 0001 section 7 linearization).
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
	err := s.Store.FinishPurgeTx(ctx, actor, tenantID, turnID, func(ctx context.Context, it Item) (map[string]string, error) {
		// Enumerate the versions the turn consists of, minus every version
		// still referenced by another non-disposed turn: a disposal of one
		// reference never removes bytes another record still requires.
		refs, err := s.disposalRefs(ctx, it.TenantID, it.TurnID)
		if err != nil {
			return nil, fmt.Errorf("enumerate versions: %w", err)
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
		return s.versionPresent(ctx, tenantID, turnID), nil
	}, &outcome)
	if err != nil {
		return outcome, outcomes, err
	}
	return outcome, outcomes, nil
}

// sharedReferences reports which of the turn's versions are also referenced
// by another turn that is not disposed: those bytes must survive this
// disposal.
func (s *Service) sharedReferences(ctx context.Context, it Item) (map[VersionRef]bool, error) {
	turns, err := s.inventory(ctx, it.TenantID)
	if err != nil {
		return nil, err
	}
	items := s.retentionIndex(ctx, it.TenantID)
	mine, err := s.disposalRefs(ctx, it.TenantID, it.TurnID)
	if err != nil {
		return nil, err
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
		refs, err := s.disposalRefs(ctx, it.TenantID, t.TurnID)
		if err != nil {
			return nil, err
		}
		for _, r := range refs {
			if own[VersionRef(r)] {
				shared[VersionRef(r)] = true
			}
		}
	}
	return shared, nil
}

// Recover reconciles every incomplete or ambiguous lifecycle operation from
// durable state plus the authoritative backend: pending/failed holds are
// re-established, release cleanups retried, purging items completed, and
// disposal_pending items whose bytes already vanished are conservatively
// marked disposed. It never consults workspace tables, and it is idempotent.
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
		report, err := s.establish(ctx, h)
		if err != nil {
			if merr := s.Store.MarkFailed(ctx, h.ID, report, err.Error()); merr != nil {
				s.logf("records: recover hold %s: %v", h.ID, merr)
			}
			continue
		}
		if err := s.Store.MarkEffective(ctx, h.ID, report); err != nil {
			s.logf("records: recover hold %s: %v", h.ID, err)
		}
	}
	// 2. Released holds with cleanup still pending.
	released, err := s.Store.HoldsInState(ctx, HoldReleased)
	if err != nil {
		return err
	}
	for _, h := range released {
		if len(h.Report.ReleaseCleanupPending) == 0 {
			continue
		}
		pending, err := s.cleanupRelease(ctx, h)
		if err != nil || len(pending) > 0 {
			s.logf("records: hold %s cleanup still pending: %v", h.ID, err)
		}
		if merr := s.Store.MarkReleaseCleanup(ctx, h.ID, pending); merr != nil {
			s.logf("records: cleanup recording: %v", merr)
		}
	}
	// 3. Purging items: complete the conditional delete (deterministic
	// recovery of the interrupted operation; the fencing is identical).
	purging, err := s.Store.ItemsInState(ctx, ItemPurging)
	if err != nil {
		return err
	}
	for _, it := range purging {
		if _, _, err := s.FinishPurge(ctx, nil, it.TurnID); err != nil {
			s.logf("records: recover purge %s: %v", it.TurnID, err)
		}
	}
	// 4. Disposal-pending or purging items whose bytes already vanished:
	// never tombstone or keep pending a record that no longer exists.
	ambiguous, err := s.Store.ItemsInState(ctx, ItemDisposalPending, ItemPurging)
	if err != nil {
		return err
	}
	for _, it := range ambiguous {
		if s.versionPresent(ctx, it.TenantID, it.TurnID) {
			continue
		}
		if err := s.Store.MarkDisposedAmbiguous(ctx, it); err != nil {
			s.logf("records: ambiguous disposal %s: %v", it.TurnID, err)
		}
	}
	return nil
}
