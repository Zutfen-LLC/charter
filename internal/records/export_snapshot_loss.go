package records

import (
	"context"
	"errors"
	"fmt"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/jackc/pgx/v5"
)

type frozenExportPresence struct {
	survivors      []evidence.VersionRef
	shared         []ExportSnapshotSharedVersion
	missing        []ExportSnapshotMissingVersion
	classification string
}

// Freeze the union of plan and verified live references inside the existing
// protection/epoch fence. A plan records intent, not loss: only its durable
// dispositions or an exact-version absence can authorize a declared gap.
//
// Logical disposition and physical presence are distinct facts. A completed
// disposal's retained_shared rows are attributed as exact versions that
// physically survived through OTHER records' references: the durable plan
// disposition is the authority, so the survivor is neither re-derived from
// present-day storage state nor declared deleted or absent. A disposed
// record therefore never regains content authority (no export readback, no
// native-hold requirement of its own) through bytes another record retains,
// and its export cannot wedge merely because the retaining record's hold is
// absent: the surviving bytes' protection is the retaining record's
// responsibility, established by that record's own hold.
func (s *Service) freezeExportPresence(ctx context.Context, tx pgx.Tx, item Item, plan []PlanRow) (frozenExportPresence, error) {
	out := frozenExportPresence{classification: "complete"}
	if s.Storage == nil {
		return out, ErrExportConflict
	}
	disposed := item.State == ItemDisposed
	var live []evidence.VersionRef
	var err error
	if len(plan) == 0 {
		if disposed {
			return out, errors.New("disposed export has no attributable plan")
		}
		var resolution refSetResolution
		live, resolution, err = s.turnReferenceSet(ctx, tx, item.TenantID, item.TurnID)
		if err != nil || resolution != refSetVerified || len(live) == 0 {
			return out, fmt.Errorf("complete export reference set not verifiable: %w", errors.Join(ErrExportConflict, err))
		}
	} else {
		live, err = s.planCoverageRefs(ctx, item.TenantID, item.TurnID)
		if err != nil {
			return out, err
		}
	}
	planned := make(map[evidence.VersionRef]PlanRow, len(plan))
	candidates := make([]evidence.VersionRef, 0, len(plan))
	for _, row := range plan {
		ref := evidence.VersionRef{Key: row.Key, Version: row.Version}
		planned[ref] = row
		candidates = append(candidates, ref)
	}
	all := unionRefs(live, candidates)
	if len(all) == 0 || len(all) > 4096 {
		return out, ErrExportConflict
	}
	for _, r := range all {
		row, known := planned[r]
		disposition := ""
		if known && (row.Disposition == OutcomeDeleted || row.Disposition == OutcomeAbsent) {
			disposition = row.Disposition
		} else if known && disposed && row.Disposition == OutcomeRetainedShared {
			out.shared = append(out.shared, ExportSnapshotSharedVersion{Key: r.Key, Version: r.Version, Disposition: OutcomeRetainedShared, PlanEpoch: row.PlanEpoch})
			continue
		} else if err := s.Storage.Head(ctx, r.Key, r.Version); err != nil {
			if !known || !errors.Is(err, s3transport.ErrObjectAbsent) {
				return out, fmt.Errorf("unverified exact export version presence: %w", err)
			}
			disposition = "readback_absent"
		}
		if disposition != "" {
			out.missing = append(out.missing, ExportSnapshotMissingVersion{Key: r.Key, Version: r.Version, Disposition: disposition, PlanEpoch: row.PlanEpoch})
			continue
		}
		if disposed {
			// A physically present version of a completed disposal without a
			// durable retained_shared disposition has no attributable
			// authority. Fail closed: neither content export nor a
			// fabricated loss declaration is permitted.
			return out, fmt.Errorf("disposed record has an undispositioned surviving exact version %s: %w", r.Key, ErrExportConflict)
		}
		mode, err := s.Storage.LegalHold(ctx, r.Key, r.Version)
		if err != nil || mode != "ON" {
			return out, fmt.Errorf("unverified exact export version custody: %w", errors.Join(ErrExportConflict, err))
		}
		out.survivors = append(out.survivors, r)
	}
	if disposed {
		out.classification = "disposed"
	} else if len(out.missing) > 0 {
		out.classification = "partial_loss"
		if len(out.survivors) == 0 {
			out.classification = "complete_loss"
		}
	}
	return out, nil
}
