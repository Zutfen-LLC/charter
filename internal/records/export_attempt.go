package records

import (
	"context"

	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
)

// RecordExportAttemptFailure records a retryable generation failure without
// publishing any bytes. A mismatched/stale attempt never changes newer work.
// Permanent invalidity (the assembled candidate failed the same offline
// verifier) is terminal; a fresh request, snapshot and approval are required.
func (s *Store) RecordExportAttemptFailure(ctx context.Context, p store.Principal, id, attempt, stage string) error {
	p, ok := canonP(p)
	if !ok {
		return ErrForbidden
	}
	state := ExportApproved
	switch stage {
	case "readback", "publish":
	case "verification":
		state = ExportFailed
	default:
		return ErrNotFound
	}
	return s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		e, err := loadExport(ctx, tx, p.TenantID, id)
		if err != nil {
			return err
		}
		if e.RequesterID != p.UserID {
			return ErrForbidden
		}
		if e.State != ExportGenerating || e.AttemptToken == nil || *e.AttemptToken != attempt {
			return ErrExportConflict
		}
		tag, err := tx.Exec(ctx, `UPDATE scoped_exports SET state=$3,attempt_token=NULL,lease_until=NULL,
   expires_at=CASE WHEN $3='failed' THEN NULL ELSE expires_at END
   WHERE tenant_id=$1 AND id=$2 AND attempt_token=$4 AND expires_at>clock_timestamp() AND lease_until>clock_timestamp()`, p.TenantID, id, state, attempt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrExportConflict
		}
		return audit(ctx, tx, p.TenantID, &p.UserID, "export.attempt_failed", map[string]any{"export_id": id, "snapshot_digest": e.SnapshotDigest, "stage": stage, "disposition": state})
	})
}
