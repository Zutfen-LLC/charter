package records

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Revalidation checks the frozen records, not a fresh selection. Later
// captures cannot grow the approved scope. Any hold epoch change invalidates
// the request; the caller keeps the tenant lock across the audited commit.
func (s *Service) revalidateFrozenExport(ctx context.Context, tx pgx.Tx, frozen ExportSnapshot, i ExportIntent) error {
	if len(frozen.Records) == 0 || len(frozen.Records) > maxExportSnapshotRecords || len(frozen.HoldIDs) == 0 {
		return ErrExportConflict
	}
	if err := lockProtection(ctx, tx, frozen.TenantID); err != nil {
		return err
	}
	ids := make([]string, 0, len(frozen.Records))
	for _, r := range frozen.Records {
		ids = append(ids, r.TurnID)
	}
	rows, err := tx.Query(ctx, `SELECT tenant_id::text, turn_id::text, matter_id::text, project_id::text, custodian_id::text,
  recorded_at, retention_expires_at, state, observed_epoch, pending_since, sweep_by::text, purge_by::text, tombstoned_at, purged_at
  FROM retention_items WHERE tenant_id=$1 AND project_id=$2 AND matter_id=$3 AND turn_id::text = ANY($4::text[])
  ORDER BY turn_id FOR UPDATE`, frozen.TenantID, i.ProjectID, i.MatterID, ids)
	if err != nil {
		return err
	}
	locked, err := scanItems(rows, nil)
	if err != nil {
		return err
	}
	if len(locked) != len(frozen.Records) {
		return ErrExportConflict
	}
	byID := make(map[string]Item, len(locked))
	for _, it := range locked {
		byID[it.TurnID] = it
	}
	epoch, err := lockEpoch(ctx, tx, frozen.TenantID, i.MatterID, false)
	if err != nil {
		return err
	}
	// Deterministic interleave point for concurrency qualification: the
	// revalidating transaction holds the protection fence, the frozen
	// records' rows and the matter epoch row at this point, so a concurrent
	// hold release or scope change blocks on the epoch row until the
	// revalidation commits.
	s.Store.hookEpoch("export_revalidate", frozen.TenantID, i.MatterID)
	if epoch != frozen.Epoch {
		return ErrExportConflict
	}
	holds, err := ActiveHolds(ctx, tx, frozen.TenantID, i.MatterID)
	if err != nil {
		return err
	}
	for _, r := range frozen.Records {
		it, ok := byID[r.TurnID]
		if !ok || it.State != r.State || it.CustodianID != r.CustodianID || !it.RecordedAt.Equal(r.RecordedAt) || !contains(i.CustodianIDs, it.CustodianID) || it.RecordedAt.Before(i.WindowStart) || !it.RecordedAt.Before(i.WindowEnd) {
			return ErrExportConflict
		}
		for _, id := range r.HeldBy {
			valid := false
			for _, h := range holds {
				if h.ID == id && h.State == HoldEffective && Matches(h, it.MatterID, it.CustodianID, it.RecordedAt) {
					valid = true
					break
				}
			}
			if !valid {
				return ErrExportConflict
			}
		}
	}
	return nil
}
