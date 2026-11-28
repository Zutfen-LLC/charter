package records

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExportCustodyAudit is a sanitized projection of a persisted audit row. It is
// not the raw JSON payload. Only the two authorizing actions are eligible.
type ExportCustodyAudit struct {
	ID, Action, ActorID, TenantID, ExportID, SnapshotDigest, IntentDigest string
	At                                                                    time.Time
}

func loadExportCustodyAudit(ctx context.Context, tx pgx.Tx, e ExportSummary) ([]ExportCustodyAudit, error) {
	if e.ApproverID == nil {
		return nil, ErrExportConflict
	}
	rows, err := tx.Query(ctx, `SELECT id,at,action,COALESCE(actor_id::text,''),
		tenant_id::text,detail->>'export_id',COALESCE(detail->>'snapshot_digest',''),COALESCE(detail->>'request_digest','')
		FROM audit_log WHERE tenant_id=$1 AND detail->>'export_id'=$2
		AND action IN ('export.request','export.approve') ORDER BY id LIMIT 3`, e.TenantID, e.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	projected := make([]ExportCustodyAudit, 0, 2)
	for rows.Next() {
		var r ExportCustodyAudit
		var id int64
		if err := rows.Scan(&id, &r.At, &r.Action, &r.ActorID, &r.TenantID, &r.ExportID, &r.SnapshotDigest, &r.IntentDigest); err != nil {
			return nil, err
		}
		if id <= 0 || r.At.IsZero() || r.TenantID != e.TenantID || r.ExportID != e.ID || r.SnapshotDigest != e.SnapshotDigest || r.IntentDigest != e.RequestDigest {
			return nil, ErrExportConflict
		}
		r.ID = strconv.FormatInt(id, 10)
		projected = append(projected, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(projected) != 2 || projected[0].Action != "export.request" || projected[0].ActorID != e.RequesterID || projected[1].Action != "export.approve" || projected[1].ActorID != *e.ApproverID {
		return nil, ErrExportConflict
	}
	return projected, nil
}
