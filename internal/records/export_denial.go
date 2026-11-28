package records

import (
	"context"
	"encoding/json"

	"github.com/Zutfen-LLC/charter/internal/store"
)

// AuditExportDenial records a tenant-local authenticated denial. It never
// resolves a supplied export identifier or copies request data into the log.
func (s *Store) AuditExportDenial(ctx context.Context, p store.Principal, action, suppliedID string, status int) error {
	p, ok := canonP(p)
	if !ok {
		return ErrForbidden
	}
	switch action {
	case "request", "approve", "generate", "retrieve", "cancel":
	default:
		return ErrNotFound
	}
	if status < 400 || status > 599 {
		return ErrNotFound
	}
	detail := map[string]any{"operation": action, "status": status}
	if id, ok := store.CanonicalID(suppliedID); ok {
		detail["supplied_export_id"] = id
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `INSERT INTO audit_log(tenant_id,actor_id,action,detail)
  SELECT tenant_id,id,'export.reject',$3 FROM users WHERE tenant_id=$1 AND id=$2`, p.TenantID, p.UserID, raw)
	return err
}
