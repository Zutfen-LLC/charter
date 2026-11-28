package exportbundle

import (
	"errors"
	"strconv"
	"time"
)

// validateCustodyAudit runs after validateSnapshot has type-checked scope and
// custody. The externally anchored manifest vouches for the projected rows;
// this offline checker cannot authenticate a live database or audit service.
func validateCustodyAudit(m map[string]any) error {
	projection, ok := m["custody_audit"].(map[string]any)
	if !ok || fields(projection, "version", "rows") != nil || projection["version"] != "scoped_projection_v1" {
		return errors.New("invalid scoped custody audit projection")
	}
	rows, ok := projection["rows"].([]any)
	if !ok || len(rows) != 2 {
		return errors.New("request and approval audit rows required")
	}
	custody := m["custody"].(map[string]any)
	scope := m["scope"].(map[string]any)
	actions := [2]string{"export.request", "export.approve"}
	actors := [2]any{custody["requester_id"], custody["approver_id"]}
	var previousID int64
	var previousIntent string
	for i, v := range rows {
		r, ok := v.(map[string]any)
		if !ok || fields(r, "id", "at", "action", "actor_id", "tenant_id", "export_id", "snapshot_id", "intent_digest") != nil {
			return errors.New("invalid custody audit row")
		}
		id, _ := r["id"].(string)
		n, err := strconv.ParseInt(id, 10, 64)
		at, _ := r["at"].(string)
		stamp, timeErr := time.Parse(time.RFC3339Nano, at)
		intent, _ := r["intent_digest"].(string)
		if err != nil || n <= previousID || strconv.FormatInt(n, 10) != id || timeErr != nil || stamp.IsZero() || stamp.UTC().Format(time.RFC3339Nano) != at || !digestRE.MatchString(intent) || (i > 0 && intent != previousIntent) {
			return errors.New("invalid custody audit sequence, timestamp or intent digest")
		}
		if r["action"] != actions[i] || r["actor_id"] != actors[i] || r["tenant_id"] != scope["tenant_id"] || r["export_id"] != m["export_id"] || r["snapshot_id"] != custody["snapshot_id"] {
			return errors.New("custody audit row does not bind the approved export")
		}
		previousID, previousIntent = n, intent
	}
	return nil
}
