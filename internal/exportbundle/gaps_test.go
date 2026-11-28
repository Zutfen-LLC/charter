package exportbundle

import (
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

func TestAuthenticatedHistoricalGapNeverReturnsComplete(t *testing.T) {
	const hold = "123e4567-e89b-42d3-a456-426614174001"
	const uid = "123e4567-e89b-42d3-a456-426614174002"
	planHash := evidence.SHA256([]byte("frozen historical plan"))
	snap := evidence.SHA256([]byte("gap snapshot"))
	const admitted = "2026-01-02T00:00:00Z"
	m := map[string]any{
		"schema_version": SchemaVersion, "profile": evidence.RetentionProfile, "export_id": fixtureTurn,
		"snapshot": map[string]any{"id": snap, "revision": "19", "captured_at": "2026-02-01T00:00:00Z", "hold_ids": []any{hold}},
		"scope":    map[string]any{"tenant_id": "tenant", "project_id": "project", "matter_id": "matter", "custodian_ids": []any{uid}, "window_start": "2026-01-01T00:00:00Z", "window_end": "2026-02-01T00:00:00Z"},
		"custody":  map[string]any{"requester_id": "requester", "approver_id": "reviewer", "requested_at": "2026-02-01T00:00:00Z", "approved_at": "2026-02-01T00:01:00Z", "snapshot_id": snap},
		"turns":    []any{}, "objects": []any{},
	}
	missing := map[string]any{"key": "charter/v1/lab/tenant/admissions/" + planHash, "version": "v1", "plan_epoch": 7, "disposition": "absent"}
	gap := map[string]any{"turn_id": fixtureTurn, "kind": "complete_loss", "custodian_id": uid, "recorded_at": admitted, "hold_ids": []any{hold}, "missing_versions": []any{missing}}
	m["gaps"] = []any{gap}
	verify := func() (Result, error) {
		raw, err := evidence.Canonical(m)
		if err != nil {
			t.Fatal(err)
		}
		return VerifyMembers(map[string][]byte{"manifest.json": raw}, evidence.RetentionProfile, evidence.SHA256(raw))
	}
	got, err := verify()
	if err != nil || got.Status != DeclaredGap || got.Turns != 0 || len(got.Gaps) != 1 {
		t.Fatalf("authentic declared historical loss = %#v %v", got, err)
	}
	for _, disposition := range []string{"planned", "unknown", "protected"} {
		missing["disposition"] = disposition
		if _, err = verify(); err == nil {
			t.Fatalf("accepted unverified loss %q", disposition)
		}
	}
	missing["disposition"] = "deleted"
	gap["kind"] = "partial_loss"
	if _, err = verify(); err == nil {
		t.Fatal("partial loss without surviving evidence was accepted")
	}
}
