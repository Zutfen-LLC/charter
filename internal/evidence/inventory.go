package evidence

import (
	"context"
	"time"
)

// TurnIdentity names one admitted turn with the attributes hold matching
// (ADR 0001 section 7) and retention scheduling need. It is derived from the
// AUTHORITATIVE evidence backend, never from workspace tables, so lifecycle
// operations keep working after chats, projects or custodians are deleted.
type TurnIdentity struct {
	TenantID, ProjectID, MatterID, CustodianID, TurnID string
	RecordedAt                                         time.Time
}

// TurnInventory is implemented by backends that can enumerate every admitted
// turn of a tenant from authoritative storage (an exhaustive bounded scan for
// the retained profile; the append-only admission table for PostgreSQL).
type TurnInventory interface {
	InventoryTurns(ctx context.Context, tenantID string) ([]TurnIdentity, error)
}

// VersionRef is one exact object version of the retained namespace.
type VersionRef struct{ Key, Version string }

// TurnVersions is implemented by backends that can enumerate the exact
// versions (admission marker, event slots, data events and referenced
// content-addressed objects) that make up one turn.
type TurnVersions interface {
	TurnVersionRefs(ctx context.Context, tenantID, turnID string) ([]VersionRef, error)
}

// TurnsInventory returns the inventory when the backend implements it.
func TurnsInventory(b Backend) (TurnInventory, bool) {
	i, ok := b.(TurnInventory)
	return i, ok
}

// VersionsOf returns the version enumerator when the backend implements it.
func VersionsOf(b Backend) (TurnVersions, bool) {
	v, ok := b.(TurnVersions)
	return v, ok
}

// DisposalVersions is implemented by backends that can enumerate a turn's
// versions for disposal (tolerating expired retention, since expired
// evidence is what disposal operates on).
type DisposalVersions interface {
	TurnDisposalRefs(ctx context.Context, tenantID, turnID string) ([]VersionRef, error)
}

// DisposalVersionsOf returns the disposal enumerator when implemented.
func DisposalVersionsOf(b Backend) (DisposalVersions, bool) {
	v, ok := b.(DisposalVersions)
	return v, ok
}
