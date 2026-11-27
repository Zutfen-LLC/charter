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

// NamespaceEnumeration is the fallback enumeration of a turn's own
// namespaces with its completeness classification (C07 round-2 finding 3).
type NamespaceEnumeration struct {
	Refs []VersionRef
	// Complete reports whether every listed event-slot version was read
	// AND its signed candidate verified, and the listed slot sequence has
	// no holes. When false, at least one listed slot could not be read or
	// verified: its object references are UNKNOWN - the true reference
	// set is a strict superset of Refs, and an unreadable reference must
	// never be treated as an absent one.
	Complete bool
}

// NamespaceVersions is implemented by backends that can enumerate every
// version under a turn's own namespaces (event slots and data events) plus
// the object versions the still-decodable slots reference, WITHOUT chain
// verification. The shared-reference and required-version scans use it as
// the fallback for a sibling turn whose verified enumeration is
// unavailable (mid-deletion or a broken chain): the sibling must be
// neither silently treated as reference-free nor allowed to wedge every
// disposal in the tenant forever. ErrNotFound means authoritatively
// NOTHING is left under the turn's namespaces; an incomplete enumeration
// is reported through Complete=false and must cause the caller to refuse
// the irreversible action it was fencing.
type NamespaceVersions interface {
	TurnNamespaceRefs(ctx context.Context, tenantID, turnID string) (NamespaceEnumeration, error)
}

// NamespaceVersionsOf returns the namespace enumerator when implemented.
func NamespaceVersionsOf(b Backend) (NamespaceVersions, bool) {
	v, ok := b.(NamespaceVersions)
	return v, ok
}

// TurnTerminal is implemented by backends that can report whether a turn's
// capture has reached a terminal event (turn_completed / turn_failed /
// turn_aborted). Disposal eligibility requires a verified terminal state: an
// admitted, actively executing turn must never be destroyed by ordinary
// expiry (C07 review finding 6A). Terminality is monotonic once observed.
type TurnTerminal interface {
	TurnTerminal(ctx context.Context, tenantID, turnID string) (bool, error)
}

// TerminalOf returns the terminality prober when implemented. Backends that
// cannot report terminality are treated as non-terminal (fail closed).
func TerminalOf(b Backend) (TurnTerminal, bool) {
	v, ok := b.(TurnTerminal)
	return v, ok
}
