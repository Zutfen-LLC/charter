// Package records implements the C07 matter hold, deletion and retention
// lifecycle (#7, ADR 0001 section 7).
//
// Layering: holds and lifecycle state are CONTROL-PLANE records in
// PostgreSQL; evidence bytes remain exclusively in the append-only evidence
// store (PostgreSQL profile) or the retained S3 Object Lock profile. Storage
// protection for held evidence uses the backend's NATIVE legal hold (and the
// always-on COMPLIANCE retention), never a database flag presented as
// protection. Disposal is a two-phase conditional delete fenced by the
// per-matter hold epoch: both the hold placement and the irreversible delete
// serialize on the same row, so a hold acknowledged before the delete commits
// always wins (ADR linearization rule).
package records

import (
	"time"
)

// Hold states. pending means the hold epoch is committed (disposal is fenced)
// but storage-native protection is not yet verified; effective means it is
// established and read back; failed means establishment failed and is
// retryable (the fence remains in force - failure never weakens protection);
// released removes only that hold's claim.
const (
	HoldPending   = "pending"
	HoldEffective = "effective"
	HoldFailed    = "failed"
	HoldReleased  = "released"
)

// Disposal lifecycle states (docs/contracts/state-machines.md).
const (
	ItemActive          = "active"
	ItemDisposalPending = "disposal_pending"
	ItemPurging         = "purging"
	ItemDisposed        = "disposed"
)

// Hold is the durable hold record.
type Hold struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	MatterID       string     `json:"matter_id"`
	CustodianIDs   []string   `json:"custodian_ids"`
	WindowStart    *time.Time `json:"window_start,omitempty"`
	WindowEnd      *time.Time `json:"window_end,omitempty"`
	Reason         string     `json:"reason"`
	State          string     `json:"state"`
	Epoch          int64      `json:"epoch"`
	ReleaseEpoch   *int64     `json:"release_epoch,omitempty"`
	PlacedBy       string     `json:"placed_by"`
	PlacedAt       time.Time  `json:"placed_at"`
	EffectiveAt    *time.Time `json:"effective_at,omitempty"`
	ReleasedBy     *string    `json:"released_by,omitempty"`
	ReleasedAt     *time.Time `json:"released_at,omitempty"`
	ReleaseReason  *string    `json:"release_reason,omitempty"`
	IdempotencyKey string     `json:"idempotency_key"`
	Report         Report     `json:"report"`
}

// Report is the hold's durable coverage report (ADR: the miss must be visible
// rather than silent).
type Report struct {
	// The scope revision (the hold's epoch value) this report was verified
	// under; the effective transition binds to it, so a committed report
	// always corresponds to the exact scope revision it verified.
	ScopeEpoch int64 `json:"scope_epoch,omitempty"`
	// Turns enumerated in scope at establishment, with per-item outcomes.
	Items []ReportedItem `json:"items"`
	// Turn IDs already disposed when the hold was placed.
	DisposedBeforeHold []string `json:"disposed_before_hold"`
	// Turn IDs in scope whose required versions could not all be verified
	// as protected (establishment failed for them; the hold is not effective
	// while any remain).
	Uncovered []string `json:"uncovered"`
	// Versions this hold protected (for release reference counting).
	ProtectedVersions []VersionRef `json:"protected_versions"`
	// Release cleanup still pending (versions that could not yet have their
	// legal hold cleared because the storage was unavailable). Conservative:
	// pending cleanup means OVER-protection, never under-protection.
	ReleaseCleanupPending []VersionRef `json:"release_cleanup_pending,omitempty"`
	// Last establishment error detail, when state is failed.
	Error string `json:"error,omitempty"`
}

// ReportedItem is one in-scope turn with its establishment outcome.
type ReportedItem struct {
	TurnID     string    `json:"turn_id"`
	Custodian  string    `json:"custodian_id"`
	RecordedAt time.Time `json:"recorded_at"`
	// AlreadyExpired: the turn's retention was already past expiry when the
	// hold was placed (recorded, not silently assumed preserved).
	AlreadyExpired bool      `json:"already_expired"`
	ExpiresAt      time.Time `json:"retention_expires_at"`
	Versions       int       `json:"versions"`
}

// VersionRef is one exact storage version protected by a hold.
type VersionRef struct {
	Key     string `json:"key"`
	Version string `json:"version"`
}

// Scope is the requested hold scope.
type Scope struct {
	MatterID     string
	CustodianIDs []string // empty = all custodians
	WindowStart  *time.Time
	WindowEnd    *time.Time
}

// Matches implements ADR 0001 section 7 hold matching: same matter, custodian
// in scope (empty = all), recorded_at inside [window_start, window_end).
func Matches(h *Hold, matterID, custodianID string, recordedAt time.Time) bool {
	if h.MatterID != matterID {
		return false
	}
	if len(h.CustodianIDs) > 0 && !contains(h.CustodianIDs, custodianID) {
		return false
	}
	if h.WindowStart != nil && recordedAt.Before(*h.WindowStart) {
		return false
	}
	if h.WindowEnd != nil && !recordedAt.Before(*h.WindowEnd) {
		return false
	}
	return true
}

// Applies reports whether a hold in the given state protects a matching item.
// pending and failed both fence disposal: the epoch is committed and a failed
// establishment is a retry, never a silent downgrade.
func Applies(state string) bool {
	return state == HoldPending || state == HoldEffective || state == HoldFailed
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
