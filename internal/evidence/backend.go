package evidence

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrConflict: an event with this (turn, seq) already exists with a
	// different hash. Replaying the identical event is not an error.
	ErrConflict = errors.New("evidence: conflicting event already stored")
	// ErrTerminal: the turn already has its terminal event.
	ErrTerminal = errors.New("evidence: turn is terminal")
	// ErrIdempotencyMismatch: same idempotency key, different input.
	ErrIdempotencyMismatch = errors.New("evidence: idempotency key reused with different input")
	ErrNotFound            = errors.New("evidence: not found")
	// ErrNotDurable: the store could not guarantee a durable write.
	ErrNotDurable = errors.New("evidence: durable write not guaranteed")
)

// Receipt is the storage receipt for a durable write. ID is a deterministic
// hash of what was stored and where, so replaying a write returns the same
// receipt. Level records the durability actually in force for that write
// (ADR 0001 section 8: the pilot must record the level actually tested).
type Receipt struct {
	Backend  string                 `json:"backend"`
	Level    string                 `json:"level"`
	ID       string                 `json:"id"`
	Retained *retainedObjectReceipt `json:"retained,omitempty"`
}

// BackendInfo describes a backend honestly. RetentionEnforced must be true only
// for a backend whose protection against the application's own credentials has
// been demonstrated by the protection suite against real storage.
type BackendInfo struct {
	Kind              string
	RetentionEnforced bool
	Notice            string
}

// Admission identifies a turn at the moment it is admitted.
type Admission struct {
	TenantID, ProjectID, MatterID, CustodianID string
	IdempotencyKey, TurnID                     string
	// Fingerprint binds the whole semantic request (see Fingerprint). A repeated
	// idempotency key with a different fingerprint is refused.
	Fingerprint string
}

// AdmitResult: Created is false when the idempotency key already admitted a
// turn; TurnID is then the EXISTING turn and nothing was written.
type AdmitResult struct {
	TurnID  string
	Created bool
	Receipt Receipt
}

// TurnRef names a turn without content.
type TurnRef struct{ TenantID, TurnID string }

// Backend is the durable evidence store. A nil error from a write means the
// data is durable at the level named in the Receipt; any error means the caller
// must assume nothing about durability and must fail closed. All writes are
// idempotent: repeating one after an ambiguous failure is always safe.
type Backend interface {
	Info() BackendInfo
	PutObject(ctx context.Context, tenantID string, data []byte) (Receipt, error)
	// Admit durably records the turn, its input object and event 0 together.
	Admit(ctx context.Context, a Admission, first Event, objects [][]byte) (AdmitResult, error)
	Append(ctx context.Context, e Event) (Receipt, error)
	Load(ctx context.Context, tenantID, turnID string) ([]Event, error)
	Object(ctx context.Context, tenantID, sha string) ([]byte, error)
	// OpenTurns lists turns with no terminal event admitted before the cutoff.
	OpenTurns(ctx context.Context, admittedBefore time.Time) ([]TurnRef, error)
}
