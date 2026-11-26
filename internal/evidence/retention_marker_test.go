package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

// An altered marker protection response must not be treated as authoritative,
// even if the signed content and the referenced event are intact.
func TestRetainedAdmissionRejectsUnprotectedMarker(t *testing.T) {
	seed := sha256.Sum256([]byte("marker retention adversary"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	ev := Event{"schema_version": "1.0.0", "tenant_id": "tenant", "project_id": "project", "turn_id": "turn", "seq": 0, "type": "turn_received", "recorded_at": "2026-01-01T00:00:00.000Z", "actor": map[string]any{"kind": "user", "id": "custodian"}, "payload": map[string]any{"custodian_id": "custodian"}, "prev_hash": nil}
	if err := Seal(ev); err != nil {
		t.Fatal(err)
	}
	body, err := checkedBody(ev)
	if err != nil {
		t.Fatal(err)
	}
	h := str(ev, "event_hash")
	digest := SHA256([]byte("request identity"))
	slot := "charter/v1/dep/tenant/admissions/" + digest
	key := "charter/v1/dep/tenant/data/events/turn/" + h
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	commit := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: "dep", Tenant: "tenant", Project: "project", Turn: "turn", Slot: slot, EventHash: h, Admission: &retainedAdmission{IdempotencyDigest: digest, Fingerprint: SHA256([]byte("request"))}, Event: retainedObjectReceipt{Deployment: "dep", Tenant: "tenant", EvidenceID: h, Bucket: "archive", Key: key, Version: "event", SHA256: SHA256(body), Length: uint64(len(body)), Mode: "COMPLIANCE", RetainUntil: until.Format(time.RFC3339), EventHash: h}}
	signed, err := signRetainedCommit(commit, priv)
	if err != nil {
		t.Fatal(err)
	}
	m := &retainedMemory{objects: map[string]map[string]s3transport.Version{
		slot: {"meta": {ID: "meta", Data: signed, Mode: "GOVERNANCE", Until: until}},
		key:  {"event": {ID: "event", Data: body, Mode: "COMPLIANCE", Until: until}},
	}}
	b, err := NewRetentionBackend(RetentionOptions{Store: m, Deployment: "dep", Bucket: "archive", TrustedCommitKey: priv.Public().(ed25519.PublicKey), MinimumRetention: until.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err = b.VerifyRetainedTurn(context.Background(), "tenant", "turn", []Event{ev}); err == nil {
		t.Fatal("unprotected commit marker was authoritative")
	}
}
