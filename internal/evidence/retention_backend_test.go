package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

type retainedMemory struct {
	objects map[string]map[string]s3transport.Version
}

func (m *retainedMemory) Create(_ context.Context, key string, b []byte, until time.Time) (string, error) {
	if m.objects[key] == nil {
		m.objects[key] = map[string]s3transport.Version{}
	}
	id := string(rune(len(m.objects[key]) + 1))
	m.objects[key][id] = s3transport.Version{ID: id, Data: append([]byte(nil), b...), Mode: "COMPLIANCE", Until: until}
	return id, nil
}
func (m *retainedMemory) Read(_ context.Context, key, id string) (s3transport.Version, error) {
	v, ok := m.objects[key][id]
	if !ok {
		return s3transport.Version{}, ErrNotFound
	}
	return v, nil
}
func (m *retainedMemory) Versions(_ context.Context, prefix string) ([]s3transport.Ref, error) {
	var out []s3transport.Ref
	for k, vs := range m.objects {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			for id := range vs {
				out = append(out, s3transport.Ref{Key: k, VersionID: id})
			}
		}
	}
	return out, nil
}

func (m *retainedMemory) Bucket() string { return "archive" }

func TestRetainedAdmissionReconstructsByExactVersion(t *testing.T) {
	seed := sha256.Sum256([]byte("signing fixture"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	ev := Event{"schema_version": "1.0.0", "tenant_id": "tenant", "project_id": "project", "turn_id": "turn", "seq": 0, "type": "turn_received", "actor": map[string]any{"kind": "user", "id": "custodian"}, "payload": map[string]any{"custodian_id": "custodian"}, "prev_hash": nil, "recorded_at": "2026-01-01T00:00:00.000Z"}
	if err := Seal(ev); err != nil {
		t.Fatal(err)
	}
	body, err := checkedBody(ev)
	if err != nil {
		t.Fatal(err)
	}
	hash := str(ev, "event_hash")
	digest := SHA256([]byte("stable admission digest"))
	slot := "charter/v1/dep/tenant/admissions/" + digest
	eventKey := "charter/v1/dep/tenant/data/events/turn/" + hash
	until := "2030-01-01T00:00:00Z"
	c := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: "dep", Slot: slot, Tenant: "tenant", Project: "project", Turn: "turn", Seq: 0, EventHash: hash, Admission: &retainedAdmission{IdempotencyDigest: digest, Fingerprint: SHA256([]byte("request"))}, Event: retainedObjectReceipt{Deployment: "dep", Tenant: "tenant", EvidenceID: hash, Bucket: "archive", Key: eventKey, Version: "event-v1", SHA256: SHA256(body), Length: uint64(len(body)), Mode: "COMPLIANCE", RetainUntil: until, Seq: 0, EventHash: hash}}
	signed, err := signRetainedCommit(c, priv)
	if err != nil {
		t.Fatal(err)
	}
	mem := &retainedMemory{objects: map[string]map[string]s3transport.Version{slot: {"marker-v1": {ID: "marker-v1", Data: signed, Mode: "COMPLIANCE", Until: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}, eventKey: {"event-v1": {ID: "event-v1", Data: body, Mode: "COMPLIANCE", Until: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}}}}
	b, err := NewRetentionBackend(RetentionOptions{Store: mem, Deployment: "dep", Bucket: "archive", TrustedCommitKey: pub, MinimumRetention: time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Load(context.Background(), "tenant", "turn")
	if err != nil {
		t.Fatalf("admission reconstruction failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatal("wrong event census")
	}
	actual, err := Marshal(got[0])
	if err != nil || string(actual) != string(body) {
		t.Fatal("loader did not return exact event bytes")
	}
}
