package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

type exportExactMemory struct{ retainedMemory }

func (*exportExactMemory) Versions(context.Context, string) ([]s3transport.Ref, error) {
	return nil, errors.New("listing prohibited in frozen readback")
}

func TestExportReadbackReconcilesSignedVersionsAndOriginalBytes(t *testing.T) {
	ctx := context.Background()
	seed := sha256.Sum256([]byte("synthetic export readback seed"))
	signer := ed25519.NewKeyFromSeed(seed[:])
	mem := &exportExactMemory{retainedMemory{objects: map[string]map[string]s3transport.Version{}}}
	b, err := NewRetentionBackend(RetentionOptions{Store: mem, Deployment: "dep", Bucket: "archive", TrustedCommitKey: signer.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	until := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	const tenant, project, turn = "tenant", "project", "turn"
	var refs []VersionRef
	add := func(key string, data []byte) {
		mem.objects[key] = map[string]s3transport.Version{"frozen": {ID: "frozen", Data: data, Mode: "COMPLIANCE", Until: until}}
		refs = append(refs, VersionRef{key, "frozen"})
	}
	receipt := func(key, id string, data []byte) retainedObjectReceipt {
		add(key, data)
		return retainedObjectReceipt{Deployment: "dep", Tenant: tenant, EvidenceID: id, Bucket: "archive", Key: key, Version: "frozen", SHA256: SHA256(data), Length: uint64(len(data)), Mode: "COMPLIANCE", RetainUntil: until.Format(time.RFC3339)}
	}
	input := []byte("original\ninput\x00")
	digest := SHA256(input)
	inputReceipt := receipt(b.objectKey(tenant, digest), digest, input)
	admissionKey := SHA256([]byte("idempotency"))
	var prevHash any
	var prevMarker *retainedMarkerReceipt
	var original [][]byte
	for seq, kind := range []string{"turn_received", "turn_interrupted"} {
		actor := map[string]any{"kind": "user", "id": "custodian"}
		p := map[string]any{"custodian_id": "custodian", "evidence_profile": RetentionProfile, "input": map[string]any{"sha256": digest, "bytes": len(input)}}
		slot := b.prefix + tenant + "/admissions/" + admissionKey
		if seq > 0 {
			actor = map[string]any{"kind": "service", "id": "recorder"}
			p = map[string]any{"reason": "synthetic", "disclosure": "none"}
			slot = b.eventSlot(tenant, turn, uint64(seq))
		}
		e := Event{"schema_version": "1.0.0", "tenant_id": tenant, "project_id": project, "matter_id": "matter", "turn_id": turn, "seq": seq, "type": kind, "actor": actor, "payload": p, "prev_hash": prevHash, "recorded_at": "2024-01-01T00:00:00.000Z"}
		if err := Seal(e); err != nil {
			t.Fatal(err)
		}
		raw, err := Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		original = append(original, raw)
		hash := str(e, "event_hash")
		r := receipt(b.eventKey(tenant, turn, hash), hash, raw)
		r.Seq, r.EventHash = uint64(seq), hash
		c := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: "dep", Slot: slot, Tenant: tenant, Project: project, Turn: turn, Seq: uint64(seq), EventHash: hash, Event: r, Predecessor: prevMarker}
		if seq == 0 {
			c.Admission = &retainedAdmission{IdempotencyDigest: admissionKey, Fingerprint: digest}
			c.Objects = []retainedObjectReceipt{inputReceipt}
		}
		marker, err := signRetainedCommit(c, signer)
		if err != nil {
			t.Fatal(err)
		}
		add(slot, marker)
		prevMarker = &retainedMarkerReceipt{Bucket: "archive", Key: slot, Version: "frozen", SHA256: SHA256(marker), Length: uint64(len(marker)), Mode: "COMPLIANCE", RetainUntil: until.Format(time.RFC3339)}
		prevHash = hash
	}
	got, err := b.LoadExportReadback(ctx, tenant, project, turn, refs)
	if err != nil || len(got.CanonicalEvents) != len(original) || len(got.Versions) != len(refs) || !bytes.Equal(got.Objects[digest], input) {
		t.Fatalf("frozen complete turn did not verify: %v", err)
	}
	for i, raw := range original {
		if !bytes.Equal(got.CanonicalEvents[i], raw) {
			t.Fatal("original event was rewritten")
		}
	}
	extra := VersionRef{b.objectKey(tenant, SHA256([]byte("unreferenced"))), "frozen"}
	for _, changed := range [][]VersionRef{refs[1:], append(append([]VersionRef{}, refs...), extra)} {
		if got, err := b.LoadExportReadback(ctx, tenant, project, turn, changed); err == nil || len(got.CanonicalEvents) != 0 {
			t.Fatal("missing or extra refs passed frozen readback")
		}
	}
	// Lose the admission marker and event-zero bytes, but keep exact input
	// and the signed terminal survivor. The plan still supplies both IDs.
	var survivors, missing []VersionRef
	admission, err := ParseEvent(original[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if strings.Contains(r.Key, "/admissions/") || r.Key == b.eventKey(tenant, turn, str(admission, "event_hash")) {
			missing = append(missing, r)
			delete(mem.objects[r.Key], r.Version)
		} else {
			survivors = append(survivors, r)
		}
	}
	partial, err := b.LoadPartialExportReadback(ctx, tenant, project, "matter", turn, survivors, missing)
	if err != nil || len(partial.CanonicalEvents) != 1 || len(partial.MissingSequences) != 1 || partial.MissingSequences[0] != 0 || !bytes.Equal(partial.CanonicalEvents[0], original[1]) || !bytes.Equal(partial.Objects[digest], input) {
		t.Fatalf("partial signed survivor and exact input were not preserved: %v", err)
	}
}
