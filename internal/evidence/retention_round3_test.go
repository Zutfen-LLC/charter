package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"sort"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

// C07 round-3 review finding 1 (CRITICAL): TurnNamespaceRefs must include
// the turn's ADMISSION marker and its sequence-0 content-addressed object
// references. The admission marker is the only place a turn's input objects
// are referenced: a sibling whose verified enumeration is unavailable (a
// broken subsequent event chain) must never present a fallback reference
// set that silently excludes its admission-only input object, because the
// disposal of another record referencing the same exact object version may
// then delete that version.

// round3Memory is a retained-namespace memory transport whose deletes remove
// the exact version from enumeration (the records transport's delete
// semantics: reads of a deleted version report s3transport.ErrObjectAbsent).
type round3Memory struct {
	objects map[string]map[string]s3transport.Version
	deleted map[string]bool
}

func (m *round3Memory) Create(_ context.Context, key string, b []byte, until time.Time) (string, error) {
	if m.objects[key] == nil {
		m.objects[key] = map[string]s3transport.Version{}
	}
	id := string(rune(len(m.objects[key]) + 'a'))
	m.objects[key][id] = s3transport.Version{ID: id, Data: append([]byte(nil), b...), Mode: "COMPLIANCE", Until: until}
	return id, nil
}

func (m *round3Memory) Read(_ context.Context, key, id string) (s3transport.Version, error) {
	if m.deleted[key+"|"+id] {
		return s3transport.Version{}, s3transport.ErrObjectAbsent
	}
	v, ok := m.objects[key][id]
	if !ok {
		return s3transport.Version{}, ErrNotFound
	}
	return v, nil
}

func (m *round3Memory) Versions(_ context.Context, prefix string) ([]s3transport.Ref, error) {
	var out []s3transport.Ref
	for k, vs := range m.objects {
		if len(k) < len(prefix) || k[:len(prefix)] != prefix {
			continue
		}
		for id := range vs {
			if m.deleted[k+"|"+id] {
				continue
			}
			out = append(out, s3transport.Ref{Key: k, VersionID: id})
		}
	}
	return out, nil
}

func (m *round3Memory) Bucket() string { return "archive" }

func (m *round3Memory) delete(key, id string) { m.deleted[key+"|"+id] = true }

// markerDigestOf and markerLengthOf read back the published slot bytes so
// the successor's predecessor receipt describes the actual marker version.
func markerDigestOf(t *testing.T, m *round3Memory, key, version string) string {
	t.Helper()
	v, err := m.Read(context.Background(), key, version)
	if err != nil {
		t.Fatal(err)
	}
	return SHA256(v.Data)
}

func markerLengthOf(t *testing.T, m *round3Memory, key, version string) uint64 {
	t.Helper()
	v, err := m.Read(context.Background(), key, version)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(len(v.Data))
}

// round3Turn builds a signed retained turn shape: an admission marker whose
// commit references the turn_received event data and the given input objects
// (content-addressed, shareable across turns), followed by event slots. The
// terminal slot closes the chain.
type round3Turn struct {
	turnID            string
	admissionSlot     string
	admissionVersion  string
	admissionEvent    VersionRef
	sharedObject      VersionRef
	slotVersions      []string
	terminalSlotIndex int
}

func buildRound3Turn(t *testing.T, priv ed25519.PrivateKey, mem *round3Memory, turnID string, sharedKey, sharedVersion string) *round3Turn {
	t.Helper()
	const dep = "dep"
	prefix := "charter/v1/" + dep + "/tenant/"
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	untilS := "2030-01-01T00:00:00Z"
	tr := &round3Turn{turnID: turnID}
	mkReceipt := func(key, version, digest, eventHash string, seq uint64, length int) retainedObjectReceipt {
		return retainedObjectReceipt{Deployment: dep, Tenant: "tenant", EvidenceID: digest, Bucket: "archive", Key: key, Version: version, SHA256: digest, Length: uint64(length), Mode: "COMPLIANCE", RetainUntil: untilS, Seq: seq, EventHash: eventHash}
	}
	publish := func(c retainedCommit) string {
		t.Helper()
		raw, err := signRetainedCommit(c, priv)
		if err != nil {
			t.Fatal(err)
		}
		v, err := mem.Create(context.Background(), c.Slot, raw, until)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	put := func(key string, b []byte) string {
		t.Helper()
		v, err := mem.Create(context.Background(), key, b, until)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	// The shared content-addressed input object (referenced by the ADMISSION
	// marker only - no later event repeats the reference). Both turns
	// reference the SAME exact version (content addressing deduplicates).
	sharedData := []byte("r3-shared-input")
	sharedSHA := SHA256(sharedData)
	tr.sharedObject = VersionRef{Key: sharedKey, Version: sharedVersion}
	if ids := mem.objects[sharedKey]; len(ids) > 0 {
		for id := range ids {
			tr.sharedObject.Version = id // the single existing exact version
		}
	} else {
		tr.sharedObject.Version = put(sharedKey, sharedData)
	}
	// The admission event data (turn_received).
	admissionEventKey := prefix + "data/events/" + turnID + "/ea"
	admissionEventData := []byte("turn-received:" + turnID)
	admissionEventVersion := put(admissionEventKey, admissionEventData)
	tr.admissionEvent = VersionRef{Key: admissionEventKey, Version: admissionEventVersion}
	// The admission marker (seq 0) references its event data and the shared
	// input object: the "admission-only input object reference".
	digest := SHA256([]byte("admission-" + turnID))
	tr.admissionSlot = prefix + "admissions/" + digest
	admission := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: dep, Slot: tr.admissionSlot, Tenant: "tenant", Project: "project", Turn: turnID, EventHash: SHA256(admissionEventData), Admission: &retainedAdmission{IdempotencyDigest: digest, Fingerprint: SHA256([]byte("request-" + turnID))}, Event: mkReceipt(admissionEventKey, admissionEventVersion, SHA256(admissionEventData), SHA256(admissionEventData), 0, len(admissionEventData))}
	shared := mkReceipt(sharedKey, tr.sharedObject.Version, sharedSHA, "", 0, len(sharedData))
	admission.Objects = []retainedObjectReceipt{shared}
	tr.admissionVersion = publish(admission)
	prevMarker := retainedMarkerReceipt{Bucket: "archive", Key: tr.admissionSlot, Version: tr.admissionVersion, SHA256: markerDigestOf(t, mem, tr.admissionSlot, tr.admissionVersion), Length: markerLengthOf(t, mem, tr.admissionSlot, tr.admissionVersion), Mode: "COMPLIANCE", RetainUntil: untilS}
	// Two event slots; slot 2 is terminal.
	for seq := uint64(1); seq <= 2; seq++ {
		key := prefix + "events/" + turnID + "/" + string(rune('0'+seq))
		data := []byte("event-" + turnID + "-" + string(rune('0'+seq)))
		eventKey := prefix + "data/events/" + turnID + "/e" + string(rune('0'+seq))
		eventVersion := put(eventKey, data)
		c := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: dep, Slot: key, Tenant: "tenant", Project: "project", Turn: turnID, Seq: seq, EventHash: SHA256(data), Event: mkReceipt(eventKey, eventVersion, SHA256(data), SHA256(data), seq, len(data)), Predecessor: &prevMarker}
		if seq == 1 {
			// The first event references its own object (not the shared one).
			ownKey := prefix + "data/objects/own-" + turnID
			ownData := []byte("own-" + turnID)
			ownVersion := put(ownKey, ownData)
			c.Objects = []retainedObjectReceipt{mkReceipt(ownKey, ownVersion, SHA256(ownData), "", 0, len(ownData))}
		}
		v := publish(c)
		tr.slotVersions = append(tr.slotVersions, v)
		prevMarker = retainedMarkerReceipt{Bucket: "archive", Key: key, Version: v, SHA256: markerDigestOf(t, mem, key, v), Length: markerLengthOf(t, mem, key, v), Mode: "COMPLIANCE", RetainUntil: untilS}
	}
	tr.terminalSlotIndex = 1
	return tr
}

// TestNamespaceFallbackIncludesAdmissionReferences is the executable RED
// reproduction of round-3 finding 1 at the reviewed head 702bb2f: two turns
// share an exact content-addressed object version referenced ONLY through
// their admission markers; the sibling's subsequent event chain is broken
// (a deleted middle slot) so the shared-reference scan resolves it through
// the namespace fallback; the fallback must include the admission marker,
// its event data and its input objects - a complete fallback reference set
// that excludes them authorizes the deletion of the sibling's evidence.
func TestNamespaceFallbackIncludesAdmissionReferences(t *testing.T) {
	seed := sha256.Sum256([]byte("round3 fallback fixture"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	mem := &round3Memory{objects: map[string]map[string]s3transport.Version{}, deleted: map[string]bool{}}
	const dep = "dep"
	sharedKey := "charter/v1/" + dep + "/tenant/data/objects/r3-shared"
	a := buildRound3Turn(t, priv, mem, "turn-a", sharedKey, "")
	b := buildRound3Turn(t, priv, mem, "turn-b", sharedKey, "")
	// The two turns reference the EXACT same shared object version.
	if a.sharedObject != b.sharedObject {
		t.Fatalf("setup: the two admissions do not reference the same exact shared version: %v vs %v", a.sharedObject, b.sharedObject)
	}
	bkd, err := NewRetentionBackend(RetentionOptions{Store: mem, Deployment: dep, Bucket: "archive", TrustedCommitKey: pub, MinimumRetention: time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Sanity: both turns enumerate completely while intact.
	for _, id := range []string{"turn-a", "turn-b"} {
		if refs, err := bkd.TurnDisposalRefs(ctx, "tenant", id); err != nil || len(refs) == 0 {
			t.Fatalf("setup: intact turn %s does not enumerate: %v", id, err)
		}
	}
	// Break B's subsequent event chain: delete the middle slot (slot 1)
	// while the terminal slot survives. The verified enumeration now fails
	// (chain contiguity), so every reference decision about B falls back to
	// the namespace enumeration.
	mem.delete("charter/v1/"+dep+"/tenant/events/turn-b/1", b.slotVersions[0])
	if _, err := bkd.TurnDisposalRefs(ctx, "tenant", "turn-b"); err == nil {
		t.Fatal("setup: the chain-broken sibling still enumerates verified")
	}
	enum, err := bkd.TurnNamespaceRefs(ctx, "tenant", "turn-b")
	if err != nil {
		t.Fatalf("namespace fallback failed: %v", err)
	}
	if !enum.Complete {
		t.Fatalf("the fallback enumeration of a chain-broken sibling with readable slots must stay complete (deleted slots are absent, not unknown)")
	}
	has := func(r VersionRef) bool {
		for _, got := range enum.Refs {
			if got == r {
				return true
			}
		}
		return false
	}
	// FINDING 1: the fallback must include the admission marker itself, the
	// admission event data and the admission-only input object.
	if !has(VersionRef{Key: b.admissionSlot, Version: b.admissionVersion}) {
		t.Fatalf("FINDING 1: the fallback reference set excludes the sibling's admission marker %s", b.admissionSlot)
	}
	if !has(b.admissionEvent) {
		t.Fatalf("FINDING 1: the fallback reference set excludes the admission's event data %s", b.admissionEvent.Key)
	}
	if !has(b.sharedObject) {
		t.Fatalf("FINDING 1: the fallback reference set excludes the admission-only shared object %s - disposing the sibling turn referencing the same exact version would delete the surviving turn's input evidence", b.sharedObject.Key)
	}
	// The remaining slot references stay enumerated (convergence for the
	// surviving bytes is preserved).
	if len(enum.Refs) == 0 {
		t.Fatal("FINDING 1: the fallback enumerated nothing")
	}
	sort.Slice(enum.Refs, func(i, j int) bool { return enum.Refs[i].Key < enum.Refs[j].Key })
}

// TestNamespaceFallbackAdmissionUnreadableIsUnknown: an admission marker
// that is listed but whose read fails is an UNKNOWN reference set, never a
// reference-free one (fail closed on unreadable reference metadata).
func TestNamespaceFallbackAdmissionUnreadableIsUnknown(t *testing.T) {
	seed := sha256.Sum256([]byte("round3 fallback fixture"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	mem := &round3Memory{objects: map[string]map[string]s3transport.Version{}, deleted: map[string]bool{}}
	const dep = "dep"
	sharedKey := "charter/v1/" + dep + "/tenant/data/objects/r3-shared2"
	b := buildRound3Turn(t, priv, mem, "turn-b2", sharedKey, "")
	faulty := &round3FaultyRead{inner: mem, failKey: b.admissionSlot}
	bkd, err := NewRetentionBackend(RetentionOptions{Store: faulty, Deployment: dep, Bucket: "archive", TrustedCommitKey: pub, MinimumRetention: time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	enum, err := bkd.TurnNamespaceRefs(context.Background(), "tenant", "turn-b2")
	if err == nil && enum.Complete {
		t.Fatal("FINDING 1: an unreadable admission marker yielded a complete fallback reference set - its references are unknown, never absent")
	}
}

// round3FaultyRead fails reads of one key (transient storage failure).
type round3FaultyRead struct {
	inner   *round3Memory
	failKey string
}

func (f *round3FaultyRead) Create(ctx context.Context, key string, b []byte, until time.Time) (string, error) {
	return f.inner.Create(ctx, key, b, until)
}
func (f *round3FaultyRead) Read(ctx context.Context, key, id string) (s3transport.Version, error) {
	if key == f.failKey {
		return s3transport.Version{}, errRound3Read
	}
	return f.inner.Read(ctx, key, id)
}
func (f *round3FaultyRead) Versions(ctx context.Context, prefix string) ([]s3transport.Ref, error) {
	return f.inner.Versions(ctx, prefix)
}
func (f *round3FaultyRead) Bucket() string { return f.inner.Bucket() }

type round3ReadError struct{}

func (round3ReadError) Error() string { return "round3: injected admission read failure" }

var errRound3Read = round3ReadError{}
