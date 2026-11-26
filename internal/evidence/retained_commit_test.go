package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func retainedFixture(t *testing.T, seq uint64) (retainedCommit, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("test signing seed"))
	key := ed25519.NewKeyFromSeed(seed[:])
	event := retainedObjectReceipt{Deployment: "dep", Tenant: "tenant", EvidenceID: "event:turn:0", Bucket: "bucket", Key: "dep/tenant/events/turn/0", Version: "v-event", SHA256: SHA256([]byte("event")), Length: 5, Mode: "COMPLIANCE", RetainUntil: "2030-01-01T00:00:00Z", Seq: 0, EventHash: SHA256([]byte("event"))}
	c := retainedCommit{Schema: "charter.retained-commit.v1", Deployment: "dep", Slot: "dep/tenant/turns/turn/seq/0", Tenant: "tenant", Project: "project", Turn: "turn", Seq: seq, EventHash: SHA256([]byte("event")), Event: event, Objects: []retainedObjectReceipt{}}
	if seq == 0 {
		c.Admission = &retainedAdmission{IdempotencyDigest: SHA256([]byte("idem")), Fingerprint: SHA256([]byte("fingerprint"))}
	} else {
		c.Predecessor = &retainedMarkerReceipt{Bucket: "bucket", Key: "dep/tenant/turns/turn/turn/seq/0", Version: "v-prev", SHA256: SHA256([]byte("prev")), Length: 10, Mode: "COMPLIANCE", RetainUntil: "2030-01-01T00:00:00Z"}
	}
	return c, key
}
func TestRetainedCommitSignVerifyCanonical(t *testing.T) {
	c, key := retainedFixture(t, 0)
	signed, err := signRetainedCommit(c, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyRetainedCommit(signed, ed25519.PublicKey(key.Public().(ed25519.PublicKey)), retainedCoordinates{Deployment: "dep", Tenant: "tenant", Project: "project", Turn: "turn", Seq: 0, Slot: c.Slot})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("verified payload empty")
	}
	if _, err := ParseJSON(got); err != nil {
		t.Fatalf("verified payload invalid: %v", err)
	}
	if _, err = verifyRetainedCommit(append([]byte(" "), signed...), key.Public().(ed25519.PublicKey), retainedCoordinates{Deployment: "dep", Tenant: "tenant", Project: "project", Turn: "turn", Seq: 0, Slot: c.Slot}); err == nil {
		t.Fatal("accepted non-canonical encoding")
	}
}
func TestRetainedCommitRejectsWrongKeyAndDuplicateFields(t *testing.T) {
	c, key := retainedFixture(t, 0)
	signed, err := signRetainedCommit(c, key)
	if err != nil {
		t.Fatal(err)
	}
	otherSeed := sha256.Sum256([]byte("other"))
	other := ed25519.NewKeyFromSeed(otherSeed[:])
	coords := retainedCoordinates{Deployment: "dep", Tenant: "tenant", Project: "project", Turn: "turn", Seq: 0, Slot: c.Slot}
	if _, err = verifyRetainedCommit(signed, other.Public().(ed25519.PublicKey), coords); err == nil {
		t.Fatal("accepted unknown key")
	}
	dup := append([]byte(`{"schema":"x","schema":"y"}`), 0)
	if _, err = verifyRetainedCommit(dup, key.Public().(ed25519.PublicKey), coords); err == nil {
		t.Fatal("accepted duplicate JSON field")
	}
}
func TestRetainedReceiptIDBindsVersionAndRetention(t *testing.T) {
	c, _ := retainedFixture(t, 0)
	r := c.Event
	id, err := retainedReceiptID(r)
	if err != nil {
		t.Fatal(err)
	}
	changed := r
	changed.Version = "other"
	id2, err := retainedReceiptID(changed)
	if err != nil {
		t.Fatal(err)
	}
	if id == id2 {
		t.Fatal("version not bound")
	}
	changed = r
	changed.RetainUntil = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	id2, err = retainedReceiptID(changed)
	if err != nil {
		t.Fatal(err)
	}
	if id == id2 {
		t.Fatal("retention not bound")
	}
}
func TestRetainedCommitRejectsMalformedDigestAndUnsortedObjects(t *testing.T) {
	c, key := retainedFixture(t, 0)
	c.Event.SHA256 = "sha256:" + hex.EncodeToString(make([]byte, 32))
	c.Objects = []retainedObjectReceipt{{Deployment: "dep", Tenant: "tenant", EvidenceID: "z", Bucket: "bucket", Key: "z", Version: "v", SHA256: SHA256(nil), Length: 0, Mode: "COMPLIANCE", RetainUntil: "2030-01-01T00:00:00Z"}, {Deployment: "dep", Tenant: "tenant", EvidenceID: "a", Bucket: "bucket", Key: "a", Version: "v", SHA256: SHA256(nil), Length: 0, Mode: "COMPLIANCE", RetainUntil: "2030-01-01T00:00:00Z"}}
	if _, err := signRetainedCommit(c, key); err == nil {
		t.Fatal("accepted unsorted object receipts")
	}
	c.Objects = nil
	c.Event.SHA256 = "bad"
	if _, err := signRetainedCommit(c, key); err == nil {
		t.Fatal("accepted malformed digest")
	}
}

func TestRetainedReceiptRejectsNullVersionAndUnsafeInteger(t *testing.T) {
	c, _ := retainedFixture(t, 0)
	r := c.Event
	r.Version = "null"
	if _, err := retainedReceiptID(r); err == nil {
		t.Fatal("accepted S3 null version")
	}
	r.Version = c.Event.Version
	r.Length = 1 << 53
	if _, err := retainedReceiptID(r); err == nil {
		t.Fatal("accepted non-portable receipt length")
	}
}
