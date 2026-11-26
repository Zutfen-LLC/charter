package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// Supplemental only: fake storage semantics plus an actual PostgreSQL fence.
func TestRetainedRecorderReconstructsAndIgnoresLatestSubstitution(t *testing.T) {
	ctx := context.Background()
	p := PG{DB: testdb.New(t)}
	fence, err := p.AcquireFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fence.Release)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &retainedMemory{objects: map[string]map[string]s3transport.Version{}}
	o := RetentionOptions{Store: m, Deployment: "synthetic", Bucket: m.Bucket(), TrustedCommitKey: pub, Signer: priv, Fence: fence, RetainFor: time.Hour}
	b, err := NewRetentionBackend(o)
	if err != nil {
		t.Fatal(err)
	}
	rec := &Recorder{Fence: fence, Backend: b, Policy: func(context.Context, Request) (Decision, error) {
		return Decision{Allow: true, PolicyVersion: "policy", ReserveUnits: 3, Destination: Destination{Provider: "mock", EndpointID: "local", ModelID: "model"}}, nil
	}}
	req := Request{TenantID: "tenant", ProjectID: "project", MatterID: "matter", CustodianID: "custodian", IdempotencyKey: "idem", RequestID: "request", Input: []byte("exact synthetic input"), Sources: []Source{{ID: "source", Version: 1, Bytes: []byte("source excerpt")}}}
	out := []byte("exact output")
	var calls atomic.Int32
	call := func(context.Context, []byte) (ModelOutcome, error) {
		calls.Add(1)
		return ModelOutcome{Accepted: true, Complete: true, Output: out}, nil
	}
	if missing, err := rec.Process(ctx, req, call, nil); !errors.Is(err, ErrFailClosed) || len(missing.Output) != 0 || missing.TurnID != "" || calls.Load() != 0 || len(m.objects) != 0 {
		t.Fatalf("missing fresh gate reached admission or dispatch: calls=%d objects=%d err=%v", calls.Load(), len(m.objects), err)
	}
	r, err := rec.Process(ctx, req, call, func(context.Context) error { return nil })
	if err != nil || string(r.Output) != string(out) {
		t.Fatalf("synthetic turn: %v", err)
	}
	es, err := b.Load(ctx, req.TenantID, r.TurnID)
	if err != nil || len(es) != 12 {
		t.Fatalf("load: %d events: %v", len(es), err)
	}
	// Event coordinates are part of the canonical bytes and of the commit
	// slot; a resealed replay under a different tenant cannot reuse it.
	foreign := make(Event)
	for k, v := range es[1] {
		foreign[k] = v
	}
	foreign["tenant_id"] = "other-tenant"
	if err := Seal(foreign); err != nil {
		t.Fatal(err)
	}
	if receipt, err := b.Append(ctx, foreign); !errors.Is(err, ErrNotFound) || receipt.ID != "" {
		t.Fatalf("cross-tenant append replay: %v", err)
	}
	key := b.objectKey(req.TenantID, SHA256(out))
	m.objects[key]["substitute-latest"] = s3transport.Version{ID: "substitute-latest", Mode: "COMPLIANCE", Until: time.Now().Add(time.Hour), Data: []byte("substituted data")}
	// Reopen with only the pinned public key and namespace, no DB or workspace.
	o.Signer = nil
	o.Fence = nil
	view, err := NewRetentionBackend(o)
	if err != nil {
		t.Fatal(err)
	}
	es, err = view.Load(ctx, req.TenantID, r.TurnID)
	if err != nil {
		t.Fatal(err)
	}
	objs, err := view.LoadRetainedObjects(ctx, req.TenantID, r.TurnID, es)
	if err != nil {
		t.Fatal(err)
	}
	if errs := VerifyRetentionFull(es, objs); len(errs) != 0 {
		t.Fatalf("reconstructed chain: %v", errs)
	}
	if string(objs[SHA256(out)]) != string(out) {
		t.Fatal("latest displaced original output")
	}
	if _, err = view.Load(ctx, "other-tenant", r.TurnID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	n, err := rec.Recover(ctx, time.Time{})
	if n != 0 || err != nil {
		t.Fatalf("startup recovery: %d %v", n, err)
	}
	if withheld, err := rec.Process(ctx, req, call, nil); !errors.Is(err, ErrFailClosed) || len(withheld.Output) != 0 || withheld.Replayed || calls.Load() != 1 {
		t.Fatalf("retained replay without a delivery gate: calls=%d output_bytes=%d err=%v", calls.Load(), len(withheld.Output), err)
	}
	r, err = rec.Process(ctx, req, call, func(context.Context) error { return nil })
	if err != nil || !r.Replayed || string(r.Output) != string(out) || calls.Load() != 1 {
		t.Fatalf("unexpected replay: calls=%d err=%v", calls.Load(), err)
	}
}
