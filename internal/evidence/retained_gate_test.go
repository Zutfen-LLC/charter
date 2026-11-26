package evidence_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

// This only drives the recorder boundary. It deliberately uses PostgreSQL;
// it is not a test of storage retention or of a storage implementation.
type gateCheckBackend struct {
	evidence.Backend
	rejectAt string
	calls    []string
}

func (b *gateCheckBackend) VerifyRetainedTurn(_ context.Context, tenant, turn string, expected []evidence.Event) error {
	if len(expected) == 0 || expected[0]["tenant_id"] != tenant || expected[0]["turn_id"] != turn {
		return errors.New("turn coordinates not bound")
	}
	tail, _ := expected[len(expected)-1]["type"].(string)
	b.calls = append(b.calls, tail)
	if tail == b.rejectAt {
		return errors.New("retained evidence readback unavailable")
	}
	return nil
}

func TestRetainedReadbackRefusesDispatchOrDelivery(t *testing.T) {
	for _, tc := range []struct {
		tail       string
		modelCalls int32
	}{{"evidence_ack", 0}, {"turn_completed", 1}} {
		t.Run(tc.tail, func(t *testing.T) {
			var b *gateCheckBackend
			f := newFx(t, func(inner evidence.Backend) evidence.Backend {
				b = &gateCheckBackend{Backend: inner, rejectAt: tc.tail}
				return b
			})
			got, err := f.rec.Process(context.Background(), f.req("protected-readback", "synthetic exact input"), f.model("must not be returned"), nil)
			if !errors.Is(err, evidence.ErrFailClosed) || len(got.Output) != 0 || f.calls.Load() != tc.modelCalls {
				t.Fatalf("readback failure escaped gate: err=%v outputLen=%d modelCalls=%d expected=%d stages=%v", err, len(got.Output), f.calls.Load(), tc.modelCalls, b.calls)
			}
		})
	}
}
