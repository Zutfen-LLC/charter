package evidence_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

func TestC05PostArmAuthorizationAndRouteRefusalBeforeDispatch(t *testing.T) {
	for _, mode := range []string{"authorization", "route", "ambiguous-arm"} {
		t.Run(mode, func(t *testing.T) {
			f := newFx(t, nil)
			ctx := context.Background()
			stop := errors.New("intentional refusal")
			armed := false
			f.rec.Governance = func(_ context.Context, _ evidence.Request) (evidence.GovernedPlan, error) {
				return evidence.GovernedPlan{
					Destination: f.policy.Destination, PolicyVersion: "test-c05", RegistryModel: "test-model-a",
					Build: func(r evidence.Request) ([]byte, error) {
						return evidence.RenderRequest(f.policy.Destination, r.Input, r.Sources)
					},
					Reserve: func(context.Context, string, []byte) (int, error) { return 100, nil },
					Arm: func(context.Context, string) error {
						armed = true
						if mode == "ambiguous-arm" {
							return stop
						}
						return nil
					},
					CheckRoute: func(context.Context) error {
						if mode == "route" && armed {
							return stop
						}
						return nil
					},
					Invoke: f.model("wrong"),
				}, nil
			}
			gate := func(context.Context) error {
				if mode == "authorization" && armed {
					return stop
				}
				return nil
			}
			_, err := f.rec.Process(ctx, f.req("abc", "synthetic"), f.model("legacy bypass"), gate)
			if err == nil || !armed || f.calls.Load() != 0 {
				t.Fatalf("err=%v armed=%t provider invocations=%d", err, armed, f.calls.Load())
			}
		})
	}
}
