package routing

import (
	"context"
	"errors"
	"fmt"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Governance pins one resolved model for this turn. Configuration is immutable
// across serving; project authorization is read again before invocation.
func Governance(cfg Config, budget evidence.PG, syntheticRetention bool, countSynthetic func()) evidence.Governance {
	return func(ctx context.Context, r evidence.Request) (evidence.GovernedPlan, error) {
		id := r.ModelID
		if id == "" {
			id = "det-a"
		}
		resolve := func(ctx context.Context) (Model, error) {
			p, err := budget.GetPolicy(ctx, r.TenantID, r.ProjectID)
			if errors.Is(err, pgx.ErrNoRows) {
				return Model{}, evidence.ErrDenied
			}
			if err != nil {
				return Model{}, errors.New("routing: project policy unavailable")
			}
			if !p.Enabled {
				return Model{}, evidence.ErrDenied
			}
			c := cfg
			c.Policy = Policy{AllowedModelIDs: p.AllowedModels, LocalOnly: p.LocalOnly}
			m, err := c.Resolve(id)
			if err != nil || (syntheticRetention && m.Kind == KindLocalHTTP) {
				return Model{}, evidence.ErrDenied
			}
			return m, nil
		}
		m, err := resolve(ctx)
		if err != nil {
			return evidence.GovernedPlan{}, err
		}
		var receipt evidence.BudgetReceipt
		var adapter Adapter
		switch m.Kind {
		case KindDeterministicA, KindDeterministicB:
			adapter = DeterministicAdapter{Kind: m.Kind}
		case KindLocalHTTP:
			adapter = HTTPAdapter{Timeout: cfg.Timeout, BearerToken: cfg.BearerToken}
		default:
			return evidence.GovernedPlan{}, evidence.ErrDenied
		}
		return evidence.GovernedPlan{
			Destination: m.Destination, RegistryModel: m.ID, PolicyVersion: "charter-routing-v1",
			Build: func(r evidence.Request) ([]byte, error) {
				return evidence.RenderRequest(m.Destination, r.Input, r.Sources)
			},
			Reserve: func(ctx context.Context, turn string, sent []byte) (int, error) {
				if int64(len(sent)) > m.MaxRequestBytes {
					return 0, evidence.ErrDenied
				}
				max, ok := cost(m, int64(len(sent)), m.MaxOutputBytes)
				if !ok {
					return 0, evidence.ErrDenied
				}
				var err error
				receipt, err = budget.Reserve(ctx, evidence.BudgetReservation{TenantID: r.TenantID, ProjectID: r.ProjectID, TurnID: turn, IdempotencyKey: r.IdempotencyKey, ModelID: m.ID, Destination: m.Destination, Amount: max})
				var pe *pgconn.PgError
				if errors.As(err, &pe) && (pe.Code == "54000" || pe.Code == "42501") {
					return 0, evidence.ErrDenied
				}
				if err != nil {
					return 0, errors.New("routing: reservation was not confirmed")
				}
				if receipt.Replayed {
					return 0, evidence.ErrTurnInFlight
				}
				return int(max), nil
			},
			Arm: func(ctx context.Context, _ string) error { return budget.MarkDispatchPossible(ctx, receipt.ID) },
			CheckRoute: func(ctx context.Context) error {
				current, err := resolve(ctx)
				if err != nil {
					return err
				}
				if current != m {
					return evidence.ErrDenied
				}
				return nil
			},
			Invoke: func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
				if err := ctx.Err(); err != nil {
					return evidence.ModelOutcome{}, err
				}
				if syntheticRetention && countSynthetic != nil {
					countSynthetic()
				}
				o, err := adapter.Invoke(ctx, m, sent)
				out := o.ModelOutcome
				if err != nil {
					return out, errors.New("routing: adapter did not complete")
				}
				if out.Accepted && !o.UsageMissing && !o.UsageInconsistent && !o.UsageExcessive {
					if n, ok := cost(m, o.InputBytes, o.OutputBytes); ok {
						out.UsageUnits = &n
					} else {
						return out, fmt.Errorf("routing: usage exceeds numeric domain")
					}
				}
				return out, nil
			},
		}, nil
	}
}

func cost(m Model, in, out int64) (int64, bool) {
	if in < 0 || out < 0 || m.RequestByteRate < 0 || m.OutputByteRate < 0 {
		return 0, false
	}
	if (in > 0 && m.RequestByteRate > maxSafeInteger/in) || (out > 0 && m.OutputByteRate > maxSafeInteger/out) {
		return 0, false
	}
	a, b := in*m.RequestByteRate, out*m.OutputByteRate
	if a > maxSafeInteger-b {
		return 0, false
	}
	return a + b, true
}
