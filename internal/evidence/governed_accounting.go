package evidence

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

const budgetVersion = "charter-budget-v1"

func settlementPayload(events []Event, reserved int) map[string]any {
	if i := last(events, "usage_reserved"); i >= 0 && str(payload(events[i]), "accounting_version") == budgetVersion {
		if n, ok := acknowledgedCost(events); ok {
			return map[string]any{"units": n, "basis": "provider_reported"}
		}
	}
	return map[string]any{"units": reserved, "basis": "reserved_max"}
}

func noDispatchReason(r string) bool {
	switch r {
	case "route_revoked_before_dispatch", "dispatch_denied", "cancelled_before_dispatch", "dispatch_ownership_lost":
		return true
	}
	return false
}

func interruptedSettlement(events []Event, reason string) map[string]any {
	p := settlementPayload(events, reservedUnits(events))
	if i := last(events, "usage_reserved"); i >= 0 && str(payload(events[i]), "accounting_version") == budgetVersion && noDispatchReason(reason) && DeriveDisclosure(events) == DisclosureUnknown && last(events, "output_recorded") < 0 {
		p["confirmed_no_dispatch"] = reason
	}
	return p
}

func acknowledgedCost(events []Event) (int64, bool) {
	i := last(events, "output_recorded")
	if i < 0 || i+1 >= len(events) || last(events[:i], "provider_accepted") < 0 || str(events[i+1], "type") != "evidence_ack" {
		return 0, false
	}
	n, ok := integer(payload(events[i])["provider_cost_units"])
	return n, ok && safeBudgetAmount(n)
}

func (rc *Recorder) reconcile(ctx context.Context, t *turn) error {
	if rc.Accounting == nil {
		return nil
	}
	wc, cancel := rc.wctx(ctx)
	defer cancel()
	return rc.Accounting(wc, rc.Backend, t.tenant, t.id)
}

// ReconcileBudget never loads content from the workspace and never sends to a
// provider. It only uses a verified terminal evidence log to reduce a possible
// charge. An unavailable or unverified log leaves the reservation outstanding.
func (b PG) ReconcileBudget(ctx context.Context, backend Backend, tenant, turnID string) error {
	var id, status string
	var dispatch bool
	err := b.DB.QueryRow(ctx, `SELECT reservation_id::text,status,dispatch_possible FROM evidence_budget_reservations WHERE tenant_id=$1::uuid AND turn_id=$2::uuid`, tenant, turnID).Scan(&id, &status, &dispatch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if status != "open" {
		return nil
	}
	evs, err := backend.Load(ctx, tenant, turnID)
	if err != nil {
		return err
	}
	if len(evs) == 0 {
		return errors.New("budget: evidence missing")
	}
	var objects map[string][]byte
	if retained, ok := backend.(retainedTurnBackend); ok {
		if err := retained.VerifyRetainedTurn(ctx, tenant, turnID, evs); err != nil {
			return err
		}
		objects, err = retained.LoadRetainedObjects(ctx, tenant, turnID, evs)
	} else {
		objects, err = loadObjects(ctx, backend, tenant, evs)
	}
	if err != nil {
		return err
	}
	if len(VerifyFull(evs, objects)) != 0 {
		return errors.New("budget: terminal evidence failed verification")
	}
	if !dispatch {
		if last(evs, "provider_accepted") >= 0 || last(evs, "response_released") >= 0 {
			return errors.New("budget: unarmed reservation has dispatch evidence")
		}
		return b.ReleaseUnmarked(ctx, id)
	}
	settle := last(evs, "usage_settled")
	if settle < 0 {
		return errors.New("budget: armed reservation has no settlement evidence")
	}
	p := payload(evs[settle])
	if noDispatchReason(str(p, "confirmed_no_dispatch")) {
		n := int64(0)
		return b.Settle(ctx, id, &n)
	}
	if str(p, "basis") == "provider_reported" {
		n, ok := integer(p["units"])
		if !ok {
			return errors.New("budget: invalid exact settlement")
		}
		return b.Settle(ctx, id, &n)
	}
	return b.Settle(ctx, id, nil)
}

func (b PG) RecoverBudget(ctx context.Context, backend Backend) error {
	pending, err := b.Outstanding(ctx)
	if err != nil {
		return err
	}
	for _, row := range pending {
		r := row.Reservation
		if err := b.ReconcileBudget(ctx, backend, r.TenantID, r.TurnID); err != nil {
			return err
		}
	}
	return nil
}
