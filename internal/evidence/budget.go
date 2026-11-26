package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const MaxBudgetAmount int64 = 1<<53 - 1

func safeBudgetAmount(v int64) bool { return v >= 0 && v <= MaxBudgetAmount }

var ErrBudgetConflict = errors.New("evidence: budget idempotency conflict")
var ErrBudgetDenied = errors.New("evidence: budget cap or policy denied")
var ErrBudgetTransition = errors.New("evidence: invalid budget transition")

type BudgetPolicy struct {
	TenantID, ProjectID string
	LocalOnly           bool
	AllowedModels       []string
	ProjectCap          int64
	TenantCap           *int64
	Enabled             bool
}
type BudgetReservation struct {
	TenantID, ProjectID, TurnID, IdempotencyKey string
	ModelID                                     string
	Destination                                 Destination
	Amount                                      int64
}
type BudgetReceipt struct {
	ID          string
	PeriodStart time.Time
	Replayed    bool
}
type BudgetOutstanding struct {
	Reservation      BudgetReservation
	PeriodStart      time.Time
	DispatchPossible bool
}
type BudgetModelSummary struct {
	ModelID     string `json:"model_id"`
	Outstanding int64  `json:"outstanding"`
	Settled     int64  `json:"settled"`
	Unknown     int64  `json:"unknown"`
}
type BudgetSummary struct {
	TenantID    string               `json:"-"`
	ProjectID   string               `json:"project_id"`
	PeriodStart time.Time            `json:"period_start"`
	ProjectCap  int64                `json:"project_cap"`
	TenantCap   *int64               `json:"tenant_cap,omitempty"`
	Outstanding int64                `json:"outstanding"`
	Settled     int64                `json:"settled"`
	Unknown     int64                `json:"unknown"`
	Remaining   int64                `json:"remaining"`
	Frozen      bool                 `json:"frozen"`
	Models      []BudgetModelSummary `json:"models"`
}

// SetPolicy is owner-side only: application roles have no DML or callable setter.
func (b PG) SetPolicy(ctx context.Context, p BudgetPolicy) error {
	if p.TenantID == "" || p.ProjectID == "" || !safeBudgetAmount(p.ProjectCap) || p.ProjectCap == 0 || (p.TenantCap != nil && (!safeBudgetAmount(*p.TenantCap) || *p.TenantCap == 0)) {
		return errors.New("evidence: invalid budget policy")
	}
	tx, _, release, err := b.begin(ctx)
	if err != nil {
		return err
	}
	defer release()
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT evidence_budget_set_policy($1::uuid,$2::uuid,$3,$4,$5,$6)`, p.TenantID, p.ProjectID, p.LocalOnly, p.AllowedModels, p.ProjectCap, p.TenantCap)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (b PG) GetPolicy(ctx context.Context, tenant, project string) (BudgetPolicy, error) {
	var p BudgetPolicy
	p.TenantID = tenant
	p.ProjectID = project
	err := b.DB.QueryRow(ctx, `SELECT local_only,allowed_models,project_cap,tenant_cap,enabled AND NOT frozen FROM evidence_budget_policy WHERE tenant_id=$1::uuid AND project_id=$2::uuid`, tenant, project).Scan(&p.LocalOnly, &p.AllowedModels, &p.ProjectCap, &p.TenantCap, &p.Enabled)
	return p, err
}
func validateBudgetReservation(r BudgetReservation) error {
	if r.TenantID == "" || r.ProjectID == "" || r.TurnID == "" || r.IdempotencyKey == "" || r.ModelID == "" || r.Destination.Provider == "" || r.Destination.EndpointID == "" || r.Destination.ModelID == "" || !safeBudgetAmount(r.Amount) {
		return errors.New("evidence: invalid budget reservation")
	}
	return nil
}

// Reserve freezes the UTC day in PostgreSQL and atomically checks project and tenant exposure.
func (b PG) Reserve(ctx context.Context, r BudgetReservation) (BudgetReceipt, error) {
	if err := validateBudgetReservation(r); err != nil {
		return BudgetReceipt{}, err
	}
	tx, _, release, err := b.begin(ctx)
	if err != nil {
		return BudgetReceipt{}, err
	}
	defer release()
	defer tx.Rollback(ctx)
	var id string
	var period time.Time
	var replay bool
	err = tx.QueryRow(ctx, `SELECT reservation_id::text,period_start,replayed FROM evidence_budget_reserve($1::uuid,$2::uuid,$3::uuid,$4,$5,$6,$7,$8,$9,$10)`, r.TenantID, r.ProjectID, r.TurnID, r.IdempotencyKey, r.ModelID, r.Destination.Provider, r.Destination.EndpointID, r.Destination.ModelID, r.Amount, MaxBudgetAmount).Scan(&id, &period, &replay)
	if err != nil {
		return BudgetReceipt{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return BudgetReceipt{}, err
	}
	return BudgetReceipt{ID: id, PeriodStart: period, Replayed: replay}, nil
}
func (b PG) MarkDispatchPossible(ctx context.Context, id string) error {
	return b.transition(ctx, `SELECT evidence_budget_mark_dispatch($1::uuid)`, id)
}
func (b PG) ReleaseUnmarked(ctx context.Context, id string) error {
	return b.transition(ctx, `SELECT evidence_budget_release_unmarked($1::uuid)`, id)
}
func (b PG) transition(ctx context.Context, q string, args ...any) error {
	tx, _, release, err := b.begin(ctx)
	if err != nil {
		return err
	}
	defer release()
	defer tx.Rollback(ctx)
	var ok bool
	if err = tx.QueryRow(ctx, q, args...).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrBudgetTransition
	}
	return tx.Commit(ctx)
}

func (b PG) NoteOverrun(ctx context.Context, id string, units int64) error {
	return b.transition(ctx, `SELECT evidence_budget_note_overrun($1::uuid,$2)`, id, units)
}

// Settle records verified exact usage or conservatively charges max reservation if unknown. Owner/evidence backend only.
func (b PG) Settle(ctx context.Context, id string, exact *int64) error {
	if exact != nil && !safeBudgetAmount(*exact) {
		return fmt.Errorf("evidence: invalid settlement amount")
	}
	tx, _, release, err := b.begin(ctx)
	if err != nil {
		return err
	}
	defer release()
	defer tx.Rollback(ctx)
	var ok bool
	if err = tx.QueryRow(ctx, `SELECT evidence_budget_settle($1::uuid,$2,$3)`, id, exact, exact == nil).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrBudgetConflict
	}
	return tx.Commit(ctx)
}
func (b PG) Outstanding(ctx context.Context) ([]BudgetOutstanding, error) {
	rows, err := b.DB.Query(ctx, `SELECT tenant_id::text,project_id::text,turn_id::text,idempotency_key,model_id,provider,endpoint_id,destination_model_id,reserved_amount,period_start,dispatch_possible FROM evidence_budget_reservations WHERE status='open' ORDER BY period_start,tenant_id,project_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BudgetOutstanding{}
	for rows.Next() {
		var o BudgetOutstanding
		r := &o.Reservation
		if err = rows.Scan(&r.TenantID, &r.ProjectID, &r.TurnID, &r.IdempotencyKey, &r.ModelID, &r.Destination.Provider, &r.Destination.EndpointID, &r.Destination.ModelID, &r.Amount, &o.PeriodStart, &o.DispatchPossible); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (b PG) Summary(ctx context.Context, tenant, project string) (BudgetSummary, error) {
	var s BudgetSummary
	s.TenantID = tenant
	s.ProjectID = project
	tx, err := b.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return s, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `SELECT period_start,project_cap,tenant_cap,outstanding,settled,unknown,remaining,frozen FROM evidence_budget_summary($1::uuid,$2::uuid)`, tenant, project).Scan(&s.PeriodStart, &s.ProjectCap, &s.TenantCap, &s.Outstanding, &s.Settled, &s.Unknown, &s.Remaining, &s.Frozen)
	if err != nil {
		return s, err
	}
	rows, err := tx.Query(ctx, `SELECT model_id,COALESCE(sum(GREATEST(reserved_amount,overrun_floor)) FILTER (WHERE status='open'),0)::bigint,
      COALESCE(sum(actual_amount) FILTER (WHERE status='settled' AND NOT unknown),0)::bigint,
      COALESCE(sum(actual_amount) FILTER (WHERE status='settled' AND unknown),0)::bigint
      FROM evidence_budget_reservations WHERE tenant_id=$1::uuid AND project_id=$2::uuid AND (period_start=$3 OR status='open')
      GROUP BY model_id ORDER BY model_id`, tenant, project, s.PeriodStart)
	if err != nil {
		return s, err
	}
	defer rows.Close()
	s.Models = []BudgetModelSummary{}
	for rows.Next() {
		var row BudgetModelSummary
		if err := rows.Scan(&row.ModelID, &row.Outstanding, &row.Settled, &row.Unknown); err != nil {
			return s, err
		}
		s.Models = append(s.Models, row)
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	return s, tx.Commit(ctx)
}
