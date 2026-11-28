package records

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
)

const maxExportSnapshotCustodians = 256

var errInvalidExportSnapshot = errors.New("records: invalid export snapshot selection")

// ExportSnapshotRequest is assembled from the authorized principal and
// authoritative admission/catalog/hold reads; TenantID is never request input.
type ExportSnapshotRequest struct {
	TenantID, ProjectID, MatterID string
	Custodians                    []string
	WindowStart, WindowEnd        time.Time
	CustodyActor                  string
	CustodyAt                     time.Time
	Epoch                         int64
	Holds                         []*Hold
	Items                         []Item
	Identities                    []evidence.TurnIdentity
}

type ExportSnapshotVersion struct {
	Key     string `json:"key"`
	Version string `json:"version"`
}

type ExportSnapshotMissingVersion struct {
	Key         string `json:"key"`
	Version     string `json:"version"`
	Disposition string `json:"disposition"`
	PlanEpoch   *int64 `json:"plan_epoch,omitempty"`
}

// ExportSnapshotSharedVersion attributes an exact version of a completed
// disposal that physically survived through another record's references
// (retained_shared). It is attribution, never content: a disposed record
// cannot regain export authority over bytes another record retains, and the
// survivor is neither declared deleted nor absent.
type ExportSnapshotSharedVersion struct {
	Key         string `json:"key"`
	Version     string `json:"version"`
	Disposition string `json:"disposition"`
	PlanEpoch   *int64 `json:"plan_epoch,omitempty"`
}

type ExportSnapshotRecord struct {
	TenantID       string                         `json:"tenant_id"`
	ProjectID      string                         `json:"project_id"`
	MatterID       string                         `json:"matter_id"`
	TurnID         string                         `json:"turn_id"`
	CustodianID    string                         `json:"custodian_id"`
	RecordedAt     time.Time                      `json:"recorded_at"`
	State          string                         `json:"state"`
	HeldBy         []string                       `json:"held_by"`
	Versions       []ExportSnapshotVersion        `json:"versions"`
	Missing        []ExportSnapshotMissingVersion `json:"missing,omitempty"`
	RetainedShared []ExportSnapshotSharedVersion  `json:"retained_shared_versions,omitempty"`
	Classification string                         `json:"classification"`
}

type ExportSnapshot struct {
	TenantID     string                 `json:"tenant_id"`
	ProjectID    string                 `json:"project_id"`
	MatterID     string                 `json:"matter_id"`
	WindowStart  time.Time              `json:"window_start"`
	WindowEnd    time.Time              `json:"window_end"`
	CustodyActor string                 `json:"custody_actor"`
	CustodyAt    time.Time              `json:"custody_at"`
	Epoch        int64                  `json:"matter_hold_epoch"`
	Records      []ExportSnapshotRecord `json:"records"`
	HoldIDs      []string               `json:"hold_ids"`
	Uncovered    []string               `json:"uncovered"`
}

// SelectExportSnapshot freezes a bounded exact selection from serialized,
// authoritative reads. It does not query mutable workspace tables. Lock
// acquisition and parent-side revision revalidation remain caller duties.
func SelectExportSnapshot(r ExportSnapshotRequest) (ExportSnapshot, error) {
	if r.TenantID == "" || r.ProjectID == "" || r.MatterID == "" || r.CustodyActor == "" || r.CustodyAt.IsZero() || r.Epoch < 0 || r.WindowStart.IsZero() || r.WindowEnd.IsZero() || !r.WindowStart.Before(r.WindowEnd) || r.WindowStart.Location() != time.UTC || r.WindowEnd.Location() != time.UTC || r.CustodyAt.Location() != time.UTC || r.WindowEnd.Sub(r.WindowStart) > 366*24*time.Hour || len(r.Custodians) == 0 || len(r.Custodians) > maxExportSnapshotCustodians {
		return ExportSnapshot{}, errInvalidExportSnapshot
	}
	custodians := make(map[string]bool, len(r.Custodians))
	for _, c := range r.Custodians {
		if c == "" || custodians[c] {
			return ExportSnapshot{}, errInvalidExportSnapshot
		}
		custodians[c] = true
	}
	ids := make(map[string]evidence.TurnIdentity, len(r.Identities))
	for _, id := range r.Identities {
		if id.TenantID != r.TenantID || id.TurnID == "" {
			continue
		}
		if _, exists := ids[id.TurnID]; exists {
			return ExportSnapshot{}, fmt.Errorf("%w: ambiguous admission", errInvalidExportSnapshot)
		}
		ids[id.TurnID] = id
	}
	holds := make([]*Hold, 0, len(r.Holds))
	holdIDs := map[string]bool{}
	for _, h := range r.Holds {
		// Only fully effective protection authorizes export. Pending and
		// failed holds fence disposal but have not established readable
		// evidence coverage.
		if h == nil || h.TenantID != r.TenantID || h.MatterID != r.MatterID || h.State != HoldEffective {
			continue
		}
		holds = append(holds, h)
	}
	out := ExportSnapshot{TenantID: r.TenantID, ProjectID: r.ProjectID, MatterID: r.MatterID, WindowStart: r.WindowStart, WindowEnd: r.WindowEnd, CustodyActor: r.CustodyActor, CustodyAt: r.CustodyAt, Epoch: r.Epoch}
	seen := map[string]bool{}
	for _, it := range r.Items {
		// Scope filtering precedes diagnostics to avoid leaking foreign evidence.
		if it.TenantID != r.TenantID || it.ProjectID != r.ProjectID || it.MatterID != r.MatterID || !custodians[it.CustodianID] || it.RecordedAt.Before(r.WindowStart) || !it.RecordedAt.Before(r.WindowEnd) {
			continue
		}
		if it.TurnID == "" || seen[it.TurnID] {
			return ExportSnapshot{}, fmt.Errorf("%w: duplicate catalog identity", errInvalidExportSnapshot)
		}
		seen[it.TurnID] = true
		id, ok := ids[it.TurnID]
		if !ok {
			return ExportSnapshot{}, fmt.Errorf("%w: matching catalog admission unavailable", errInvalidExportSnapshot)
		}
		if id.ProjectID != it.ProjectID || id.MatterID != it.MatterID || id.CustodianID != it.CustodianID || !id.RecordedAt.Equal(it.RecordedAt) {
			return ExportSnapshot{}, fmt.Errorf("%w: catalog/admission mismatch", errInvalidExportSnapshot)
		}
		rec := ExportSnapshotRecord{TenantID: it.TenantID, ProjectID: it.ProjectID, MatterID: it.MatterID, TurnID: it.TurnID, CustodianID: it.CustodianID, RecordedAt: it.RecordedAt, State: it.State, Classification: "uncovered"}
		for _, h := range holds {
			if Matches(h, it.MatterID, it.CustodianID, it.RecordedAt) {
				rec.HeldBy = append(rec.HeldBy, h.ID)
				holdIDs[h.ID] = true
			}
		}
		if len(rec.HeldBy) == 0 {
			out.Uncovered = append(out.Uncovered, it.TurnID)
		} else {
			rec.Classification = "complete"
		}
		out.Records = append(out.Records, rec)
	}
	sort.Slice(out.Records, func(i, j int) bool { return out.Records[i].TurnID < out.Records[j].TurnID })
	sort.Strings(out.Uncovered)
	for id := range holdIDs {
		out.HoldIDs = append(out.HoldIDs, id)
	}
	sort.Strings(out.HoldIDs)
	return out, nil
}

const (
	maxExportSnapshotRecords  = 5000
	maxExportSnapshotVersions = 100000
)

// ExportSnapshotCallbacks adapts the C07 service to the governance store's
// callback contract. Tenant and custody actor are closure-bound authority;
// neither callback accepts them from an export request.
func (s *Service) ExportSnapshotCallbacks(tenantID, custodyActor string) (SnapshotCallback, RevalidateCallback) {
	snapshot := func(ctx context.Context, tx pgx.Tx, intent ExportIntent) ([]byte, error) {
		return s.captureExportSnapshot(ctx, tx, tenantID, custodyActor, intent, time.Now().UTC().Truncate(time.Microsecond))
	}
	revalidate := func(ctx context.Context, tx pgx.Tx, projectID string, intent ExportIntent, prior []byte) error {
		var frozen ExportSnapshot
		if err := json.Unmarshal(prior, &frozen); err != nil {
			return fmt.Errorf("records: invalid frozen export snapshot: %w", err)
		}
		canonical, _, err := canonicalExportIntent(intent)
		if err != nil {
			return err
		}
		canonicalProject, ok := store.CanonicalID(projectID)
		if !ok || canonicalProject != canonical.ProjectID || frozen.TenantID != tenantID || frozen.ProjectID != canonical.ProjectID || frozen.MatterID != canonical.MatterID || frozen.CustodyAt.IsZero() || !frozen.WindowStart.Equal(canonical.WindowStart) || !frozen.WindowEnd.Equal(canonical.WindowEnd) || (custodyActor != "" && frozen.CustodyActor != custodyActor) {
			return ErrExportConflict
		}
		return s.revalidateFrozenExport(ctx, tx, frozen, canonical)
	}
	return snapshot, revalidate
}

func (s *Service) captureExportSnapshot(ctx context.Context, tx pgx.Tx, tenantID, custodyActor string, intent ExportIntent, custodyAt time.Time) ([]byte, error) {
	if s == nil || s.Store == nil || s.Backend == nil || tx == nil || !s.Retained || s.Backend.Info().Kind != evidence.RetentionProfile {
		return nil, errors.New("records: retained snapshot service unavailable")
	}
	var ok bool
	if tenantID, ok = store.CanonicalID(tenantID); !ok {
		return nil, ErrForbidden
	}
	if custodyActor, ok = store.CanonicalID(custodyActor); !ok {
		return nil, ErrForbidden
	}
	i, _, err := canonicalExportIntent(intent)
	if err != nil {
		return nil, err
	}
	if len(i.CustodianIDs) == 0 || len(i.CustodianIDs) > maxExportSnapshotCustodians || i.WindowEnd.Sub(i.WindowStart) > 366*24*time.Hour {
		return nil, errInvalidExportSnapshot
	}
	// The enclosing governance transaction already holds tenants. Continue the
	// C07 lock order exactly: protection, matching retention rows, matter epoch.
	if err := lockProtection(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT tenant_id::text, turn_id::text, matter_id::text, project_id::text, custodian_id::text,
		recorded_at, retention_expires_at, state, observed_epoch, pending_since, sweep_by::text, purge_by::text, tombstoned_at, purged_at
		FROM retention_items WHERE tenant_id=$1 AND project_id=$2 AND matter_id=$3
		AND custodian_id::text = ANY($4::text[]) AND recorded_at >= $5 AND recorded_at < $6
		ORDER BY turn_id FOR UPDATE`, tenantID, i.ProjectID, i.MatterID, i.CustodianIDs, i.WindowStart, i.WindowEnd)
	if err != nil {
		return nil, err
	}
	lockedItems, err := scanItems(rows, nil)
	if err != nil {
		return nil, err
	}
	epoch, err := lockEpoch(ctx, tx, tenantID, i.MatterID, false)
	if err != nil {
		return nil, err
	}
	// Deterministic interleave point for concurrency qualification: the
	// capture transaction holds the protection fence, the scoped item rows
	// and the matter epoch row at this point, so a concurrent hold release
	// or scope change blocks on the epoch row until the capture commits.
	s.Store.hookEpoch("export_snapshot", tenantID, i.MatterID)
	holds, err := ActiveHolds(ctx, tx, tenantID, i.MatterID)
	if err != nil {
		return nil, err
	}
	identities, err := s.inventory(ctx, tx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("records: export inventory: %w", err)
	}
	items, err := s.retentionIndex(ctx, tx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("records: export catalog: %w", err)
	}
	identityByID := make(map[string]evidence.TurnIdentity, len(identities))
	for _, id := range identities {
		if id.TenantID != tenantID || id.TurnID == "" {
			return nil, errors.New("records: export inventory returned invalid identity")
		}
		if _, exists := identityByID[id.TurnID]; exists {
			return nil, fmt.Errorf("records: export inventory has ambiguous turn %s", id.TurnID)
		}
		identityByID[id.TurnID] = id
	}
	inScope := func(project, matter, custodian string, recordedAt time.Time) bool {
		return project == i.ProjectID && matter == i.MatterID && contains(i.CustodianIDs, custodian) && !recordedAt.Before(i.WindowStart) && recordedAt.Before(i.WindowEnd)
	}
	var scopedItems []Item
	for _, item := range items {
		if item.TenantID == tenantID && inScope(item.ProjectID, item.MatterID, item.CustodianID, item.RecordedAt) {
			scopedItems = append(scopedItems, item)
		}
	}
	if len(scopedItems) != len(lockedItems) {
		return nil, errors.New("records: matching catalog changed or did not match locked retention rows")
	}
	locked := make(map[string]bool, len(lockedItems))
	for _, item := range lockedItems {
		locked[item.TurnID] = true
	}
	for _, item := range scopedItems {
		if !locked[item.TurnID] {
			return nil, errors.New("records: matching retention item was not locked")
		}
	}
	for _, id := range identities {
		if id.TenantID == tenantID && inScope(id.ProjectID, id.MatterID, id.CustodianID, id.RecordedAt) {
			if _, exists := items[id.TurnID]; !exists {
				return nil, fmt.Errorf("records: in-scope admission %s has no lifecycle catalog row", id.TurnID)
			}
		}
	}
	if len(scopedItems) > maxExportSnapshotRecords {
		return nil, errInvalidExportSnapshot
	}
	byTurn := make(map[string]frozenExportPresence, len(scopedItems))
	authorityIDs := append([]evidence.TurnIdentity(nil), identities...)
	totalVersions := 0
	for _, item := range scopedItems {
		id, exists := identityByID[item.TurnID]
		if exists && (id.ProjectID != item.ProjectID || id.MatterID != item.MatterID || id.CustodianID != item.CustodianID || !id.RecordedAt.Equal(item.RecordedAt)) {
			return nil, fmt.Errorf("records: in-scope catalog/admission mismatch for turn %s", item.TurnID)
		}
		held := false
		for _, hold := range holds {
			if hold != nil && hold.State == HoldEffective && hold.TenantID == tenantID && Matches(hold, item.MatterID, item.CustodianID, item.RecordedAt) {
				held = true
				break
			}
		}
		if !held {
			if !exists {
				return nil, ErrExportConflict
			}
			continue
		}
		plan, err := s.Store.planOf(ctx, tx, tenantID, item.TurnID)
		if err != nil {
			return nil, err
		}
		if len(plan) == 0 {
			if !exists || item.State != ItemActive {
				return nil, ErrExportConflict
			}
			terminal, err := s.terminalCheck(ctx, tx, id)
			if err != nil || !terminal {
				return nil, fmt.Errorf("records: in-scope turn not verifiably terminal: %w", errors.Join(ErrExportConflict, err))
			}
		}
		frozen, err := s.freezeExportPresence(ctx, tx, item, plan)
		if err != nil {
			return nil, err
		}
		if !exists {
			if len(frozen.missing) == 0 {
				return nil, ErrExportConflict
			}
			// Durable catalog identity outlives event-zero and the admission root.
			// Only plan-backed exact loss can take this path; do not create an event.
			authorityIDs = append(authorityIDs, evidence.TurnIdentity{TenantID: item.TenantID, ProjectID: item.ProjectID, MatterID: item.MatterID, CustodianID: item.CustodianID, TurnID: item.TurnID, RecordedAt: item.RecordedAt})
		}
		byTurn[item.TurnID] = frozen
		totalVersions += len(frozen.survivors) + len(frozen.missing) + len(frozen.shared)
		if totalVersions > maxExportSnapshotVersions {
			return nil, errInvalidExportSnapshot
		}
	}
	selection, err := SelectExportSnapshot(ExportSnapshotRequest{
		TenantID: tenantID, ProjectID: i.ProjectID, MatterID: i.MatterID,
		Custodians: i.CustodianIDs, WindowStart: i.WindowStart, WindowEnd: i.WindowEnd,
		CustodyActor: custodyActor, CustodyAt: custodyAt, Epoch: epoch,
		Holds: holds, Items: scopedItems, Identities: authorityIDs,
	})
	if err != nil {
		return nil, err
	}
	for n := range selection.Records {
		r := &selection.Records[n]
		if f, ok := byTurn[r.TurnID]; ok {
			r.Classification = f.classification
			r.Missing = f.missing
			r.RetainedShared = f.shared
			for _, ref := range f.survivors {
				r.Versions = append(r.Versions, ExportSnapshotVersion{Key: ref.Key, Version: ref.Version})
			}
		}
		sort.Strings(r.HeldBy)
	}
	encoded, err := json.Marshal(selection)
	if err != nil {
		return nil, err
	}
	if len(encoded) == 0 || len(encoded) > ExportSnapshotMaxBytes {
		return nil, errInvalidExportSnapshot
	}
	return encoded, nil
}
