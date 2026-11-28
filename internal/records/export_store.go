package records

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
	"sort"
	"time"
)

const (
	ExportRequested        = "requested"
	ExportApproved         = "approved"
	ExportGenerating       = "generating"
	ExportReady            = "ready"
	ExportFailed           = "failed"
	ExportCancelled        = "cancelled"
	ExportExpired          = "expired"
	ExportMaxBytes         = 32 << 20
	ExportSnapshotMaxBytes = 1 << 20
	ExportTTL              = 24 * time.Hour
	ExportTenantLimit      = 10
)

var ErrExportConflict = errors.New("records: conflicting export intent or state")

type ExportIntent struct {
	ProjectID    string    `json:"project_id"`
	MatterID     string    `json:"matter_id"`
	CustodianIDs []string  `json:"custodian_ids"`
	WindowStart  time.Time `json:"window_start"`
	WindowEnd    time.Time `json:"window_end"`
	Reason       string    `json:"reason"`
}
type NewExportRequest struct {
	RequestID string
	Intent    ExportIntent
}
type ExportSummary struct {
	ID, TenantID, ProjectID, MatterID, RequesterID                                            string
	CustodianIDs                                                                              []string
	WindowStart, WindowEnd                                                                    time.Time
	Reason, State, RequestDigest, SnapshotDigest, ManifestDigest, RequesterRole, ApproverRole string
	CustodyAudit                                                                              []ExportCustodyAudit
	Snapshot, Package                                                                         []byte
	RequesterAt, ApprovedAt, LeaseUntil, ExpiresAt, requesterGrantAt, approverGrantAt         *time.Time
	ApproverID, AttemptToken                                                                  *string
}
type SnapshotCallback func(context.Context, pgx.Tx, ExportIntent) ([]byte, error)
type RevalidateCallback func(context.Context, pgx.Tx, string, ExportIntent, []byte) error
type exportIntentWire struct {
	ProjectID              string   `json:"project_id"`
	MatterID               string   `json:"matter_id"`
	CustodianIDs           []string `json:"custodian_ids"`
	WindowStart, WindowEnd string
	Reason                 string `json:"reason"`
}

func canonicalExportIntent(i ExportIntent) (ExportIntent, []byte, error) {
	var ok bool
	if i.ProjectID, ok = store.CanonicalID(i.ProjectID); !ok {
		return i, nil, ErrNotFound
	}
	if i.MatterID, ok = store.CanonicalID(i.MatterID); !ok {
		return i, nil, ErrNotFound
	}
	if i.Reason == "" || len(i.Reason) > 2000 || i.WindowStart.IsZero() || i.WindowEnd.IsZero() || !i.WindowEnd.After(i.WindowStart) {
		return i, nil, ErrNotFound
	}
	i.WindowStart = i.WindowStart.UTC().Truncate(time.Microsecond)
	i.WindowEnd = i.WindowEnd.UTC().Truncate(time.Microsecond)
	for n := range i.CustodianIDs {
		if i.CustodianIDs[n], ok = store.CanonicalID(i.CustodianIDs[n]); !ok {
			return i, nil, ErrNotFound
		}
	}
	sort.Strings(i.CustodianIDs)
	for n := 1; n < len(i.CustodianIDs); n++ {
		if i.CustodianIDs[n] == i.CustodianIDs[n-1] {
			return i, nil, ErrNotFound
		}
	}
	w := exportIntentWire{i.ProjectID, i.MatterID, i.CustodianIDs, i.WindowStart.Format(time.RFC3339Nano), i.WindowEnd.Format(time.RFC3339Nano), i.Reason}
	b, e := json.Marshal(w)
	return i, b, e
}
func exportDigest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func exportIntentFrom(e ExportSummary) ExportIntent {
	return ExportIntent{e.ProjectID, e.MatterID, e.CustodianIDs, e.WindowStart, e.WindowEnd, e.Reason}
}

func checkExportParties(ctx context.Context, tx pgx.Tx, e ExportSummary, requireApprover bool) error {
	var requesterActive bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_roles r JOIN users u ON u.id=r.user_id AND u.tenant_id=r.tenant_id WHERE r.user_id=$1 AND r.tenant_id=$2 AND r.role='records_officer' AND r.granted_at=$3 AND u.disabled_at IS NULL)`, e.RequesterID, e.TenantID, e.requesterGrantAt).Scan(&requesterActive); err != nil {
		return err
	}
	if !requesterActive {
		return ErrForbidden
	}
	if !requireApprover {
		return nil
	}
	if e.ApproverID == nil || e.ApproverRole != store.RoleExportReviewer {
		return ErrForbidden
	}
	var approverActive bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_roles r JOIN users u ON u.id=r.user_id AND u.tenant_id=r.tenant_id WHERE r.user_id=$1 AND r.tenant_id=$2 AND r.role='export_reviewer' AND r.granted_at=$3 AND u.disabled_at IS NULL)`, *e.ApproverID, e.TenantID, e.approverGrantAt).Scan(&approverActive); err != nil {
		return err
	}
	if !approverActive {
		return ErrForbidden
	}
	return nil
}
func loadExport(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenant, id string) (ExportSummary, error) {
	var e ExportSummary
	var raw []byte
	err := q.QueryRow(ctx, `SELECT id::text,tenant_id::text,project_id::text,matter_id::text,requester_id::text,custodian_ids,window_start,window_end,reason,state,request_digest,snapshot_digest,COALESCE(manifest_digest,''),request_bytes,snapshot_bytes,requester_role,requester_at,approver_id::text,COALESCE(approver_role,''),approved_at,attempt_token::text,lease_until,expires_at,requester_grant_at,approver_grant_at FROM scoped_exports WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&e.ID, &e.TenantID, &e.ProjectID, &e.MatterID, &e.RequesterID, &e.CustodianIDs, &e.WindowStart, &e.WindowEnd, &e.Reason, &e.State, &e.RequestDigest, &e.SnapshotDigest, &e.ManifestDigest, &raw, &e.Snapshot, &e.RequesterRole, &e.RequesterAt, &e.ApproverID, &e.ApproverRole, &e.ApprovedAt, &e.AttemptToken, &e.LeaseUntil, &e.ExpiresAt, &e.requesterGrantAt, &e.approverGrantAt)
	if err != nil {
		return e, err
	}
	if exportDigest(raw) != e.RequestDigest || exportDigest(e.Snapshot) != e.SnapshotDigest {
		return e, ErrExportConflict
	}
	return e, nil
}

// RequestExport derives tenant/requester from Principal and snapshots only a new intent.
func (s *Store) RequestExport(ctx context.Context, p store.Principal, r NewExportRequest, snapshot SnapshotCallback, revalidate RevalidateCallback) (ExportSummary, error) {
	p, ok := canonP(p)
	if !ok {
		return ExportSummary{}, ErrForbidden
	}
	requestKey := r.RequestID
	if len(requestKey) == 0 || len(requestKey) > 128 || snapshot == nil || revalidate == nil {
		return ExportSummary{}, ErrNotFound
	}
	i, raw, err := canonicalExportIntent(r.Intent)
	if err != nil {
		return ExportSummary{}, err
	}
	var out ExportSummary
	err = s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		var old []byte
		var id string
		e := tx.QueryRow(ctx, `SELECT id::text,request_bytes FROM scoped_exports WHERE tenant_id=$1 AND requester_id=$2 AND request_key=$3 FOR UPDATE`, p.TenantID, p.UserID, requestKey).Scan(&id, &old)
		if e == nil {
			if string(old) != string(raw) {
				return ErrExportConflict
			}
			out, e = loadExport(ctx, tx, p.TenantID, id)
			if e != nil {
				return e
			}
			if err := checkExportParties(ctx, tx, out, false); err != nil {
				return err
			}
			return revalidate(ctx, tx, out.ProjectID, i, out.Snapshot)
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		// Project, matter and custodian authority is evaluated by the injected
		// retained-evidence callback, not mutable workspace catalog prechecks.
		var n int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM scoped_exports WHERE tenant_id=$1 AND state IN ('requested','approved','generating','ready')`, p.TenantID).Scan(&n); e != nil {
			return e
		}
		if n >= ExportTenantLimit {
			return ErrExportConflict
		}
		snap, e := snapshot(ctx, tx, i)
		if e != nil {
			return e
		}
		if len(snap) > ExportSnapshotMaxBytes {
			return ErrNotFound
		}
		if e = revalidate(ctx, tx, i.ProjectID, i, snap); e != nil {
			return e
		}
		rd, sd := exportDigest(raw), exportDigest(snap)
		if e = tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&id); e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO scoped_exports(id,tenant_id,request_key,project_id,matter_id,requester_id,request_bytes,request_digest,custodian_ids,window_start,window_end,reason,snapshot_bytes,snapshot_digest,requester_role,requester_grant_at,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'records_officer',(SELECT granted_at FROM tenant_roles WHERE tenant_id=$2 AND user_id=$6 AND role='records_officer'),'requested')`, id, p.TenantID, requestKey, i.ProjectID, i.MatterID, p.UserID, raw, rd, i.CustodianIDs, i.WindowStart, i.WindowEnd, i.Reason, snap, sd)
		if e != nil {
			return e
		}
		if e = audit(ctx, tx, p.TenantID, &p.UserID, "export.request", map[string]any{"export_id": id, "request_digest": rd, "snapshot_digest": sd}); e != nil {
			return e
		}
		out, e = loadExport(ctx, tx, p.TenantID, id)
		return e
	})
	return out, err
}
func exportTenantMatches(p store.Principal, tenant string) bool {
	t, ok := store.CanonicalID(tenant)
	return ok && t == p.TenantID
}

func exportLive(e ExportSummary) bool { return e.ExpiresAt != nil && time.Now().Before(*e.ExpiresAt) }

func (s *Store) ApproveExport(ctx context.Context, p store.Principal, tenant, id, expected string, check RevalidateCallback) (ExportSummary, error) {
	p, ok := canonP(p)
	if !ok {
		return ExportSummary{}, ErrForbidden
	}
	if !exportTenantMatches(p, tenant) {
		return ExportSummary{}, ErrNotFound
	}
	var out ExportSummary
	err := s.beginTx(ctx, p, store.RoleExportReviewer, func(tx pgx.Tx) error {
		e, err := loadExport(ctx, tx, tenant, id)
		if err != nil {
			return ErrNotFound
		}
		if !exportLive(e) || check == nil {
			return ErrExportConflict
		}
		if e.State == ExportApproved && e.ApproverID != nil && *e.ApproverID == p.UserID && e.SnapshotDigest == expected {
			if err = checkExportParties(ctx, tx, e, true); err != nil {
				return err
			}
			if err = check(ctx, tx, e.ProjectID, exportIntentFrom(e), e.Snapshot); err != nil {
				return err
			}
			out = e
			return nil
		}
		if e.State != ExportRequested || e.RequesterID == p.UserID || e.SnapshotDigest != expected || check == nil {
			return ErrExportConflict
		}
		if err = checkExportParties(ctx, tx, e, false); err != nil {
			return err
		}
		if err = check(ctx, tx, e.ProjectID, exportIntentFrom(e), e.Snapshot); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE scoped_exports SET approver_id=$3,approver_role='export_reviewer',approved_at=clock_timestamp(),approver_grant_at=(SELECT granted_at FROM tenant_roles WHERE tenant_id=$1 AND user_id=$3 AND role='export_reviewer'),state='approved' WHERE tenant_id=$1 AND id=$2 AND state='requested'`, tenant, id, p.UserID)
		if err != nil {
			return err
		}
		if err = audit(ctx, tx, tenant, &p.UserID, "export.approve", map[string]any{"export_id": id, "snapshot_digest": e.SnapshotDigest, "request_digest": e.RequestDigest}); err != nil {
			return err
		}
		out, err = loadExport(ctx, tx, tenant, id)
		return err
	})
	return out, err
}

func (s *Store) BeginExport(ctx context.Context, p store.Principal, tenant, id string, lease time.Duration, check RevalidateCallback) (ExportSummary, string, error) {
	p, ok := canonP(p)
	if !ok {
		return ExportSummary{}, "", ErrForbidden
	}
	if !exportTenantMatches(p, tenant) {
		return ExportSummary{}, "", ErrNotFound
	}
	if lease <= 0 || lease > 15*time.Minute {
		return ExportSummary{}, "", ErrNotFound
	}
	var out ExportSummary
	var token string
	err := s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		e, err := loadExport(ctx, tx, tenant, id)
		if err != nil {
			return ErrNotFound
		}
		if e.RequesterID != p.UserID || check == nil || !exportLive(e) {
			return ErrForbidden
		}
		if e.State != ExportApproved && !(e.State == ExportGenerating && e.LeaseUntil != nil && time.Now().After(*e.LeaseUntil)) {
			return ErrExportConflict
		}
		if err = checkExportParties(ctx, tx, e, true); err != nil {
			return err
		}
		if err = check(ctx, tx, e.ProjectID, exportIntentFrom(e), e.Snapshot); err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&token); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE scoped_exports SET state='generating',attempt_token=$3,lease_until=now()+$4::interval WHERE tenant_id=$1 AND id=$2`, tenant, id, token, lease.String())
		if err != nil {
			return err
		}
		if err = audit(ctx, tx, tenant, &p.UserID, "export.generate", map[string]any{"export_id": id}); err != nil {
			return err
		}
		out, err = loadExport(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		out.CustodyAudit, err = loadExportCustodyAudit(ctx, tx, out)
		return err
	})
	return out, token, err
}
func (s *Store) PublishExport(ctx context.Context, p store.Principal, tenant, id, token, snapshotDigest, manifestDigest string, b []byte, verify func([]byte, string, string) error, check RevalidateCallback) (ExportSummary, error) {
	p, ok := canonP(p)
	if !ok {
		return ExportSummary{}, ErrForbidden
	}
	if !exportTenantMatches(p, tenant) {
		return ExportSummary{}, ErrNotFound
	}
	if len(b) == 0 || len(b) > ExportMaxBytes || verify == nil || check == nil || len(manifestDigest) != 64 || len(snapshotDigest) != 64 {
		return ExportSummary{}, ErrNotFound
	}
	// Package verification may perform substantial local I/O; never run it while holding DB locks.
	if err := verify(b, snapshotDigest, manifestDigest); err != nil {
		return ExportSummary{}, err
	}
	var out ExportSummary
	err := s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		e, err := loadExport(ctx, tx, tenant, id)
		if err != nil {
			return ErrNotFound
		}
		if !exportLive(e) || e.RequesterID != p.UserID || e.SnapshotDigest != snapshotDigest || e.State != ExportGenerating || e.AttemptToken == nil || *e.AttemptToken != token || e.LeaseUntil == nil || !time.Now().Before(*e.LeaseUntil) {
			return ErrExportConflict
		}
		if err = checkExportParties(ctx, tx, e, true); err != nil {
			return err
		}
		if err = check(ctx, tx, e.ProjectID, exportIntentFrom(e), e.Snapshot); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE scoped_exports SET state='ready',package_bytes=$3,manifest_digest=$4,attempt_token=NULL,lease_until=NULL WHERE tenant_id=$1 AND id=$2 AND state='generating' AND attempt_token=$5 AND expires_at>clock_timestamp() AND lease_until>clock_timestamp()`, tenant, id, b, manifestDigest, token)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrExportConflict
		}
		if err = audit(ctx, tx, tenant, &p.UserID, "export.ready", map[string]any{"export_id": id, "manifest_digest": manifestDigest, "snapshot_digest": snapshotDigest}); err != nil {
			return err
		}
		out, err = loadExport(ctx, tx, tenant, id)
		return err
	})
	return out, err
}
func (s *Store) GetApprovedExport(ctx context.Context, p store.Principal, tenant, id string, check RevalidateCallback) ([]byte, error) {
	b, _, err := s.GetApprovedExportBundle(ctx, p, tenant, id, check)
	return b, err
}

func (s *Store) GetApprovedExportBundle(ctx context.Context, p store.Principal, tenant, id string, check RevalidateCallback) ([]byte, string, error) {
	p, ok := canonP(p)
	if !ok {
		return nil, "", ErrForbidden
	}
	if !exportTenantMatches(p, tenant) {
		return nil, "", ErrNotFound
	}
	var b []byte
	var digest string
	err := s.beginTx(ctx, p, store.RoleExportReviewer, func(tx pgx.Tx) error {
		e, err := loadExport(ctx, tx, tenant, id)
		if err != nil {
			return ErrNotFound
		}
		if e.State != ExportReady || e.ApproverID == nil || *e.ApproverID != p.UserID || e.ExpiresAt == nil || !time.Now().Before(*e.ExpiresAt) || check == nil {
			return ErrNotFound
		}
		if err = checkExportParties(ctx, tx, e, true); err != nil {
			return err
		}
		if err = check(ctx, tx, e.ProjectID, exportIntentFrom(e), e.Snapshot); err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, `SELECT package_bytes FROM scoped_exports WHERE tenant_id=$1 AND id=$2 AND state='ready' AND expires_at>clock_timestamp()`, tenant, id).Scan(&b); err != nil {
			return ErrNotFound
		}
		if len(b) == 0 || len(b) > ExportMaxBytes || len(e.ManifestDigest) != 64 {
			return ErrNotFound
		}
		digest = e.ManifestDigest
		if err = audit(ctx, tx, tenant, &p.UserID, "export.retrieve", map[string]any{"export_id": id, "manifest_digest": e.ManifestDigest}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	return b, digest, nil
}
func (s *Store) CancelExport(ctx context.Context, p store.Principal, tenant, id string) error {
	p, ok := canonP(p)
	if !ok {
		return ErrForbidden
	}
	if !exportTenantMatches(p, tenant) {
		return ErrNotFound
	}
	return s.beginTx(ctx, p, store.RoleRecordsOfficer, func(tx pgx.Tx) error {
		e, err := loadExport(ctx, tx, tenant, id)
		if err != nil {
			return ErrNotFound
		}
		if e.RequesterID != p.UserID || e.State == ExportCancelled || e.State == ExportExpired {
			return ErrExportConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE scoped_exports SET state='cancelled',package_bytes=NULL,attempt_token=NULL,lease_until=NULL,expires_at=NULL WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
			return err
		}
		return audit(ctx, tx, tenant, &p.UserID, "export.cancel", map[string]any{"export_id": id})
	})
}

// CleanupExports expires packages and returns abandoned generation attempts to approved.
func (s *Store) CleanupExports(ctx context.Context, tenant string) (int64, error) {
	tenant, ok := store.CanonicalID(tenant)
	if !ok {
		return 0, ErrNotFound
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT true FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant).Scan(&locked); err != nil {
		return 0, ErrNotFound
	}
	tag, err := tx.Exec(ctx, `UPDATE scoped_exports SET state=CASE WHEN expires_at<=now() THEN 'expired' ELSE 'approved' END, package_bytes=NULL, attempt_token=NULL, lease_until=NULL, expires_at=CASE WHEN expires_at<=now() THEN NULL ELSE expires_at END WHERE tenant_id=$1 AND state IN ('requested','approved','generating','ready') AND (expires_at<=now() OR (state='generating' AND lease_until<=now()))`, tenant)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() > 0 {
		if err = audit(ctx, tx, tenant, nil, "export.cleanup", map[string]any{"changed": tag.RowsAffected()}); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
