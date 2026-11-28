package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/exportbundle"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// RetainedExports has no workspace content or general evidence read endpoint.
// The retained reader is exercised only after the approved attempt is acquired.
type RetainedExports struct {
	Records *records.Service
	Backend *evidence.RetentionBackend
}

func (x *RetainedExports) AuditDenial(ctx context.Context, p store.Principal, operation, id string, status int) error {
	return x.Records.Store.AuditExportDenial(ctx, p, operation, id, status)
}

func (x *RetainedExports) Request(ctx context.Context, p store.Principal, r records.NewExportRequest) (records.ExportSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	snapshot, check := x.Records.ExportSnapshotCallbacks(p.TenantID, p.UserID)
	return x.Records.Store.RequestExport(ctx, p, r, snapshot, check)
}
func (x *RetainedExports) Approve(ctx context.Context, p store.Principal, id, digest string) (records.ExportSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, check := x.Records.ExportSnapshotCallbacks(p.TenantID, "")
	return x.Records.Store.ApproveExport(ctx, p, p.TenantID, id, digest, check)
}
func (x *RetainedExports) Cancel(ctx context.Context, p store.Principal, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return x.Records.Store.CancelExport(ctx, p, p.TenantID, id)
}
func (x *RetainedExports) Generate(ctx context.Context, p store.Principal, id string) (_ records.ExportSummary, returned error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	_, check := x.Records.ExportSnapshotCallbacks(p.TenantID, p.UserID)
	s, attempt, err := x.Records.Store.BeginExport(ctx, p, p.TenantID, id, 2*time.Minute, check)
	if err != nil {
		return records.ExportSummary{}, err
	}
	stage := "readback"
	defer func() {
		if returned == nil {
			return
		}
		recoverCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		// If authorization or the database has become unavailable, the
		// durable lease is the recovery layer; failure cannot publish.
		_ = x.Records.Store.RecordExportAttemptFailure(recoverCtx, p, id, attempt, stage)
	}()
	files, digest, err := assembleRetainedDirectory(ctx, s, x.Backend.LoadExportReadback, x.Backend.LoadPartialExportReadback)
	if err != nil {
		return records.ExportSummary{}, err
	}
	packageBytes, err := json.Marshal(files)
	if err != nil || len(packageBytes) > records.ExportMaxBytes {
		return records.ExportSummary{}, errors.New("export: package limit exceeded")
	}
	stage = "publish"
	verify := func(b []byte, snapshot, manifest string) error {
		if snapshot != s.SnapshotDigest || manifest != strings.TrimPrefix(digest, "sha256:") || !bytes.Equal(b, packageBytes) {
			stage = "verification"
			return records.ErrExportConflict
		}
		_, err := exportbundle.VerifyMembers(files, evidence.RetentionProfile, digest)
		if err != nil {
			stage = "verification"
		}
		return err
	}
	return x.Records.Store.PublishExport(ctx, p, p.TenantID, id, attempt, s.SnapshotDigest, strings.TrimPrefix(digest, "sha256:"), packageBytes, verify, check)
}
func (x *RetainedExports) Retrieve(ctx context.Context, p store.Principal, id string) (ExportDelivery, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, check := x.Records.ExportSnapshotCallbacks(p.TenantID, "")
	b, digest, err := x.Records.Store.GetApprovedExportBundle(ctx, p, p.TenantID, id, check)
	if err != nil {
		return ExportDelivery{}, err
	}
	return ExportDelivery{b, "sha256:" + digest}, nil
}

type exportReadback func(context.Context, string, string, string, []evidence.VersionRef) (evidence.ExportReadback, error)

type partialExportReadback func(context.Context, string, string, string, string, []evidence.VersionRef, []evidence.VersionRef) (evidence.PartialExportReadback, error)

func assembleRetainedDirectory(ctx context.Context, s records.ExportSummary, read exportReadback, readPartial partialExportReadback) (map[string][]byte, string, error) {
	var frozen records.ExportSnapshot
	err := json.Unmarshal(s.Snapshot, &frozen)
	snapshotID := evidence.SHA256(s.Snapshot)
	if err != nil || strings.TrimPrefix(snapshotID, "sha256:") != s.SnapshotDigest || frozen.TenantID != s.TenantID || frozen.ProjectID != s.ProjectID || frozen.MatterID != s.MatterID || frozen.CustodyActor != s.RequesterID || s.ApproverID == nil || s.RequesterAt == nil || s.ApprovedAt == nil || *s.ApproverID == s.RequesterID || len(frozen.Records) == 0 {
		return nil, "", records.ErrExportConflict
	}
	files := map[string][]byte{}
	add := func(path string, raw []byte) error {
		if prev, ok := files[path]; ok {
			if !bytes.Equal(prev, raw) {
				return records.ErrExportConflict
			}
			return nil
		}
		files[path] = raw
		return nil
	}
	total := 0
	turns := make([]any, 0, len(frozen.Records))
	gaps := make([]any, 0)
	objSizes := map[string]int{}
	for _, r := range frozen.Records {
		refs := make([]evidence.VersionRef, 0, len(r.Versions))
		for _, v := range r.Versions {
			refs = append(refs, evidence.VersionRef{Key: v.Key, Version: v.Version})
		}
		var missingRef []evidence.VersionRef
		missing := make([]any, 0, len(r.Missing))
		for _, loss := range r.Missing {
			missingRef = append(missingRef, evidence.VersionRef{Key: loss.Key, Version: loss.Version})
			var epoch any
			if loss.PlanEpoch != nil {
				epoch = *loss.PlanEpoch
			}
			missing = append(missing, map[string]any{"key": loss.Key, "version": loss.Version, "disposition": loss.Disposition, "plan_epoch": epoch})
		}
		partial := r.Classification == "partial_loss"
		switch r.Classification {
		case "complete":
			if len(refs) == 0 || len(missing) != 0 || len(r.HeldBy) == 0 {
				return nil, "", records.ErrExportConflict
			}
		case "partial_loss":
			if len(refs) == 0 || len(missing) == 0 || len(r.HeldBy) == 0 {
				return nil, "", records.ErrExportConflict
			}
		case "complete_loss", "disposed":
			if len(refs) != 0 || len(missing) == 0 || len(r.HeldBy) == 0 {
				return nil, "", records.ErrExportConflict
			}
		case "uncovered":
			if len(refs) != 0 || len(missing) != 0 || len(r.HeldBy) != 0 {
				return nil, "", records.ErrExportConflict
			}
		default:
			return nil, "", records.ErrExportConflict
		}
		if r.Classification != "complete" {
			gaps = append(gaps, map[string]any{"kind": r.Classification, "turn_id": r.TurnID, "custodian_id": r.CustodianID, "recorded_at": r.RecordedAt.UTC().Format(time.RFC3339Nano), "hold_ids": exportStrings(r.HeldBy), "missing_versions": missing})
			if !partial {
				continue
			}
		}
		var rb evidence.ExportReadback
		var end int64
		var sources map[evidence.VersionRef]string
		holes := make([]any, 0)
		if partial {
			result, err := readPartial(ctx, s.TenantID, s.ProjectID, s.MatterID, r.TurnID, refs, missingRef)
			if err != nil {
				return nil, "", err
			}
			rb = result.ExportReadback
			end = result.EndSequence
			sources = result.Sources
			for _, seq := range result.MissingSequences {
				holes = append(holes, seq)
			}
		} else {
			var err error
			rb, err = read(ctx, s.TenantID, s.ProjectID, r.TurnID, refs)
			if err != nil {
				return nil, "", err
			}
			end = int64(len(rb.Events) - 1)
		}
		if (!partial && len(rb.Events) == 0) || len(rb.Events) != len(rb.CanonicalEvents) {
			return nil, "", records.ErrExportConflict
		}
		var path, logDigest, head any
		if len(rb.Events) > 0 {
			name := "events/" + r.TurnID + ".jsonl"
			for _, ev := range rb.CanonicalEvents {
				total += len(ev) + 1
			}
			if total > 20<<20 {
				return nil, "", errors.New("export: payload limit exceeded")
			}
			log := append(bytes.Join(rb.CanonicalEvents, []byte{'\n'}), '\n')
			if err := add(name, log); err != nil {
				return nil, "", err
			}
			path, logDigest, head = name, evidence.SHA256(log), rb.Events[len(rb.Events)-1]["event_hash"]
		}
		versions := make([]any, 0, len(rb.Versions))
		for _, v := range rb.Versions {
			source := "signed"
			if partial {
				source = sources[evidence.VersionRef{Key: v.Key, Version: v.Version}]
			}
			versions = append(versions, map[string]any{"key": v.Key, "version": v.Version, "kind": v.Kind, "sha256": v.SHA256, "bytes": int64(v.Bytes), "source": source})
		}
		turns = append(turns, map[string]any{"turn_id": r.TurnID, "custodian_id": r.CustodianID, "recorded_at": r.RecordedAt.UTC().Format(time.RFC3339Nano), "hold_ids": exportStrings(r.HeldBy), "event_path": path, "event_sha256": logDigest, "event_count": len(rb.Events), "end_sequence": end, "head_hash": head, "retained_versions": versions, "partial": partial, "missing_sequences": holes})
		for digest, blob := range rb.Objects {
			if _, seen := objSizes[digest]; !seen {
				total += len(blob)
			}
			if total > 20<<20 || evidence.SHA256(blob) != digest {
				return nil, "", errors.New("export: invalid or oversized evidence objects")
			}
			if err := add("objects/"+strings.TrimPrefix(digest, "sha256:"), blob); err != nil {
				return nil, "", err
			}
			objSizes[digest] = len(blob)
		}
	}
	ds := make([]string, 0, len(objSizes))
	for dig := range objSizes {
		ds = append(ds, dig)
	}
	sort.Strings(ds)
	objs := make([]any, 0, len(ds))
	for _, dig := range ds {
		objs = append(objs, map[string]any{"sha256": dig, "bytes": objSizes[dig]})
	}
	custodians := make([]any, 0, len(s.CustodianIDs))
	for _, id := range s.CustodianIDs {
		custodians = append(custodians, id)
	}
	utc := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	raw, err := evidence.Canonical(map[string]any{
		"schema_version": exportbundle.SchemaVersion, "profile": evidence.RetentionProfile, "export_id": s.ID,
		"snapshot": map[string]any{"id": snapshotID, "revision": strconv.FormatInt(frozen.Epoch, 10), "captured_at": utc(frozen.CustodyAt), "hold_ids": exportStrings(frozen.HoldIDs)},
		"scope":    map[string]any{"tenant_id": s.TenantID, "project_id": s.ProjectID, "matter_id": s.MatterID, "custodian_ids": custodians, "window_start": utc(s.WindowStart), "window_end": utc(s.WindowEnd)},
		"custody":  map[string]any{"requester_id": s.RequesterID, "approver_id": *s.ApproverID, "approved_at": utc(*s.ApprovedAt), "requested_at": utc(*s.RequesterAt), "snapshot_id": snapshotID},
		"turns":    turns, "objects": objs, "gaps": gaps,
	})
	if err != nil {
		return nil, "", err
	}
	files["manifest.json"] = raw
	return files, evidence.SHA256(raw), nil
}

func exportStrings(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
