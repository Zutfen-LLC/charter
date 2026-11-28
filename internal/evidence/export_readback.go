package evidence

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

// ExportVersion describes a verified retained version. It is not a capability
// and contains no transport endpoint or credential.
type ExportVersion struct {
	Key, Version, SHA256, Kind string
	Bytes                      uint64
}

// ExportReadback is an internal projection of a complete retained turn.
type ExportReadback struct {
	Events          []Event
	CanonicalEvents [][]byte
	Objects         map[string][]byte
	Versions        []ExportVersion
}

const maxExportReadback = 24 << 20
const maxExportVersionRefs = 4096

func (b *RetentionBackend) readExactExportVersion(ctx context.Context, r retainedObjectReceipt, frozen map[VersionRef]bool) ([]byte, error) {
	if r.Version == "" || r.Version == "null" || !frozen[VersionRef{r.Key, r.Version}] || r.Bucket != b.bucket || r.Deployment != b.deployment || r.Length > maxExportReadback {
		return nil, ErrConflict
	}
	v, err := b.store.Read(ctx, r.Key, r.Version)
	if err != nil {
		return nil, err
	}
	// The caller separately verifies hold authority. An expired COMPLIANCE
	// timestamp does not invalidate the original receipt or permit fallback
	// to a different version; shortening the receipt's deadline does.
	until, timeErr := time.Parse(time.RFC3339, r.RetainUntil)
	if v.ID != r.Version || v.Mode != "COMPLIANCE" || !validRetainedDigest(r.SHA256) || uint64(len(v.Data)) != r.Length || SHA256(v.Data) != r.SHA256 || timeErr != nil || v.Until.Before(until) {
		return nil, ErrNotDurable
	}
	return v.Data, nil
}

// LoadExportReadback reads only the exact immutable versions supplied by the
// caller's already-authorized snapshot. It never lists or follows latest keys.
// Complete readback requires full set reconciliation and a terminal valid
// retained event chain. It does not establish hold authority by itself.
func (b *RetentionBackend) LoadExportReadback(ctx context.Context, tenant, project, turn string, refs []VersionRef) (ExportReadback, error) {
	var out ExportReadback
	if !idRe.MatchString(tenant) || !idRe.MatchString(project) || !idRe.MatchString(turn) || len(refs) < 2 || len(refs) > maxExportVersionRefs {
		return out, ErrConflict
	}
	root := b.prefix + tenant + "/"
	admissions := root + "admissions/"
	slots := root + "events/" + turn + "/"
	data := root + "data/events/" + turn + "/"
	objects := root + "data/objects/"
	frozen := make(map[VersionRef]bool, len(refs))
	markers := map[uint64]VersionRef{}
	for _, r := range refs {
		if r.Version == "" || r.Version == "null" || len(r.Version) > 1024 || frozen[r] {
			return out, ErrConflict
		}
		frozen[r] = true
		var seq uint64
		switch {
		case strings.HasPrefix(r.Key, admissions) && validRetainedDigest(strings.TrimPrefix(r.Key, admissions)):
		case strings.HasPrefix(r.Key, slots):
			s := strings.TrimPrefix(r.Key, slots)
			n, err := strconv.ParseUint(s, 10, 53)
			if err != nil || n == 0 || n >= maxExportVersionRefs || strconv.FormatUint(n, 10) != s {
				return out, ErrConflict
			}
			seq = n
		case strings.HasPrefix(r.Key, data) && validRetainedDigest(strings.TrimPrefix(r.Key, data)):
			continue
		case strings.HasPrefix(r.Key, objects) && validRetainedDigest(strings.TrimPrefix(r.Key, objects)):
			continue
		default:
			return out, ErrConflict
		}
		if _, dup := markers[seq]; dup {
			return out, ErrConflict
		}
		markers[seq] = r
	}
	if len(markers) == 0 {
		return out, ErrConflict
	}
	out.Objects = map[string][]byte{}
	seen := make(map[VersionRef]bool, len(refs))
	var total uint64
	var prev retainedEntry
	for seq := uint64(0); seq < uint64(len(markers)); seq++ {
		r, ok := markers[seq]
		if !ok {
			return ExportReadback{}, ErrConflict
		}
		m, err := b.slotRelaxed(ctx, r.Key, []s3transport.Ref{{Key: r.Key, VersionID: r.Version}})
		if err != nil {
			return ExportReadback{}, err
		}
		c := m.commit
		if c.Tenant != tenant || c.Project != project || c.Turn != turn || c.Seq != seq || (seq > 0 && (c.Predecessor == nil || !compatibleMarker(*c.Predecessor, prev.marker))) {
			return ExportReadback{}, ErrConflict
		}
		out.Versions = append(out.Versions, ExportVersion{r.Key, r.Version, m.marker.SHA256, "marker", m.marker.Length})
		seen[r] = true
		var raw []byte
		err = b.eventDataWithReader(ctx, &m, func(ctx context.Context, receipt retainedObjectReceipt) ([]byte, error) {
			vr := VersionRef{receipt.Key, receipt.Version}
			if receipt.Length > maxExportReadback || total > maxExportReadback-receipt.Length {
				return nil, ErrNotDurable
			}
			blob, readErr := b.readExactExportVersion(ctx, receipt, frozen)
			if readErr != nil {
				return nil, readErr
			}
			kind := "object"
			if receipt == c.Event {
				kind, raw = "event", blob
			}
			total += receipt.Length
			if !seen[vr] {
				out.Versions = append(out.Versions, ExportVersion{vr.Key, vr.Version, receipt.SHA256, kind, receipt.Length})
				seen[vr] = true

			}
			return blob, nil
		})
		if err != nil {
			return ExportReadback{}, err
		}
		if str(m.event, "type") == "evidence_ack" {
			receipt, valid := ackRetainedReceipt(payload(m.event), prev.event)
			if !valid || receipt != prev.commit.Event {
				return ExportReadback{}, ErrConflict
			}
		}
		for digest, blob := range m.objects {
			out.Objects[digest] = blob
		}
		out.Events = append(out.Events, m.event)
		out.CanonicalEvents = append(out.CanonicalEvents, raw)
		prev = m
	}
	if len(seen) != len(frozen) || len(VerifyRetentionFull(out.Events, out.Objects)) > 0 {
		return ExportReadback{}, fmt.Errorf("%w: incomplete or invalid retained export readback", ErrConflict)
	}
	return out, nil
}
