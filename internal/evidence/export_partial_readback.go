package evidence

import (
	"bytes"
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
)

// PartialExportReadback reports exactly retained survivors, with no synthetic
// replacement for missing events. Sources marks signatures that were checked
// against the exporter trust key; the manifest digest authenticates this
// attribution, but does not distribute a verifier trust key.
type PartialExportReadback struct {
	ExportReadback
	EndSequence      int64
	MissingSequences []int64
	Sources          map[VersionRef]string
}

// LoadPartialExportReadback uses the already authorized exact plan union. It
// never enumerates storage, uses a latest key, or treats a read failure as loss.
func (b *RetentionBackend) LoadPartialExportReadback(ctx context.Context, tenant, project, matter, turn string, survivors, missing []VersionRef) (PartialExportReadback, error) {
	var zero PartialExportReadback
	if !idRe.MatchString(tenant) || !idRe.MatchString(project) || !idRe.MatchString(matter) || !idRe.MatchString(turn) || len(survivors) == 0 || len(missing) == 0 || len(survivors)+len(missing) > maxExportVersionRefs {
		return zero, ErrConflict
	}
	root := b.prefix + tenant + "/"
	ad, slots, events, objects := root+"admissions/", root+"events/"+turn+"/", root+"data/events/"+turn+"/", root+"data/objects/"
	plan := make(map[VersionRef]bool, len(survivors)+len(missing)) // true = frozen survivor
	markers := map[int]VersionRef{}
	seqByMarker := map[VersionRef]int{}
	eventCensus := map[string]bool{}
	metadata := map[VersionRef][2]string{}
	for index, list := range [][]VersionRef{survivors, missing} {
		for _, r := range list {
			if _, dup := plan[r]; dup || r.Version == "" || r.Version == "null" || len(r.Version) > 1024 {
				return zero, ErrConflict
			}
			plan[r] = index == 0
			seq := 0
			switch {
			case strings.HasPrefix(r.Key, ad) && validRetainedDigest(strings.TrimPrefix(r.Key, ad)):
			case strings.HasPrefix(r.Key, slots):
				tail := strings.TrimPrefix(r.Key, slots)
				n, err := strconv.Atoi(tail)
				if err != nil || n <= 0 || n >= maxExportVersionRefs || strconv.Itoa(n) != tail {
					return zero, ErrConflict
				}
				seq = n
			case strings.HasPrefix(r.Key, events) && validRetainedDigest(strings.TrimPrefix(r.Key, events)):
				h := strings.TrimPrefix(r.Key, events)
				if eventCensus[h] {
					return zero, ErrConflict
				}
				eventCensus[h] = true
				metadata[r] = [2]string{"event", h}
				continue
			case strings.HasPrefix(r.Key, objects) && validRetainedDigest(strings.TrimPrefix(r.Key, objects)):
				metadata[r] = [2]string{"object", strings.TrimPrefix(r.Key, objects)}
				continue
			default:
				return zero, ErrConflict
			}
			if _, dup := markers[seq]; dup {
				return zero, ErrConflict
			}
			markers[seq], seqByMarker[r] = r, seq
		}
	}
	if len(markers) == 0 || len(eventCensus) != len(markers) {
		return zero, ErrConflict
	}
	for seq := 0; seq < len(markers); seq++ {
		if _, ok := markers[seq]; !ok {
			return zero, ErrConflict
		}
	}
	out := PartialExportReadback{EndSequence: int64(len(markers) - 1), Sources: map[VersionRef]string{}}
	out.Objects = map[string][]byte{}
	loaded := map[VersionRef]s3transport.Version{}
	receipts := map[int]retainedEntry{}
	logs := map[int]Event{}
	raws := map[int][]byte{}
	readEventRef := map[int]VersionRef{}
	var total int
	for _, r := range survivors {
		if seq, marker := seqByMarker[r]; marker {
			m, err := b.slotRelaxed(ctx, r.Key, []s3transport.Ref{{Key: r.Key, VersionID: r.Version}})
			if err != nil {
				return zero, err
			}
			c := m.commit
			if c.Tenant != tenant || c.Project != project || c.Turn != turn || int(c.Seq) != seq || m.marker.Length > maxExportReadback {
				return zero, ErrConflict
			}
			receipts[seq] = m
			out.Versions = append(out.Versions, ExportVersion{r.Key, r.Version, m.marker.SHA256, "marker", m.marker.Length})
			out.Sources[r] = "signed"
			continue
		}
		v, err := b.store.Read(ctx, r.Key, r.Version)
		if err != nil {
			return zero, err
		}
		if v.ID != r.Version || v.Mode != "COMPLIANCE" || v.Until.IsZero() {
			return zero, ErrNotDurable
		}
		if len(v.Data) > maxExportReadback-total {
			return zero, ErrNotDurable
		}
		total += len(v.Data)
		kind, id := metadata[r][0], metadata[r][1]
		rawDigest := SHA256(v.Data)
		if kind == "object" {
			if rawDigest != id {
				return zero, ErrConflict
			}
			out.Objects[id] = v.Data
		} else {
			e, err := ParseEvent(v.Data)
			if err != nil {
				return zero, ErrConflict
			}
			canon, err := Canonical(e)
			if err != nil || !bytes.Equal(canon, v.Data) {
				return zero, ErrConflict
			}
			seq, ok := integer(e["seq"])
			if !ok || seq < 0 || seq > out.EndSequence || str(e, "tenant_id") != tenant || str(e, "project_id") != project || str(e, "matter_id") != matter || str(e, "turn_id") != turn || str(e, "event_hash") != id {
				return zero, ErrConflict
			}
			h, err := EventHash(e)
			if err != nil || h != id || logs[int(seq)] != nil {
				return zero, ErrConflict
			}
			logs[int(seq)], raws[int(seq)], readEventRef[int(seq)] = e, v.Data, r
		}
		loaded[r] = v
		out.Versions = append(out.Versions, ExportVersion{r.Key, r.Version, rawDigest, kind, uint64(len(v.Data))})
		out.Sources[r] = "plan_readback"
	}
	verifyReceipt := func(r retainedObjectReceipt) error {
		vr := VersionRef{r.Key, r.Version}
		present, known := plan[vr]
		if !known || r.Tenant != tenant || r.Bucket != b.bucket || r.Deployment != b.deployment {
			return ErrConflict
		}
		if !present {
			return nil
		}
		v, ok := loaded[vr]
		until, err := time.Parse(time.RFC3339, r.RetainUntil)
		if !ok || err != nil || v.Until.Before(until) || uint64(len(v.Data)) != r.Length || SHA256(v.Data) != r.SHA256 {
			return ErrConflict
		}
		out.Sources[vr] = "signed"
		return nil
	}
	for seq, m := range receipts {
		c := m.commit
		expectedKey := b.eventKey(tenant, turn, c.EventHash)
		r := VersionRef{c.Event.Key, c.Event.Version}
		if c.Event.Key != expectedKey || c.Event.EvidenceID != c.EventHash || verifyReceipt(c.Event) != nil {
			return zero, ErrConflict
		}
		if got := logs[seq]; plan[r] != (got != nil) || (got != nil && readEventRef[seq] != r) {
			return zero, ErrConflict
		}
		if seq > 0 {
			prev := markers[seq-1]
			if c.Predecessor == nil || c.Predecessor.Bucket != b.bucket || c.Predecessor.Key != prev.Key || c.Predecessor.Version != prev.Version {
				return zero, ErrConflict
			}
			if other, ok := receipts[seq-1]; ok && !compatibleMarker(*c.Predecessor, other.marker) {
				return zero, ErrConflict
			}
		}
		wanted := map[string]int64{}
		if e := logs[seq]; e != nil {
			for _, ref := range eventRefs(e) {
				wanted[ref.sha] = ref.bytes
			}
		}
		for _, o := range c.Objects {
			if o.EvidenceID != o.SHA256 || o.Key != b.objectKey(tenant, o.SHA256) || verifyReceipt(o) != nil {
				return zero, ErrConflict
			}
			if logs[seq] != nil {
				if size, ok := wanted[o.SHA256]; !ok || size < 0 || uint64(size) != o.Length {
					return zero, ErrConflict
				}
				delete(wanted, o.SHA256)
			}
		}
		if len(wanted) > 0 {
			return zero, ErrConflict
		}
	}
	// The plan contains exactly one marker and one data reference per slot.
	// Missing sequences reflect lost event bytes, not merely lost markers.
	for seq := 0; seq < len(markers); seq++ {
		if e := logs[seq]; e != nil {
			out.Events = append(out.Events, e)
			out.CanonicalEvents = append(out.CanonicalEvents, raws[seq])
		} else {
			out.MissingSequences = append(out.MissingSequences, int64(seq))
		}
	}
	if len(out.Events) > 0 {
		if err := VerifySurvivingExportEvents(out.Events, out.EndSequence, out.MissingSequences); err != nil {
			return zero, err
		}
	}
	sort.Slice(out.Versions, func(i, j int) bool {
		a, b := out.Versions[i], out.Versions[j]
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Version < b.Version
	})
	return out, nil
}
