package exportbundle

import (
	"errors"
	"strconv"
	"strings"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

// recordIdentity cross-checks metadata against the authorized admission
// selection even if event zero has been lost. The window selects admissions,
// not individual events: a terminal successor may fall after window_end.
func recordIdentity(record, scope map[string]any) error {
	custodian, ok := record["custodian_id"].(string)
	if !ok || !identifierRE.MatchString(custodian) || !validUTC(record["recorded_at"]) {
		return errors.New("invalid admission metadata")
	}
	date := mustTime(record["recorded_at"])
	if date.Before(mustTime(scope["window_start"])) || !date.Before(mustTime(scope["window_end"])) {
		return errors.New("admission timestamp outside scope")
	}
	for _, c := range scope["custodian_ids"].([]any) {
		if c == custodian {
			return nil
		}
	}
	return errors.New("admission custodian outside scope")
}

func knownHoldIDs(raw any, allowed map[string]bool, allowEmpty bool) error {
	ids, ok := raw.([]any)
	if !ok || (!allowEmpty && len(ids) == 0) || len(ids) > 1024 {
		return errors.New("invalid hold census")
	}
	prev := ""
	for _, v := range ids {
		id, ok := v.(string)
		if !ok || !uuidRE.MatchString(id) || id <= prev || (allowed != nil && !allowed[id]) {
			return errors.New("invalid hold identifier")
		}
		prev = id
	}
	return nil
}

func keyKind(key, tenant, turn string) (kind, id string) {
	a := strings.Split(key, "/")
	if len(a) < 6 || a[0] != "charter" || a[1] != "v1" || !identifierRE.MatchString(a[2]) || a[3] != tenant {
		return "", ""
	}
	if len(a) == 6 && a[4] == "admissions" && digestRE.MatchString(a[5]) {
		return "marker", a[5]
	}
	if len(a) == 7 && a[4] == "events" && a[5] == turn && versionSequence(a[6]) {
		return "marker", a[6]
	}
	if len(a) == 7 && a[4] == "data" && a[5] == "objects" && digestRE.MatchString(a[6]) {
		return "object", a[6]
	}
	if len(a) == 8 && a[4] == "data" && a[5] == "events" && a[6] == turn && digestRE.MatchString(a[7]) {
		return "event", a[7]
	}
	return "", ""
}

// validateVersions binds included version metadata to the exact event/object
// raw bytes. The digest of a marker is exporter-attributed metadata, not an
// offline claim that a storage endpoint or original signing key was verified.
func validateVersions(v any, tenant, turn, profile string, ev []evidence.Event, lines [][]byte, objs map[string][]byte, partial bool) (map[string]int64, error) {
	refs, ok := v.([]any)
	if !ok || len(refs) > 10000 {
		return nil, errors.New("invalid retained version census")
	}
	objectRefs := map[string]int64{}
	if profile != evidence.RetentionProfile {
		if len(refs) != 0 || partial {
			return nil, errors.New("retained metadata used by non-retained profile")
		}
		return objectRefs, nil
	}
	evt := map[string][]byte{}
	for i, e := range ev {
		h, _ := e["event_hash"].(string)
		evt[h] = lines[i]
	}
	haveEvents := map[string]bool{}
	markCount := 0
	seen := map[[2]string]bool{}
	for _, v := range refs {
		r, ok := v.(map[string]any)
		if !ok || fields(r, "key", "version", "kind", "sha256", "bytes", "source") != nil {
			return nil, errors.New("invalid retained version metadata")
		}
		key, _ := r["key"].(string)
		version, _ := r["version"].(string)
		kind, id := keyKind(key, tenant, turn)
		source, _ := r["source"].(string)
		if (source != "signed" && source != "plan_readback") || ((kind == "marker" || !partial) && source != "signed") {
			return nil, errors.New("invalid retained authenticity attribution")
		}
		digest, _ := r["sha256"].(string)
		n, ok := integer(r["bytes"])
		if kind == "" || r["kind"] != kind || version == "" || version == "null" || len(version) > 1024 || !digestRE.MatchString(digest) || !ok || n < 0 || seen[[2]string{key, version}] {
			return nil, errors.New("invalid or duplicate retained version")
		}
		seen[[2]string{key, version}] = true
		switch kind {
		case "marker":
			markCount++
		case "event":
			b, ok := evt[id]
			if !ok || haveEvents[id] || int64(len(b)) != n || evidence.SHA256(b) != digest {
				return nil, errors.New("retained event version does not bind event bytes")
			}
			haveEvents[id] = true
		case "object":
			b, ok := objs[id]
			if !ok || int64(len(b)) != n || id != digest {
				return nil, errors.New("retained object version does not bind object bytes")
			}
			objectRefs[id] = n
		}
	}
	if len(haveEvents) != len(ev) || (!partial && markCount != len(ev)) {
		return nil, errors.New("retained version set omits event or marker")
	}
	localRefs := map[string]int64{}
	if err := collectReferences(ev, localRefs); err != nil {
		return nil, err
	}
	for sha, size := range localRefs {
		if n, ok := objectRefs[sha]; !partial && (!ok || n != size) {
			return nil, errors.New("turn is missing its own retained object version")
		}
	}
	if !partial && len(localRefs) != len(objectRefs) {
		return nil, errors.New("turn retained versions contain unreferenced object")
	}
	return objectRefs, nil
}

// A retained plan indexes one marker and data reference per sequence. This
// cross-check prevents a hole declaration from masking an authenticated
// selection that described an extra suffix or only lost an object.
func validateSlotCensus(turn map[string]any, gap gapEntry, tenant, id string, end int64, nHoles int) error {
	slots := map[int64]bool{}
	refs := map[[2]string]bool{}
	nLostEvents := 0
	visit := func(v any, missing bool) error {
		row, ok := v.(map[string]any)
		if !ok {
			return errors.New("invalid retained census member")
		}
		key, _ := row["key"].(string)
		vID, _ := row["version"].(string)
		ref := [2]string{key, vID}
		if refs[ref] {
			return errors.New("version is duplicated or both surviving and missing")
		}
		refs[ref] = true
		k, s := keyKind(key, tenant, id)
		if k == "event" && missing {
			nLostEvents++
		}
		if k != "marker" {
			return nil
		}
		var seq int64
		if !digestRE.MatchString(s) {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return err
			}
			seq = n
		}
		if seq < 0 || seq > end || slots[seq] {
			return errors.New("incorrect or duplicate retained marker sequence")
		}
		slots[seq] = true
		return nil
	}
	for _, v := range turn["retained_versions"].([]any) {
		if err := visit(v, false); err != nil {
			return err
		}
	}
	if gap.id != "" {
		for _, v := range gap.raw["missing_versions"].([]any) {
			if err := visit(v, true); err != nil {
				return err
			}
		}
	}
	if nLostEvents != nHoles || int64(len(slots)) != end+1 {
		return errors.New("retained marker/data census does not account for sequence holes")
	}
	return nil
}
