package exportbundle

import (
	"errors"
	"strconv"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

type gapEntry struct {
	id, kind       string
	raw            map[string]any
	missingObjects map[string]bool
}

func readGaps(raw any, scope map[string]any, holds map[string]bool, profile string) (map[string]gapEntry, []string, error) {
	entries, ok := raw.([]any)
	if !ok || len(entries) > MaxFiles {
		return nil, nil, errors.New("invalid gap count")
	}
	out := map[string]gapEntry{}
	var reported []string
	for _, v := range entries {
		m, ok := v.(map[string]any)
		if !ok || fields(m, "turn_id", "kind", "custodian_id", "recorded_at", "hold_ids", "missing_versions") != nil {
			return nil, nil, errors.New("invalid gap declaration")
		}
		id, _ := m["turn_id"].(string)
		kind, _ := m["kind"].(string)
		if !uuidRE.MatchString(id) || out[id].id != "" || recordIdentity(m, scope) != nil {
			return nil, nil, errors.New("gap scope or identity mismatch")
		}
		missing, ok := m["missing_versions"].([]any)
		if !ok || len(missing) > 10000 || profile != evidence.RetentionProfile {
			return nil, nil, errors.New("invalid missing version list")
		}
		if kind == "uncovered" {
			if len(missing) != 0 || knownHoldIDs(m["hold_ids"], map[string]bool{}, true) != nil {
				return nil, nil, errors.New("uncovered record cannot declare retained loss")
			}
		} else if kind == "partial_loss" || kind == "complete_loss" || kind == "disposed" {
			if len(missing) == 0 || knownHoldIDs(m["hold_ids"], holds, false) != nil {
				return nil, nil, errors.New("historical loss requires scoped holds and missing versions")
			}
		} else {
			return nil, nil, errors.New("unknown gap classification")
		}
		seen := map[[2]string]bool{}
		objects := map[string]bool{}
		for _, v := range missing {
			ref, ok := v.(map[string]any)
			if !ok || fields(ref, "key", "version", "disposition", "plan_epoch") != nil {
				return nil, nil, errors.New("invalid historical loss attribution")
			}
			key, _ := ref["key"].(string)
			version, _ := ref["version"].(string)
			d, _ := ref["disposition"].(string)
			if e, ok := integer(ref["plan_epoch"]); ref["plan_epoch"] != nil && (!ok || e < 0) {
				return nil, nil, errors.New("invalid disposal plan epoch")
			}
			k, sha := keyKind(key, scope["tenant_id"].(string), id)
			if k == "" || version == "" || version == "null" || len(version) > 1024 || seen[[2]string{key, version}] || d != "deleted" && d != "absent" && d != "readback_absent" {
				return nil, nil, errors.New("invalid exact missing version")
			}
			seen[[2]string{key, version}] = true
			if k == "object" {
				objects[sha] = true
			}
		}
		out[id] = gapEntry{id, kind, m, objects}
		reported = append(reported, id+":"+kind)
	}
	return out, reported, nil
}

func versionSequence(id string) bool {
	if digestRE.MatchString(id) {
		return true
	}
	seq, err := strconv.ParseInt(id, 10, 32)
	return err == nil && seq > 0 && seq < MaxEvents && strconv.FormatInt(seq, 10) == id
}
