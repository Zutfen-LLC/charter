// Package exportbundle implements offline verification of bound C08 directory bundles.
package exportbundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

const (
	SchemaVersion = "charter-export-bundle-v1"
	MaxManifest   = 4 << 20
	MaxBundle     = 32 << 20
	MaxFiles      = 10000
	MaxEvents     = 16384
)

type Status string

const (
	Complete    Status = "complete"
	DeclaredGap Status = "declared_gap"
)

type Result struct {
	Status      Status   `json:"status"`
	Profile     string   `json:"profile"`
	Turns       int      `json:"turns"`
	Objects     int      `json:"objects"`
	Gaps        []string `json:"gaps,omitempty"`
	Limitations []string `json:"limitations"`
}
type Failure struct {
	Kind string
	Err  error
}

func (e *Failure) Error() string { return e.Kind + ": " + e.Err.Error() }
func (e *Failure) Unwrap() error { return e.Err }

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func bad(k, s string) (Result, error) { return Result{}, &Failure{k, errors.New(s)} }

// Verify requires the verifier profile and expected manifest SHA-256 from outside the bundle.
func Verify(dir, profile, expected string) (Result, error) {
	if err := validateRequest(profile, expected); err != nil {
		return Result{}, err
	}
	fs, err := openBundleFS(dir)
	if err != nil {
		return bad("operational", err.Error())
	}
	defer fs.close()
	return verifyBundle(fs, profile, expected)
}

// VerifyMembers runs the identical verifier over staged in-memory package members.
// Map keys are bundle-relative paths; this does not grant filesystem or evidence-read authority.
func VerifyMembers(files map[string][]byte, profile, expected string) (Result, error) {
	if err := validateRequest(profile, expected); err != nil {
		return Result{}, err
	}
	return verifyBundle(memoryFS(files), profile, expected)
}

type bundleReader interface {
	members(int) ([]string, error)
	read(string, int64) ([]byte, error)
}
type memoryFS map[string][]byte

func (m memoryFS) members(limit int) ([]string, error) {
	if len(m) > limit {
		return nil, errors.New("bundle member count limit exceeded")
	}
	out := make([]string, 0, len(m))
	for name := range m {
		if _, err := safeParts(name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}
func (m memoryFS) read(name string, max int64) ([]byte, error) {
	if _, err := safeParts(name); err != nil {
		return nil, err
	}
	b, ok := m[name]
	if !ok {
		return nil, errors.New("manifested member missing")
	}
	if int64(len(b)) > max {
		return nil, errors.New("file size limit exceeded")
	}
	return append([]byte(nil), b...), nil
}
func validateRequest(profile, expected string) error {
	if profile != "charter-postgres-v1" && profile != "charter-s3-compliance-v1" {
		return &Failure{"unsupported", errors.New("unknown explicitly selected evidence profile")}
	}
	if !digestRE.MatchString(expected) {
		return &Failure{"integrity", errors.New("expected manifest digest must be sha256:<64 lowercase hex>")}
	}
	return nil
}
func verifyBundle(fs bundleReader, profile, expected string) (Result, error) {
	names, err := fs.members(MaxFiles)
	if err != nil {
		return bad("integrity", err.Error())
	}
	if len(names) > MaxFiles {
		return bad("integrity", "bundle file limit exceeded")
	}
	raw, err := fs.read("manifest.json", MaxManifest)
	if err != nil {
		return bad("integrity", err.Error())
	}
	if evidence.SHA256(raw) != expected {
		return bad("integrity", "manifest digest mismatch")
	}
	v, err := evidence.ParseJSON(raw)
	if err != nil {
		return bad("integrity", "invalid manifest JSON: "+err.Error())
	}
	m, ok := v.(map[string]any)
	if !ok {
		return bad("integrity", "manifest must be an object")
	}
	canonical, err := evidence.Canonical(m)
	if err != nil || !bytes.Equal(raw, canonical) {
		return bad("integrity", "manifest is not exact canonical JSON")
	}
	if err = fields(m, "schema_version", "profile", "export_id", "snapshot", "scope", "custody", "turns", "objects", "gaps"); err != nil {
		return bad("unsupported", err.Error())
	}
	if m["schema_version"] != SchemaVersion {
		return bad("unsupported", "unsupported bundle schema")
	}
	if m["profile"] != profile {
		return bad("integrity", "manifest profile differs from caller-selected profile")
	}
	exportID, _ := m["export_id"].(string)
	if !uuidRE.MatchString(exportID) {
		return bad("integrity", "invalid export id")
	}
	if err = validateSnapshot(m["snapshot"], m["scope"], m["custody"]); err != nil {
		return bad("integrity", err.Error())
	}
	expectedFiles := map[string]bool{"manifest.json": true}
	objects := map[string][]byte{}
	objectSizes := map[string]int64{}
	referenced := map[string]int64{}
	scope := m["scope"].(map[string]any)
	holdList := m["snapshot"].(map[string]any)["hold_ids"]
	if err := knownHoldIDs(holdList, nil, profile != evidence.RetentionProfile); err != nil {
		return bad("integrity", err.Error())
	}
	holds := map[string]bool{}
	for _, id := range holdList.([]any) {
		holds[id.(string)] = true
	}
	gapMap, gaps, err := readGaps(m["gaps"], scope, holds, profile)
	if err != nil {
		return bad("integrity", err.Error())
	}
	oa, ok := m["objects"].([]any)
	if !ok || len(oa) > MaxFiles {
		return bad("integrity", "objects must be a bounded array")
	}
	total := int64(len(raw))
	for _, x := range oa {
		o, ok := x.(map[string]any)
		if !ok {
			return bad("integrity", "object entry must be object")
		}
		if err := fields(o, "sha256", "bytes"); err != nil {
			return bad("unsupported", err.Error())
		}
		sha, ok := o["sha256"].(string)
		if !ok || !digestRE.MatchString(sha) {
			return bad("integrity", "invalid object digest")
		}
		size, ok := integer(o["bytes"])
		if !ok || size < 0 || size > MaxBundle {
			return bad("integrity", "invalid object length")
		}
		if _, dup := objects[sha]; dup {
			return bad("integrity", "duplicate object declaration")
		}
		if total+size > MaxBundle {
			return bad("integrity", "bundle byte limit exceeded")
		}
		p := "objects/" + strings.TrimPrefix(sha, "sha256:")
		b, e := fs.read(p, size)
		if e != nil {
			return bad("integrity", e.Error())
		}
		if int64(len(b)) != size || evidence.SHA256(b) != sha {
			return bad("integrity", "object bytes do not match manifest")
		}
		objects[sha] = b
		objectSizes[sha] = size
		expectedFiles[p] = true
		total += size
	}
	ta, ok := m["turns"].([]any)
	if !ok || len(ta) > MaxEvents {
		return bad("integrity", "turns must be a bounded array")
	}
	usedGaps := map[string]bool{}
	seenTurns := map[string]bool{}
	totalEvents := 0
	for _, x := range ta {
		t, ok := x.(map[string]any)
		if !ok {
			return bad("integrity", "turn entry must be object")
		}
		if err := fields(t, "turn_id", "custodian_id", "recorded_at", "hold_ids", "event_path", "event_sha256", "event_count", "end_sequence", "head_hash", "partial", "missing_sequences", "retained_versions"); err != nil {
			return bad("unsupported", err.Error())
		}
		id, _ := t["turn_id"].(string)
		if !uuidRE.MatchString(id) || recordIdentity(t, scope) != nil || knownHoldIDs(t["hold_ids"], holds, profile != evidence.RetentionProfile) != nil {
			return bad("integrity", "turn id must be canonical UUID")
		}
		if seenTurns[id] {
			return bad("integrity", "duplicate turn declaration")
		}
		seenTurns[id] = true
		count, ok := integer(t["event_count"])
		end, ok2 := integer(t["end_sequence"])
		partial, partialOK := t["partial"].(bool)
		missing, missingOK := t["missing_sequences"].([]any)
		if !ok || !ok2 || count < 0 || count > int64(MaxEvents-totalEvents) || end < 0 || end >= MaxEvents || !partialOK || !missingOK || count+int64(len(missing)) != end+1 || (!partial && (count == 0 || len(missing) != 0)) {
			return bad("integrity", "event/partial census invalid")
		}
		var ev []evidence.Event
		var lines [][]byte
		if count == 0 {
			if t["event_sha256"] != nil || t["head_hash"] != nil || t["event_path"] != nil {
				return bad("integrity", "lost event log cannot declare a member")
			}
		} else {
			ep := "events/" + id + ".jsonl"
			if t["event_path"] != ep || expectedFiles[ep] {
				return bad("integrity", "invalid or duplicate event path")
			}
			remaining := MaxBundle - total
			if remaining <= 0 {
				return bad("integrity", "bundle byte limit exceeded")
			}
			b, e := fs.read(ep, remaining)
			if e != nil {
				return bad("integrity", e.Error())
			}
			expectedFiles[ep] = true
			total += int64(len(b))
			if len(b) == 0 || b[len(b)-1] != '\n' || int64(bytes.Count(b, []byte{'\n'})) != count || t["event_sha256"] != evidence.SHA256(b) {
				return bad("integrity", "event log framing or digest invalid")
			}
			lines = bytes.Split(b[:len(b)-1], []byte{'\n'})
			ev, e = evidence.ParseEventLog(b)
			if e != nil || int64(len(ev)) != count {
				return bad("integrity", "invalid event log")
			}
			totalEvents += len(ev)
			for i, event := range ev {
				c, err := evidence.Canonical(event)
				if err != nil || !bytes.Equal(c, lines[i]) {
					return bad("integrity", "noncanonical original event")
				}
			}
			if ev[len(ev)-1]["event_hash"] != t["head_hash"] {
				return bad("integrity", "event head differs from manifest")
			}
		}
		gap := gapMap[id]
		if partial {
			if gap.kind != "partial_loss" || gap.raw["custodian_id"] != t["custodian_id"] || gap.raw["recorded_at"] != t["recorded_at"] {
				return bad("integrity", "partial turn not bound to historical loss")
			}
			usedGaps[id] = true
		} else if gap.id != "" {
			return bad("integrity", "complete turn conflicts with a declared gap")
		}
		if len(ev) > 0 {
			if err := validateEventScope(ev, id, profile, scope, t, partial); err != nil {
				return bad("integrity", err.Error())
			}
		}
		local := map[string]int64{}
		if err := collectReferences(ev, local); err != nil {
			return bad("integrity", err.Error())
		}
		exact, err := validateVersions(t["retained_versions"], scope["tenant_id"].(string), id, profile, ev, lines, objects, partial)
		if err != nil {
			return bad("integrity", err.Error())
		}
		if profile == evidence.RetentionProfile {
			if err := validateSlotCensus(t, gap, scope["tenant_id"].(string), id, end, len(missing)); err != nil {
				return bad("integrity", err.Error())
			}
		}
		if partial {
			holes := make([]int64, 0, len(missing))
			for _, v := range missing {
				n, ok := integer(v)
				if !ok {
					return bad("integrity", "invalid missing sequence")
				}
				holes = append(holes, n)
			}
			if len(ev) > 0 {
				if err := evidence.VerifySurvivingExportEvents(ev, end, holes); err != nil {
					return bad("integrity", err.Error())
				}
			} else {
				for i, seq := range holes {
					if int64(i) != seq {
						return bad("integrity", "lost event sequence census is not contiguous")
					}
				}
			}
			for sha, size := range local {
				if n, ok := exact[sha]; (!ok || n != size) && !gap.missingObjects[sha] {
					return bad("integrity", "partial turn has undeclared missing object")
				}
			}
			for sha, size := range exact {
				if n, ok := local[sha]; ok && n != size {
					return bad("integrity", "partial retained object conflicts with reference")
				}
				referenced[sha] = size
			}
		} else {
			var problems []string
			if profile == evidence.RetentionProfile {
				problems = evidence.VerifyRetentionFull(ev, objects)
			} else {
				problems = evidence.VerifyCurrentFull(ev, objects)
			}
			if len(problems) > 0 {
				return bad("integrity", "event verification failed: "+problems[0])
			}
			for sha, size := range local {
				referenced[sha] = size
			}
		}
	}
	for sha, size := range referenced {
		if n, ok := objectSizes[sha]; !ok || n != size {
			return bad("integrity", "referenced objects do not match declared bytes")
		}
	}
	if len(referenced) != len(objectSizes) {
		return bad("integrity", "manifest contains unreferenced object")
	}
	for id, g := range gapMap {
		if g.kind == "partial_loss" && !usedGaps[id] {
			return bad("integrity", "partial gap has no surviving event log")
		}
	}
	if len(ta) == 0 && len(gaps) == 0 {
		return bad("integrity", "empty export selection")
	}
	if total > MaxBundle {
		return bad("integrity", "bundle byte limit exceeded")
	}
	for _, n := range names {
		if !expectedFiles[n] {
			return bad("integrity", "unmanifested package member: "+n)
		}
	}
	for n := range expectedFiles {
		found := false
		for _, x := range names {
			if x == n {
				found = true
				break
			}
		}
		if !found {
			return bad("integrity", "manifested package member missing")
		}
	}
	status := Complete
	if len(gaps) > 0 {
		status = DeclaredGap
	}
	return Result{Status: status, Profile: profile, Turns: len(ta), Objects: len(objects), Gaps: gaps, Limitations: []string{"manifest digest authenticates the supplied manifest only; caller must obtain it through a trusted channel", "offline chain consistency does not prove provenance, storage retention, WORM, external anchoring, or delivery"}}, nil
}

func validateEventScope(events []evidence.Event, turnID, profile string, scope, record map[string]any, partial bool) error {
	first := events[0]
	if seq, ok := integer(first["seq"]); ok && seq == 0 {
		p, pok := first["payload"].(map[string]any)
		actor, aok := first["actor"].(map[string]any)
		if !pok || !aok || p["evidence_profile"] != profile || actor["kind"] != "user" || actor["id"] != record["custodian_id"] || p["custodian_id"] != record["custodian_id"] || !validUTC(first["recorded_at"]) || !mustTime(first["recorded_at"]).Equal(mustTime(record["recorded_at"])) {
			return errors.New("admission identity, time or profile differs from snapshot")
		}
	} else if !partial {
		return errors.New("complete turn missing admission")
	}
	for i, event := range events {
		for _, key := range []string{"tenant_id", "project_id", "matter_id"} {
			if event[key] != scope[key] {
				return fmt.Errorf("event %d outside export %s", i, key)
			}
		}
		if event["turn_id"] != turnID {
			return fmt.Errorf("event %d turn differs from package path", i)
		}
	}
	return nil
}

func collectReferences(events []evidence.Event, refs map[string]int64) error {
	add := func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		sha, ok := m["sha256"].(string)
		if !ok || !digestRE.MatchString(sha) {
			return nil
		}
		n, ok := integer(m["bytes"])
		if !ok || n < 0 {
			return nil
		}
		if old, exists := refs[sha]; exists && old != n {
			return errors.New("event references declare conflicting object lengths")
		}
		refs[sha] = n
		return nil
	}
	for _, event := range events {
		p, ok := event["payload"].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"input", "request"} {
			if err := add(p[key]); err != nil {
				return err
			}
		}
		if list, ok := p["objects"].([]any); ok {
			for _, x := range list {
				if err := add(x); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func integer(v any) (int64, bool) {
	s, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(s), 10, 64)
	return n, err == nil
}
func fields(m map[string]any, allowed ...string) error {
	set := map[string]bool{}
	for _, k := range allowed {
		set[k] = true
	}
	for k := range m {
		if !set[k] {
			return fmt.Errorf("unknown manifest field %q", k)
		}
	}
	for _, k := range allowed {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing manifest field %q", k)
		}
	}
	return nil
}
func validateSnapshot(v, scope, custody any) error {
	s, ok := v.(map[string]any)
	if !ok {
		return errors.New("snapshot binding required")
	}
	if err := fields(s, "id", "revision", "captured_at", "hold_ids"); err != nil {
		return err
	}
	for _, k := range []string{"id", "revision"} {
		z, ok := s[k].(string)
		if !ok || z == "" {
			return errors.New("empty snapshot binding")
		}
	}
	if !validUTC(s["captured_at"]) {
		return errors.New("snapshot captured_at must be UTC RFC3339")
	}
	sc, ok := scope.(map[string]any)
	if !ok {
		return errors.New("scope required")
	}
	if err := fields(sc, "tenant_id", "project_id", "matter_id", "custodian_ids", "window_start", "window_end"); err != nil {
		return err
	}
	for _, k := range []string{"tenant_id", "project_id", "matter_id"} {
		z, ok := sc[k].(string)
		if !ok || !identifierRE.MatchString(z) {
			return errors.New("scope identifiers must be canonical lowercase identifiers")
		}
	}
	if !validUTC(sc["window_start"]) || !validUTC(sc["window_end"]) {
		return errors.New("scope requires bounded UTC window")
	}
	start := mustTime(sc["window_start"])
	end := mustTime(sc["window_end"])
	if !start.Before(end) {
		return errors.New("scope window must be non-empty and half-open")
	}
	if xs, ok := sc["custodian_ids"].([]any); !ok || len(xs) == 0 || len(xs) > 256 {
		return errors.New("custodian_ids must be an array")
	}
	ca, ok := custody.(map[string]any)
	if !ok {
		return errors.New("custody required")
	}
	if err := fields(ca, "requester_id", "approver_id", "requested_at", "approved_at", "snapshot_id"); err != nil {
		return err
	}
	requester, rok := ca["requester_id"].(string)
	approver, aok := ca["approver_id"].(string)
	if !rok || !aok || requester == "" || approver == "" || requester == approver || ca["snapshot_id"] != s["id"] || !validUTC(ca["requested_at"]) || !validUTC(ca["approved_at"]) || mustTime(ca["approved_at"]).Before(mustTime(ca["requested_at"])) {
		return errors.New("custody separation, approval time, or snapshot binding invalid")
	}
	return nil
}

var identifierRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func validUTC(v any) bool {
	s, ok := v.(string)
	if !ok || !strings.HasSuffix(s, "Z") {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}
func mustTime(v any) time.Time { s := v.(string); t, _ := time.Parse(time.RFC3339Nano, s); return t }
