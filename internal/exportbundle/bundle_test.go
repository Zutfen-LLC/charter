package exportbundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

const fixtureTurn = "123e4567-e89b-42d3-a456-426614174000"
const currentProfile = "charter-postgres-v1"

func TestVerifyMembersUsesSameBoundVerifier(t *testing.T) {
	dir, anchor := makeCurrentBundle(t)
	files := readBundleMembers(t, dir)
	got, err := VerifyMembers(files, currentProfile, anchor)
	if err != nil {
		t.Fatalf("in-memory staged package rejected: %v", err)
	}
	disk, err := Verify(dir, currentProfile, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != disk.Status || got.Turns != disk.Turns || got.Objects != disk.Objects {
		t.Fatalf("in-memory and filesystem results differ: %+v %+v", got, disk)
	}
	files["manifest.json"] = append(files["manifest.json"], byte(' '))
	if _, err = VerifyMembers(files, currentProfile, anchor); err == nil {
		t.Fatal("mutated staged manifest accepted")
	}
}
func readBundleMembers(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err == nil {
			out[filepath.ToSlash(rel)] = b
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyRequiresIndependentManifestDigest(t *testing.T) {
	if _, err := Verify(t.TempDir(), "", "sha256:"+string(make([]byte, 64))); err == nil {
		t.Fatal("empty selected profile and digest accepted")
	}
}

func TestRejectUnsafeBundleMember(t *testing.T) {
	d, anchor := makeCurrentBundle(t)
	p := filepath.Join(d, "manifest.json")
	outside := filepath.Join(t.TempDir(), "manifest-copy.json")
	if err := os.Rename(p, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(d, currentProfile, anchor); err == nil {
		t.Fatal("symlinked exact manifest accepted")
	}
}

func TestVerifyCompleteAuthenticBundleWithAdmissionProfileMarker(t *testing.T) {
	dir, anchor := makeCurrentBundle(t)
	got, err := Verify(dir, currentProfile, anchor)
	if err != nil {
		t.Fatalf("authentic complete fixture rejected: %v", err)
	}
	if got.Status != Complete || got.Turns != 1 || got.Objects != 4 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestScopeBindsEveryEventAndCustodianTime(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"tenant", func(m map[string]any) { m["scope"].(map[string]any)["tenant_id"] = "t-other" }},
		{"project", func(m map[string]any) { m["scope"].(map[string]any)["project_id"] = "p-other" }},
		{"matter", func(m map[string]any) { m["scope"].(map[string]any)["matter_id"] = "m-other" }},
		{"custodian", func(m map[string]any) { m["scope"].(map[string]any)["custodian_ids"] = []any{"different-custodian"} }},
		{"time", func(m map[string]any) { m["scope"].(map[string]any)["window_start"] = "2026-01-16T00:00:00.000Z" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := makeCurrentBundle(t)
			anchor := alterManifest(t, dir, tc.change)
			if _, err := Verify(dir, currentProfile, anchor); err == nil {
				t.Fatal("scope substitution accepted")
			}
		})
	}
}

func TestRejectSymlinkedBundleDirectoryAndMemberLimit(t *testing.T) {
	t.Run("directory substitution", func(t *testing.T) {
		dir, anchor := makeCurrentBundle(t)
		events := filepath.Join(dir, "events")
		saved := filepath.Join(t.TempDir(), "events.saved")
		if err := os.Rename(events, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(saved, events); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(dir, currentProfile, anchor); err == nil {
			t.Fatal("symlinked directory accepted")
		}
	})
	t.Run("member bound", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"a", "b", "c"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		fs, err := openBundleFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer fs.close()
		if _, err = fs.members(2); err == nil {
			t.Fatal("member count bound not enforced")
		}
	})
}

func TestRejectSymlinkedBundleAncestorWithValidDigest(t *testing.T) {
	dir, anchor := makeCurrentBundle(t)
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(dir), link); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(filepath.Join(link, filepath.Base(dir)), currentProfile, anchor); err == nil {
		t.Fatal("bundle reached through symlinked ancestor was accepted")
	}
}

func TestObjectLengthBoundBeforeRead(t *testing.T) {
	dir, _ := makeCurrentBundle(t)
	anchor := alterManifest(t, dir, func(m map[string]any) {
		m["objects"].([]any)[0].(map[string]any)["bytes"] = json.Number(fmt.Sprint(MaxBundle + 1))
	})
	if _, err := Verify(dir, currentProfile, anchor); err == nil {
		t.Fatal("over-limit object length accepted")
	}
}

func TestRejectHardlinkAndFIFO(t *testing.T) {
	t.Run("hardlink", func(t *testing.T) {
		dir, anchor := makeCurrentBundle(t)
		if err := os.Link(filepath.Join(dir, "manifest.json"), filepath.Join(t.TempDir(), "hardlink")); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(dir, currentProfile, anchor); err == nil {
			t.Fatal("hard link accepted")
		}
	})
	t.Run("fifo", func(t *testing.T) {
		dir, anchor := makeCurrentBundle(t)
		if err := os.Remove(filepath.Join(dir, "manifest.json")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(dir, "manifest.json"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(dir, currentProfile, anchor); err == nil {
			t.Fatal("FIFO accepted")
		}
	})
}

func TestRejectUnreferencedObjectEvenWhenManifestListsIt(t *testing.T) {
	dir, _ := makeCurrentBundle(t)
	extra := []byte("unreferenced object")
	sha := evidence.SHA256(extra)
	if err := os.WriteFile(filepath.Join(dir, "objects", sha[len("sha256:"):]), extra, 0600); err != nil {
		t.Fatal(err)
	}
	anchor := alterManifest(t, dir, func(m map[string]any) {
		entries := m["objects"].([]any)
		entry := map[string]any{"sha256": sha, "bytes": json.Number(fmt.Sprint(len(extra)))}
		m["objects"] = append(entries, entry)
	})
	if _, err := Verify(dir, currentProfile, anchor); err == nil {
		t.Fatal("unreferenced object accepted")
	}
}

func TestCoherentBundleReplacementRejectedByOriginalAnchor(t *testing.T) {
	original, originalAnchor := makeCurrentBundle(t)
	replacement, _ := makeCurrentBundle(t)
	replacementAnchor := alterManifest(t, replacement, func(m map[string]any) { m["snapshot"].(map[string]any)["revision"] = "revision-substituted" })
	if _, err := Verify(replacement, currentProfile, replacementAnchor); err != nil {
		t.Fatalf("replacement should be internally coherent: %v", err)
	}
	if _, err := Verify(replacement, currentProfile, originalAnchor); err == nil {
		t.Fatal("coherent replacement passed original independently supplied anchor")
	}
	if _, err := Verify(original, currentProfile, originalAnchor); err != nil {
		t.Fatalf("original anchored bundle rejected: %v", err)
	}
}

func makeCurrentBundle(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "contracts", "current-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := evidence.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	cases := root.([]any)
	var fixture map[string]any
	for _, v := range cases {
		m := v.(map[string]any)
		if m["name"] == "positive-complete" {
			fixture = m
			break
		}
	}
	if fixture == nil {
		t.Fatal("positive fixture missing")
	}
	events := fixture["events"].([]any)
	objectsRaw := fixture["objects"].(map[string]any)
	needed := map[string]bool{}
	for _, item := range events {
		payload := item.(map[string]any)["payload"].(map[string]any)
		for _, key := range []string{"input", "request"} {
			if ref, ok := payload[key].(map[string]any); ok {
				if sha, ok := ref["sha256"].(string); ok {
					needed[sha] = true
				}
			}
		}
		if list, ok := payload["objects"].([]any); ok {
			for _, item := range list {
				if ref, ok := item.(map[string]any); ok {
					if sha, ok := ref["sha256"].(string); ok {
						needed[sha] = true
					}
				}
			}
		}
	}
	var objects []any
	objectBytes := map[string][]byte{}
	for sha, v := range objectsRaw {
		if !needed[sha] {
			continue
		}
		b := []byte(v.(string))
		objectBytes[sha] = b
		objects = append(objects, map[string]any{"sha256": sha, "bytes": json.Number(fmt.Sprint(len(b)))})
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].(map[string]any)["sha256"].(string) < objects[j].(map[string]any)["sha256"].(string)
	})
	var prev any
	for i, v := range events {
		e := v.(map[string]any)
		e["turn_id"] = fixtureTurn
		e["seq"] = json.Number(fmt.Sprint(i))
		e["prev_hash"] = prev
		p := e["payload"].(map[string]any)
		if e["type"] == "evidence_ack" {
			target := events[i-1].(map[string]any)
			level := p["storage_level"].(string)
			parts := map[string]any{"tenant_id": e["tenant_id"], "turn_id": fixtureTurn, "seq": target["seq"], "event_hash": target["event_hash"], "backend": "postgres-append-only", "level": level}
			b, _ := evidence.Canonical(parts)
			p["receipt"] = evidence.SHA256(b)
			p["acked_seq"] = target["seq"]
			p["acked_event_hash"] = target["event_hash"]
		}
		h, err := evidence.EventHash(e)
		if err != nil {
			t.Fatal(err)
		}
		e["event_hash"] = h
		prev = h
	}
	// The evidence profile is an admission marker; later events intentionally omit it.
	for _, v := range events[1:] {
		delete(v.(map[string]any)["payload"].(map[string]any), "evidence_profile")
	}
	// Re-seal after removing any marker fields (the event hashes do not include those fields in the current fixture except seq/turn changes).
	prev = nil
	for _, v := range events {
		e := v.(map[string]any)
		e["prev_hash"] = prev
		h, err := evidence.EventHash(e)
		if err != nil {
			t.Fatal(err)
		}
		e["event_hash"] = h
		prev = h
	}
	// Update the receipt/ack fields against the final rewritten target event hashes and re-seal downstream.
	prev = nil
	for i, v := range events {
		e := v.(map[string]any)
		e["prev_hash"] = prev
		if e["type"] == "evidence_ack" {
			p := e["payload"].(map[string]any)
			target := events[i-1].(map[string]any)
			p["acked_event_hash"] = target["event_hash"]
			parts := map[string]any{"tenant_id": e["tenant_id"], "turn_id": fixtureTurn, "seq": target["seq"], "event_hash": target["event_hash"], "backend": "postgres-append-only", "level": p["storage_level"]}
			b, _ := evidence.Canonical(parts)
			p["receipt"] = evidence.SHA256(b)
		}
		h, err := evidence.EventHash(e)
		if err != nil {
			t.Fatal(err)
		}
		e["event_hash"] = h
		prev = h
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "events"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	var log []byte
	for _, v := range events {
		b, _ := evidence.Canonical(v)
		log = append(log, b...)
		log = append(log, '\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "events", fixtureTurn+".jsonl"), log, 0600); err != nil {
		t.Fatal(err)
	}
	for sha, b := range objectBytes {
		if err := os.WriteFile(filepath.Join(dir, "objects", sha[len("sha256:"):]), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	first := events[0].(map[string]any)
	scope := map[string]any{"tenant_id": first["tenant_id"], "project_id": first["project_id"], "matter_id": first["matter_id"], "custodian_ids": []any{first["actor"].(map[string]any)["id"]}, "window_start": "2026-01-15T00:00:00.000Z", "window_end": "2026-01-16T00:00:00.000Z"}
	snapshot := evidence.SHA256([]byte("fixture snapshot"))
	m := map[string]any{"schema_version": SchemaVersion, "profile": currentProfile, "export_id": fixtureTurn,
		"snapshot": map[string]any{"id": snapshot, "revision": "1", "captured_at": "2026-01-15T12:00:00.000Z", "hold_ids": []any{}},
		"scope":    scope, "custody": map[string]any{"requester_id": "records-a", "approver_id": "reviewer-b", "requested_at": "2026-01-15T12:00:00.000Z", "approved_at": "2026-01-15T12:00:00.000Z", "snapshot_id": snapshot},
		"turns":   []any{map[string]any{"turn_id": fixtureTurn, "custodian_id": first["actor"].(map[string]any)["id"], "recorded_at": first["recorded_at"], "hold_ids": []any{}, "event_path": "events/" + fixtureTurn + ".jsonl", "event_sha256": evidence.SHA256(log), "event_count": len(events), "end_sequence": len(events) - 1, "head_hash": prev, "partial": false, "missing_sequences": []any{}, "retained_versions": []any{}}},
		"objects": objects, "gaps": []any{}}

	b, err := evidence.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return dir, evidence.SHA256(b)
}
func alterManifest(t *testing.T, dir string, change func(map[string]any)) string {
	t.Helper()
	p := filepath.Join(dir, "manifest.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := evidence.ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	change(m)
	b, err = evidence.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	return evidence.SHA256(b)
}
