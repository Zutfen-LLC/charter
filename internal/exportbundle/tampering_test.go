package exportbundle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

func TestExportTamperingAgainstTrustedAnchor(t *testing.T) {
	eventPath := "events/" + fixtureTurn + ".jsonl"
	dir, anchor := makeCurrentBundle(t)
	good := readBundleMembers(t, dir)
	if got, err := VerifyMembers(good, currentProfile, anchor); err != nil || got.Status != Complete {
		t.Fatalf("positive fixture did not verify: %v %v", got, err)
	}
	object := ""
	for p, b := range good {
		if len(b) > 0 && filepath.Dir(p) == "objects" {
			object = p
			break
		}
	}
	if object == "" {
		t.Fatal("need nonempty object for byte mutations")
	}
	flip := func(b []byte) []byte { b = bytes.Clone(b); b[0] ^= 1; return b }
	cases := []struct {
		name string
		edit func(map[string][]byte)
	}{
		{"missing_manifest", func(m map[string][]byte) { delete(m, "manifest.json") }},
		{"missing_object", func(m map[string][]byte) { delete(m, object) }},
		{"missing_event_log", func(m map[string][]byte) { delete(m, eventPath) }},
		{"modified_object", func(m map[string][]byte) { m[object] = flip(m[object]) }},
		{"modified_event", func(m map[string][]byte) { m[eventPath] = flip(m[eventPath]) }},
		{"truncated_event_log", func(m map[string][]byte) { m[eventPath] = m[eventPath][:len(m[eventPath])-2] }},
		{"missing_event_suffix", func(m map[string][]byte) {
			b := m[eventPath]
			m[eventPath] = b[:bytes.LastIndexByte(b[:len(b)-1], '\n')+1]
		}},
		{"reordered_events", func(m map[string][]byte) {
			a := bytes.Split(m[eventPath], []byte{'\n'})
			a[0], a[1] = a[1], a[0]
			m[eventPath] = bytes.Join(a, []byte{'\n'})
		}},
		{"substituted_event_log", func(m map[string][]byte) { m[eventPath] = []byte("{\"seq\":0}\n") }},
		{"undeclared_member", func(m map[string][]byte) { m["extra.json"] = nil }},
		{"absolute_path", func(m map[string][]byte) { m["/extra.json"] = nil }},
		{"traversal", func(m map[string][]byte) { m["events/../extra.json"] = nil }},
		{"case_alias", func(m map[string][]byte) { m["MANIFEST.JSON"] = m["manifest.json"] }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			members := make(map[string][]byte, len(good)+1)
			for p, b := range good {
				members[p] = b
			}
			tc.edit(members)
			if _, err := VerifyMembers(members, currentProfile, anchor); err == nil {
				t.Fatal("tampered member census or content was accepted")
			}
		})
	}
}

func TestExportTrustedDigestDoesNotWaiveManifestParsing(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"malformed", []byte(`{"scope":`)},
		{"duplicate_key", []byte(`{"schema_version":"same","schema_version":"same"}`)},
		{"overdeep", bytes.Repeat([]byte{'['}, 1000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := makeCurrentBundle(t)
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Verify(dir, currentProfile, evidence.SHA256(tc.data))
			var v *Failure
			if !errors.As(err, &v) || v.Kind != "integrity" {
				t.Fatalf("expected parse/integrity rejection, got %v", err)
			}
		})
	}
}
