package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestC06VerifierRejectsOrphanProvenanceAndBoundTurnsWithoutExternalSource(t *testing.T) {
	events, objects := loadGolden(t, "complete-turn.json")
	payload(events[0])["source_provenance_sha256"] = SHA256([]byte("orphan"))
	errs := Verify(rechain(t, events), objects)
	if !strings.Contains(strings.Join(errs, "\n"), "[C06] orphan source provenance marker") {
		t.Fatalf("orphan provenance marker accepted: %v", errs)
	}

	events, objects = loadGolden(t, "complete-turn.json")
	payload(events[0])["source_binding_version"] = 1
	errs = Verify(rechain(t, events), objects)
	if !strings.Contains(strings.Join(errs, "\n"), "[C06]") {
		t.Fatalf("C06 turn without external source accepted: %v", errs)
	}
}

func TestC06VerifierKeepsLegacyTurnsValid(t *testing.T) {
	events, objects := loadGolden(t, "complete-turn.json")
	if errs := Verify(events, objects); len(errs) != 0 {
		t.Fatalf("legacy turn changed: %v", errs)
	}
}

func TestC06CrossLanguageBindings(t *testing.T) {
	var fixtures []struct {
		goldenFile
		Name, Diagnostic string
	}
	if err := json.Unmarshal(fixture(t, "c06-source-bindings.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			var evs []Event
			for _, raw := range f.Events {
				ev, err := ParseEvent(raw)
				if err != nil {
					t.Fatal(err)
				}
				evs = append(evs, ev)
			}
			objs := map[string][]byte{}
			for h, s := range f.Objects {
				objs[h] = []byte(s)
			}
			errs := VerifyCurrentFull(evs, objs)
			if f.Diagnostic == "" {
				if len(errs) != 0 {
					t.Fatal(errs)
				}
				return
			}
			for _, e := range errs {
				if !strings.Contains(e, "[C06]") {
					t.Fatalf("fixture failed unrelated validation: %v", errs)
				}
			}
			if !strings.Contains(strings.Join(errs, "\n"), f.Diagnostic) {
				t.Fatalf("expected %q: %v", f.Diagnostic, errs)
			}
		})
	}
}
