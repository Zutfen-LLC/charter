package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

type goldenFile struct {
	Events  []json.RawMessage `json:"events"`
	Objects map[string]string `json:"objects"`
}

func loadGolden(t *testing.T, name string) ([]Event, map[string][]byte) {
	t.Helper()
	var f goldenFile
	if err := json.Unmarshal(fixture(t, name), &f); err != nil {
		t.Fatal(err)
	}
	var evs []Event
	for _, r := range f.Events {
		e, err := ParseEvent(r)
		if err != nil {
			t.Fatal(err)
		}
		evs = append(evs, e)
	}
	objs := map[string][]byte{}
	for h, s := range f.Objects {
		objs[h] = []byte(s)
	}
	return evs, objs
}

// The Go verifier accepts every golden log produced by the Python reference
// model, reproducing each event hash exactly: this is the cross-language
// proof that the two implementations canonicalize identically.
func TestGoldenFixturesVerifyInGo(t *testing.T) {
	want := map[string]string{
		"complete-turn.json":           DisclosureDisclosed,
		"interrupted-mid-stream.json":  DisclosureDisclosed,
		"unknown-disclosure.json":      DisclosureUnknown,
		"crash-before-intent-ack.json": DisclosureNone,
	}
	for name, disc := range want {
		evs, objs := loadGolden(t, name)
		if errs := Verify(evs, objs); len(errs) != 0 {
			t.Errorf("%s: %v", name, errs)
		}
		if got := DeriveDisclosure(evs); got != disc {
			t.Errorf("%s: disclosure %s want %s", name, got, disc)
		}
	}
}

func TestVerifierRejectsTampering(t *testing.T) {
	has := func(errs []string, sub string) bool {
		for _, e := range errs {
			if strings.Contains(e, sub) {
				return true
			}
		}
		return false
	}
	t.Run("changed payload", func(t *testing.T) {
		evs, objs := loadGolden(t, "complete-turn.json")
		payload(evs[1])["route"] = "elsewhere"
		if !has(Verify(evs, objs), "hash mismatch") {
			t.Fatal("tamper not detected")
		}
	})
	t.Run("dropped event", func(t *testing.T) {
		evs, objs := loadGolden(t, "complete-turn.json")
		evs = append(evs[:2:2], evs[3:]...)
		if len(Verify(evs, objs)) == 0 {
			t.Fatal("tamper not detected")
		}
	})
	t.Run("changed object", func(t *testing.T) {
		evs, objs := loadGolden(t, "complete-turn.json")
		for h := range objs {
			objs[h] = append(objs[h], '!')
		}
		if !has(Verify(evs, objs), "changed object") {
			t.Fatal("changed bytes not detected")
		}
	})
	t.Run("missing object", func(t *testing.T) {
		evs, _ := loadGolden(t, "complete-turn.json")
		if !has(Verify(evs, map[string][]byte{}), "missing object") {
			t.Fatal("missing object not detected")
		}
	})
	t.Run("R1 provider before acked intent", func(t *testing.T) {
		evs, _ := loadGolden(t, "complete-turn.json")
		// Remove the ack (seq 5) and re-chain so only R1 is violated.
		evs = rechain(t, append(evs[:5:5], evs[6:]...))
		if !has(Verify(evs, nil), "R1") {
			t.Fatal("R1 violation not detected")
		}
	})
	t.Run("R2 release before acked output", func(t *testing.T) {
		evs, _ := loadGolden(t, "complete-turn.json")
		evs = rechain(t, append(evs[:8:8], evs[9:]...)) // drop the output ack
		if !has(Verify(evs, nil), "R2") {
			t.Fatal("R2 violation not detected")
		}
	})
}

// rechain renumbers and re-hashes so that a test isolates one rule.
func rechain(t *testing.T, evs []Event) []Event {
	t.Helper()
	oldToNew := map[any]any{}
	var prev any
	for i, e := range evs {
		old := e["event_hash"]
		e["seq"], e["prev_hash"] = i, prev
		if str(e, "type") == "evidence_ack" {
			p := payload(e)
			a, _ := integer(p["acked_seq"])
			if int(a) >= i {
				a = int64(i - 1)
			}
			p["acked_seq"], p["acked_event_hash"] = int(a), evs[a]["event_hash"]
		}
		if err := Seal(e); err != nil {
			t.Fatal(err)
		}
		oldToNew[old] = e["event_hash"]
		prev = e["event_hash"]
	}
	return evs
}
