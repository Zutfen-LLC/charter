package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCurrentProfileFixtureSemantics(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "contracts", "current-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string            `json:"name"`
		Expect  string            `json:"expect_code"`
		Events  []json.RawMessage `json:"events"`
		Objects map[string]string `json:"objects"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) != 20 {
		t.Fatalf("fixture census: %d %v", len(cases), err)
	}
	for _, f := range cases {
		t.Run(f.Name, func(t *testing.T) {
			var events []Event
			for i, b := range f.Events {
				e, err := ParseEvent(b)
				if err != nil {
					t.Fatal(err)
				}
				h, err := EventHash(e)
				if err != nil || h != str(e, "event_hash") || (i > 0 && e["prev_hash"] != events[i-1]["event_hash"]) {
					t.Fatalf("fixture is not rehashed at %d: %v", i, err)
				}
				events = append(events, e)
			}
			objs := map[string][]byte{}
			for sha, s := range f.Objects {
				objs[sha] = []byte(s)
			}
			errs := Verify(events, objs)
			if f.Expect == "" {
				if len(errs) > 0 {
					t.Fatalf("positive current profile: %v", errs)
				}
			} else if !strings.Contains(strings.Join(errs, "\n"), "["+f.Expect+"]") {
				t.Fatalf("want [%s], got %v", f.Expect, errs)
			}
		})
	}
}
