package evidence

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSharedRetainedProfileFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../fixtures/contracts/retained-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string            `json:"name"`
		Expect  string            `json:"expect_code"`
		Events  []json.RawMessage `json:"events"`
		Objects map[string]string `json:"objects"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil || len(cases) != 11 {
		t.Fatalf("fixture census: %d %v", len(cases), err)
	}
	for _, f := range cases {
		t.Run(f.Name, func(t *testing.T) {
			var events []Event
			var prev any
			for i, raw := range f.Events {
				e, err := ParseEvent(raw)
				if err != nil {
					t.Fatal(err)
				}
				h, err := EventHash(e)
				if err != nil || e["prev_hash"] != prev || e["event_hash"] != h {
					t.Fatalf("fixture not rehashed at %d", i)
				}
				prev = h
				events = append(events, e)
			}
			objs := map[string][]byte{}
			for k, v := range f.Objects {
				objs[k] = []byte(v)
			}
			errs := VerifyRetentionFull(events, objs)
			if f.Expect == "" {
				if len(errs) != 0 || len(VerifyStructure(events)) != 0 {
					t.Fatalf("valid retained receipt: %v", errs)
				}
				if len(VerifyRetentionFull(events, nil)) == 0 || len(VerifyCurrentFull(events, objs)) == 0 {
					t.Fatal("missing byte set or incorrect profile accepted")
				}
			}
			if f.Expect != "" && !strings.Contains(strings.Join(errs, "\n"), "["+f.Expect+"]") {
				t.Fatalf("expected %s: %v", f.Expect, errs)
			}
		})
	}
}
