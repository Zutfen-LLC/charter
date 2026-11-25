package evidence

import (
	"strings"
	"testing"
)

func eventIndex(e []Event, typ string) int { return last(e, typ) }

func TestVerifierProfileControls(t *testing.T) {
	cases := []struct {
		name, fixture, want string
		edit                func([]Event)
	}{
		{"ack requires receipt", "complete-turn.json", "receipt", func(e []Event) { delete(payload(e[eventIndex(e, "evidence_ack")]), "receipt") }},
		{"ack receipt is nonempty", "complete-turn.json", "receipt", func(e []Event) { payload(e[eventIndex(e, "evidence_ack")])["receipt"] = "" }},
		{"destination agrees with intent", "complete-turn.json", "destination", func(e []Event) {
			payload(e[1])["destination"] = map[string]any{"provider": "test-a", "endpoint_id": "ep-1", "model_id": "test-model"}
			payload(e[eventIndex(e, "disclosure_intent")])["provider"] = "other"
		}},
		{"destination agrees with provider acceptance", "complete-turn.json", "destination", func(e []Event) { payload(e[eventIndex(e, "provider_accepted")])["endpoint_id"] = "other" }},
		{"settlement precedes successful completion", "complete-turn.json", "usage_settled", func(e []Event) { i := eventIndex(e, "usage_settled"); e[i], e[i+1] = e[i+1], e[i] }},
		{"unknown disclosure settles reservation", "unknown-disclosure.json", "reserved", func(e []Event) { payload(e[eventIndex(e, "usage_settled")])["units"] = 1 }},
		{"first actor is user", "complete-turn.json", "actor", func(e []Event) { e[0]["actor"] = map[string]any{"kind": "service", "id": "charter-control-plane"} }},
		{"recovery actor is service", "unknown-disclosure.json", "actor", func(e []Event) {
			i := eventIndex(e, TypeTurnInterrupted)
			e[i]["actor"] = map[string]any{"kind": "user", "id": "u-custodian-1"}
		}},
		{"legacy summary cannot assert exact input", "complete-turn.json", "legacy", func(e []Event) { payload(e[0])["input_summary"] = "exact input: synthetic prompt" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, o := loadGolden(t, tc.fixture)
			tc.edit(e)
			e = rechain(t, e)
			errs := Verify(e, o)
			if !strings.Contains(strings.Join(errs, "\n"), tc.want) {
				t.Fatalf("expected %q in semantic errors; got %v", tc.want, errs)
			}
		})
	}
}
