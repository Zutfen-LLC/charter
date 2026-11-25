package evidence

import (
	"fmt"
	"strings"
)

// Terminal event types (R3).
const (
	TypeTurnCompleted   = "turn_completed"
	TypeTurnInterrupted = "turn_interrupted"
)

func isTerminal(t string) bool { return t == TypeTurnCompleted || t == TypeTurnInterrupted }

// Verify is the independent verifier of ADR 0001 sections 6, 8 and 9 and
// versioning.md. It needs only the events (and, when objects != nil, the
// object bytes keyed by sha256). It returns every violation found; an empty
// result means the log verifies. It is deliberately written against generic
// maps, not against the recorder's types, so it checks what was stored.
func Verify(events []Event, objects map[string][]byte) []string {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	if len(events) == 0 {
		return []string{"empty log"}
	}
	var prev any // nil until the first event
	prevSet := false
	acked := map[int]bool{}
	var types []string
	first := events[0]
	for i, e := range events {
		typ := str(e, "type")
		types = append(types, typ)
		if v := str(e, "schema_version"); !strings.HasPrefix(v, "1.") {
			add("seq %d: unsupported schema_version %q", i, v)
		}
		for _, k := range []string{"tenant_id", "project_id", "matter_id", "turn_id"} {
			if str(e, k) != str(first, k) {
				add("seq %d: %s differs within the turn", i, k)
			}
		}
		if s, ok := integer(e["seq"]); !ok || s != int64(i) {
			add("seq %d: out of order", i)
		}
		pv, _ := e["prev_hash"].(string)
		if !prevSet {
			if e["prev_hash"] != nil {
				add("seq %d: broken chain", i)
			}
		} else if pv != prev {
			add("seq %d: broken chain", i)
		}
		h, err := EventHash(e)
		if err != nil || h != str(e, "event_hash") {
			add("seq %d: hash mismatch", i)
		}
		prev, prevSet = str(e, "event_hash"), true
		p := payload(e)
		switch typ {
		case "evidence_ack":
			a, ok := integer(p["acked_seq"])
			if !ok || a < 0 || a >= int64(i) || str(events[a], "event_hash") != p["acked_event_hash"] {
				add("seq %d: ack does not match event", i)
			} else {
				for j := 0; j <= int(a); j++ {
					acked[j] = true
				}
			}
		case "policy_decision":
			if d := p["decision"]; d != "allow" && d != "deny" {
				add("seq %d: policy_decision must be allow or deny", i)
			}
		case "provider_accepted":
			if j := last(events[:i], "disclosure_intent"); j < 0 || !acked[j] {
				add("seq %d: R1 provider contacted before acked disclosure_intent", i)
			}
		case "response_released":
			j := last(events[:i], "output_recorded")
			if j < 0 || !acked[j] || payload(events[j])["complete"] != true {
				add("seq %d: R2 response released before acked complete output", i)
			}
		}
		switch typ {
		case "context_sealed", "disclosure_intent", "provider_accepted", "response_released":
			j := last(events[:i], "policy_decision")
			if j < 0 || payload(events[j])["decision"] != "allow" {
				add("seq %d: R4 %s without a preceding allow policy_decision", i, typ)
			}
		}
	}
	var terms []int
	for i, t := range types {
		if isTerminal(t) {
			terms = append(terms, i)
		}
	}
	if len(terms) != 1 || terms[0] != len(events)-1 {
		add("R3: exactly one terminal event, last")
	}
	if contains(types, "response_released") && types[len(types)-1] != TypeTurnCompleted {
		add("R3: response released in a turn that did not complete")
	}
	// The intent must name the exact request bytes that were sealed.
	if si, ii := last(events, "context_sealed"), last(events, "disclosure_intent"); si >= 0 && ii >= 0 {
		req, _ := payload(events[ii])["request"].(map[string]any)
		if req["sha256"] != payload(events[si])["request_sha256"] {
			add("seq %d: disclosure_intent request does not match the sealed request", ii)
		}
	}
	if objects != nil {
		for i, e := range events {
			for _, ref := range objectRefs(e) {
				data, ok := objects[ref]
				switch {
				case !ok:
					add("seq %d: missing object %s", i, ref)
				case SHA256(data) != ref:
					add("seq %d: changed object %s", i, ref)
				}
			}
		}
	}
	return errs
}

// objectRefs lists every object an event references: payload.objects, the
// intent's request, and the sealed request hash.
func objectRefs(e Event) []string {
	p := payload(e)
	var out []string
	if l, ok := p["objects"].([]any); ok {
		for _, o := range l {
			if m, ok := o.(map[string]any); ok {
				if s, ok := m["sha256"].(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	if m, ok := p["request"].(map[string]any); ok {
		if s, ok := m["sha256"].(string); ok {
			out = append(out, s)
		}
	}
	if s, ok := p["request_sha256"].(string); ok {
		out = append(out, s)
	}
	return out
}

func last(events []Event, typ string) int {
	for i := len(events) - 1; i >= 0; i-- {
		if str(events[i], "type") == typ {
			return i
		}
	}
	return -1
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Disclosure values derived from the log (ADR 0001 section 9). They are never
// stored separately.
const (
	DisclosureNone      = "none"
	DisclosureUnknown   = "unknown"
	DisclosureDisclosed = "disclosed"
)

// DeriveDisclosure computes the disclosure state from the log alone.
func DeriveDisclosure(events []Event) string {
	acked := map[int]bool{}
	for _, e := range events {
		if str(e, "type") == "evidence_ack" {
			if a, ok := integer(payload(e)["acked_seq"]); ok {
				for j := 0; j <= int(a) && j < len(events); j++ {
					acked[j] = true
				}
			}
		}
	}
	intent := false
	for i, e := range events {
		switch str(e, "type") {
		case "provider_accepted":
			return DisclosureDisclosed
		case "disclosure_intent":
			if acked[i] {
				intent = true
			}
		}
	}
	if intent {
		return DisclosureUnknown
	}
	return DisclosureNone
}
