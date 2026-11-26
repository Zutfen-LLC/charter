package evidence

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Terminal event types (R3).
const (
	TypeTurnCompleted   = "turn_completed"
	TypeTurnInterrupted = "turn_interrupted"
)

func isTerminal(t string) bool { return t == TypeTurnCompleted || t == TypeTurnInterrupted }

// Verification error codes. Every error string is "seq N: [CODE] text" (or
// "[CODE] text" for whole-log rules); the negative fixtures in
// fixtures/contracts/negative pin the code each violation must produce, in
// both this verifier and the Python reference.
const (
	CodeEnvelope   = "ENVELOPE"
	CodeChain      = "CHAIN"
	CodeLifecycle  = "LIFECYCLE"
	CodePolicy     = "POLICY"
	CodeRefs       = "REFS"
	CodeDisclosure = "DISCLOSURE"
	CodeObject     = "OBJECT"
	CodeLength     = "LENGTH"
)

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	semverRe  = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	tsRe      = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
	shaRe     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	typeRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	receiptRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)
)

type vref struct {
	sha   string
	bytes int64
}

func asObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

// asRef parses {"sha256": "sha256:<hex>", "bytes": <int >= 0>}.
func asRef(v any) (vref, bool) {
	m, ok := asObj(v)
	if !ok {
		return vref{}, false
	}
	s, ok := m["sha256"].(string)
	n, ok2 := integer(m["bytes"])
	if !ok || !ok2 || !shaRe.MatchString(s) || n < 0 {
		return vref{}, false
	}
	return vref{s, n}, true
}

func asRefList(v any) ([]vref, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]vref, 0, len(l))
	for _, x := range l {
		r, ok := asRef(x)
		if !ok {
			return nil, false
		}
		out = append(out, r)
	}
	return out, true
}

// VerifyStructure checks everything that needs only the event log: envelope,
// hashes, chain, lifecycle, gates R1-R4, mandatory references and their
// internal consistency, and recorded-versus-derived disclosure. It does NOT
// look at object bytes, so a log that passes may still be missing or have
// altered objects; use VerifyFull for that.
func VerifyStructure(events []Event) []string { return verify(events, nil, false) }

// VerifyFull verifies every declared object in addition to VerifyStructure. A
// legacy log with only input_summary can pass this compatibility check; it does
// not prove the exact bytes of an original input. Use VerifyCurrentFull to
// require the current evidence profile. objects must be
// non-nil (an empty map means "no objects available", so every reference is
// reported missing).
func VerifyFull(events []Event, objects map[string][]byte) []string {
	if objects == nil {
		return []string{"[OBJECT] VerifyFull needs the object set; use VerifyStructure for a structural-only check"}
	}
	return verify(events, objects, true)
}

// Verify keeps the original signature: objects == nil means structural-only
// verification, anything else is full verification.
func Verify(events []Event, objects map[string][]byte) []string {
	if objects == nil {
		return VerifyStructure(events)
	}
	return VerifyFull(events, objects)
}

// VerifyCurrentFull requires the current profile, exact input and every
// object. Callers verifying current evidence must explicitly select this entry
// point, rather than delegating profile expectations to an untrusted export.
func VerifyCurrentFull(events []Event, objects map[string][]byte) []string {
	if len(events) == 0 || str(payload(events[0]), "evidence_profile") != CurrentProfile {
		return []string{"[ENVELOPE] current evidence profile is required"}
	}
	return VerifyFull(events, objects)
}

func verify(events []Event, objects map[string][]byte, full bool) (errs []string) {
	defer func() {
		// Malformed input must produce verification errors, never a crash.
		if r := recover(); r != nil {
			errs = append(errs, fmt.Sprintf("[%s] malformed input (internal check failed: %v)", CodeEnvelope, r))
		}
	}()
	add := func(i int, code, f string, a ...any) {
		p := ""
		if i >= 0 {
			p = fmt.Sprintf("seq %d: ", i)
		}
		errs = append(errs, fmt.Sprintf("%s[%s] %s", p, code, fmt.Sprintf(f, a...)))
	}
	if len(events) == 0 {
		return []string{"[" + CodeEnvelope + "] empty log"}
	}
	first := events[0]
	profile, hasProfile := payload(first)["evidence_profile"]
	current := profile == CurrentProfile
	if hasProfile && !current {
		add(0, CodeEnvelope, "unknown evidence profile")
	}
	acked := map[int]bool{}
	var sealedObjs map[string]int64 // object refs declared by context_sealed
	var sealedReq string
	var types []string
	state := "start"
	released, decided, denied := false, false, false
	declared := map[string]int64{} // sha -> declared length, to catch contradictions
	var reservedUnits int64
	var hasReservation bool
	var policyDestination, intentDestination map[string]any

	for i, e := range events {
		typ, _ := e["type"].(string)
		types = append(types, typ)
		envelope(i, e, first, add)
		// chain and hash
		if s, ok := integer(e["seq"]); !ok || s != int64(i) {
			add(i, CodeChain, "seq out of order")
		}
		if i == 0 {
			if e["prev_hash"] != nil {
				add(i, CodeChain, "first event must have a null prev_hash")
			}
		} else if ph, _ := e["prev_hash"].(string); ph != str(events[i-1], "event_hash") {
			add(i, CodeChain, "broken chain")
		}
		if h, err := EventHash(e); err != nil || h != str(e, "event_hash") {
			add(i, CodeChain, "hash mismatch")
		}
		if a, ok := asObj(e["actor"]); ok {
			kind, _ := a["kind"].(string)
			want := "service"
			if i == 0 {
				want = "user"
			}
			if kind != want {
				add(i, CodeEnvelope, "actor.kind must be %s for this event", want)
			}
		}
		p, pok := asObj(e["payload"])
		if !pok {
			p = map[string]any{}
		}
		// declared references of every kind, for length consistency
		for _, r := range eventRefs(e) {
			if old, seen := declared[r.sha]; seen && old != r.bytes {
				add(i, CodeLength, "object %s declared with different lengths (%d and %d)", r.sha, old, r.bytes)
			}
			declared[r.sha] = r.bytes
		}

		isMinorUnknown := !knownType[typ]
		if i == 0 && typ != "turn_received" {
			add(i, CodeLifecycle, "the first event must be turn_received")
		}
		if i > 0 && typ == "turn_received" {
			add(i, CodeLifecycle, "turn_received may appear only once, at seq 0")
		}
		if current {
			checkCurrentEvent(events, i, typ, p, add)
		}
		switch typ {
		case "turn_received":
			if in, ok := p["input"]; ok {
				if _, ok := asRef(in); !ok {
					add(i, CodeRefs, "input must be a {sha256, bytes} reference")
				}
			} else if _, ok := p["input_summary"].(string); !ok {
				add(i, CodeRefs, "turn_received needs an input reference (or a legacy input_summary)")
			}
		case "policy_decision":
			d, _ := p["decision"].(string)
			if d == "allow" {
				policyDestination, _ = asObj(p["destination"])
				if v, exists := p["destination"]; exists && (policyDestination == nil || !destinationFieldsWellFormed(v)) {
					add(i, CodeRefs, "policy destination has invalid identifiers")
				}
				if policyDestination != nil && !destinationEqual(p, policyDestination) {
					add(i, CodeRefs, "policy destination conflicts with its corresponding identifiers")
				}
			}
			switch {
			case d != "allow" && d != "deny":
				add(i, CodePolicy, "decision must be allow or deny")
			case i != 1:
				add(i, CodePolicy, "the policy decision must be seq 1")
			}
			if decided {
				add(i, CodePolicy, "repeated policy decision")
			}
			decided, denied = true, d == "deny"
		case "usage_reserved":
			if n, ok := integer(p["units"]); !ok || n < 0 {
				add(i, CodeRefs, "usage_reserved.units must be a non-negative integer")
			} else {
				reservedUnits, hasReservation = n, true
			}
		case "context_sealed":
			sealedObjs = map[string]int64{}
			objs, ok := asRefList(p["objects"])
			if !ok || len(objs) == 0 {
				add(i, CodeRefs, "context_sealed.objects must be a non-empty list of {sha256, bytes}")
			}
			for _, o := range objs {
				sealedObjs[o.sha] = o.bytes
			}
			sealedReq, _ = p["request_sha256"].(string)
			if !shaRe.MatchString(sealedReq) {
				add(i, CodeRefs, "request_sha256 missing or malformed")
			} else if _, ok := sealedObjs[sealedReq]; !ok {
				add(i, CodeRefs, "request_sha256 is not among the sealed objects")
			}
			srcs, ok := p["sources"].([]any)
			if !ok {
				add(i, CodeRefs, "context_sealed.sources must be a list")
			}
			for _, sx := range srcs {
				sm, ok := asObj(sx)
				sid, _ := sm["source_id"].(string)
				ver, vok := integer(sm["version"])
				sh, _ := sm["sha256"].(string)
				if !ok || sid == "" || !vok || ver < 0 || !shaRe.MatchString(sh) {
					add(i, CodeRefs, "malformed source reference")
				} else if _, in := sealedObjs[sh]; !in {
					add(i, CodeRefs, "source %s sha256 is not among the sealed objects", sid)
				}
			}
		case "disclosure_intent":
			intentDestination = p
			if !destinationFieldsWellFormed(p) {
				add(i, CodeRefs, "disclosure intent has invalid destination identifiers")
			}
			if policyDestination != nil && !destinationEqual(policyDestination, intentDestination) {
				add(i, CodeRefs, "disclosure intent destination differs from policy destination")
			}
			rq, ok := asRef(p["request"])
			if !ok {
				add(i, CodeRefs, "disclosure_intent.request must be a {sha256, bytes} reference")
			} else {
				if sealedReq == "" {
					add(i, CodeRefs, "disclosure_intent without a sealed request")
				} else if rq.sha != sealedReq {
					add(i, CodeRefs, "disclosure_intent request does not match the sealed request")
				} else if n, ok := sealedObjs[rq.sha]; ok && n != rq.bytes {
					add(i, CodeLength, "disclosure_intent request length differs from the sealed object length")
				}
			}
			for _, k := range []string{"provider", "endpoint_id"} {
				if s, _ := p[k].(string); s == "" {
					add(i, CodeRefs, "disclosure_intent.%s is required", k)
				}
			}
		case "evidence_ack":
			receipt, ok := p["receipt"].(string)
			if !ok || !receiptRe.MatchString(receipt) {
				add(i, CodeRefs, "evidence_ack.receipt is required and must be a valid identifier")
			}
			level, hasLevel := p["storage_level"]
			if (current || hasLevel) && level != postgresDurableLevel {
				add(i, CodeRefs, "evidence_ack.storage_level must identify a supported durable storage class")
			}
			a, ok := integer(p["acked_seq"])
			h, _ := p["acked_event_hash"].(string)
			if !ok || a < 0 || a >= int64(i) || h == "" || str(events[a], "event_hash") != h {
				add(i, CodeRefs, "ack does not match event")
			} else {
				if level == postgresDurableLevel && receipt != eventReceipt(postgresDurableLevel, events[a]).ID {
					add(i, CodeRefs, "evidence_ack receipt does not bind the storage level and target event")
				}
				target := str(events[a], "type")
				if current && (a != int64(i-1) || (target != "disclosure_intent" && target != "output_recorded")) {
					add(i, CodeRefs, "current evidence_ack must target its immediately preceding intent or output event")
				}
				for j := 0; j <= int(a); j++ {
					acked[j] = true
				}
			}
		case "provider_accepted":
			if !destinationFieldsWellFormed(p) {
				add(i, CodeRefs, "provider acceptance has invalid destination identifiers")
			}
			if intentDestination != nil && !destinationEqual(intentDestination, p) {
				add(i, CodeRefs, "provider acceptance destination differs from disclosure intent")
			}
			if j := last(events[:i], "disclosure_intent"); j < 0 || !acked[j] {
				add(i, "R1", "provider contacted before acked disclosure_intent")
			}
		case "output_recorded":
			if j := last(events[:i], "disclosure_intent"); j < 0 || !acked[j] {
				add(i, "R1", "output recorded without acknowledged disclosure intent")
			}
			if _, ok := p["complete"].(bool); !ok {
				add(i, CodeRefs, "output_recorded.complete must be a boolean")
			}
			if o, ok := asRefList(p["objects"]); !ok || len(o) != 1 {
				add(i, CodeRefs, "output_recorded.objects must be exactly one {sha256, bytes} reference")
			}
		case "response_released":
			j := last(events[:i], "output_recorded")
			if j < 0 || !acked[j] || payload(events[j])["complete"] != true {
				add(i, "R2", "response released before acked complete output")
			}
			released = true
		case "usage_settled":
			basis := str(p, "basis")
			if n, ok := integer(p["units"]); !ok || n < 0 {
				add(i, CodeRefs, "usage_settled.units must be a non-negative integer")
			} else if basis == "reserved_max" && (!hasReservation || n != reservedUnits) {
				add(i, CodeRefs, "usage_settled reserved_max units must equal the full reservation")
			}
			if basis != "reserved_max" && basis != "provider_reported" {
				add(i, CodeRefs, "usage_settled.basis must be provider_reported or reserved_max")
			}
			if DeriveDisclosure(events[:i]) == DisclosureUnknown && basis != "reserved_max" {
				add(i, CodeRefs, "unknown disclosure must use reserved_max settlement")
			}
		case TypeTurnCompleted:
			if p["outcome"] == "completed" && last(events[:i], "usage_settled") < 0 {
				add(i, CodeLifecycle, "successful completion requires usage_settled")
			}
			switch o, _ := p["outcome"].(string); {
			case o == "completed" && !released:
				add(i, CodeLifecycle, "turn_completed(completed) without a recorded release")
			case o == "denied" && !denied:
				add(i, CodeLifecycle, "turn_completed(denied) without a deny decision")
			case o != "completed" && o != "denied":
				add(i, CodeRefs, "turn_completed.outcome must be completed or denied")
			}
		case TypeTurnInterrupted:
			if r, _ := p["reason"].(string); r == "" {
				add(i, CodeRefs, "turn_interrupted.reason is required")
			}
			dv, _ := p["disclosure"].(string)
			if dv != DisclosureNone && dv != DisclosureUnknown && dv != DisclosureDisclosed {
				add(i, CodeRefs, "turn_interrupted.disclosure must be none, unknown or disclosed")
			} else if want := DeriveDisclosure(events[:i]); dv != want {
				add(i, CodeDisclosure, "recorded disclosure %q but the log derives %q", dv, want)
			}
			if DeriveDisclosure(events[:i]) == DisclosureUnknown && last(events[:i], "usage_settled") < 0 {
				add(i, CodeLifecycle, "unknown disclosure must settle the full reservation before interruption")
			}
			if released {
				add(i, "R3", "a turn with a recorded release cannot end interrupted")
			}
		}
		// R4: an allow decision must precede everything that discloses.
		switch typ {
		case "context_sealed", "disclosure_intent", "provider_accepted", "response_released":
			j := last(events[:i], "policy_decision")
			if j < 0 || payload(events[j])["decision"] != "allow" {
				add(i, "R4", "%s without a preceding allow policy_decision", typ)
			}
		}
		// lifecycle (evidence_ack and unknown MINOR types do not move the state)
		if typ != "evidence_ack" && !isMinorUnknown {
			next := transition(state, typ, p, denied, released)
			if next == "" {
				add(i, CodeLifecycle, "%s is not allowed after %s", typ, state)
			} else {
				state = next
			}
		}
	}
	terms := 0
	termAt := -1
	for i, t := range types {
		if isTerminal(t) {
			terms++
			termAt = i
		}
	}
	if terms != 1 || termAt != len(events)-1 {
		add(-1, "R3", "exactly one terminal event, last")
	}
	if contains(types, "response_released") && types[len(types)-1] != TypeTurnCompleted {
		add(-1, "R3", "response released in a turn that did not complete")
	}
	if full {
		for _, r := range allRefs(events) {
			data, ok := objects[r.sha]
			switch {
			case !ok:
				add(-1, CodeObject, "missing object %s", r.sha)
			case SHA256(data) != r.sha:
				add(-1, CodeObject, "changed object %s (digest mismatch)", r.sha)
			case int64(len(data)) != r.bytes:
				add(-1, CodeLength, "object %s is %d bytes but declared %d", r.sha, len(data), r.bytes)
			}
		}
	}
	return errs
}

var knownType = map[string]bool{"turn_received": true, "policy_decision": true, "usage_reserved": true,
	"context_sealed": true, "disclosure_intent": true, "evidence_ack": true, "provider_accepted": true,
	"output_recorded": true, "response_released": true, "usage_settled": true, TypeTurnCompleted: true,
	TypeTurnInterrupted: true, "outcome_resolved": true}

// transition is the lifecycle of docs/contracts/state-machines.md. It returns
// the next state, or "" if typ is not allowed in state. outcome_resolved is a
// post-hoc append that is only legal after the terminal event; that rule is
// enforced elsewhere (exports), so here it is simply not in the main flow.
func transition(state, typ string, p map[string]any, denied, released bool) string {
	if typ == TypeTurnInterrupted {
		// Allowed from any non-terminal state before a release was recorded.
		switch state {
		case "start", "denied", "released", "settled_released", "terminal":
			return ""
		}
		return "terminal"
	}
	switch state {
	case "start":
		if typ == "turn_received" {
			return "received"
		}
	case "received":
		if typ == "policy_decision" {
			if p["decision"] == "deny" {
				return "denied"
			}
			return "decided"
		}
	case "denied":
		if typ == TypeTurnCompleted {
			return "terminal"
		}
	case "decided":
		return pick(typ, "usage_reserved", "reserved")
	case "reserved":
		return pick(typ, "context_sealed", "sealed")
	case "sealed":
		return pick(typ, "disclosure_intent", "intent")
	case "intent":
		if typ == "output_recorded" && p["complete"] == false {
			return "output_unconfirmed"
		}
		return pick(typ, "provider_accepted", "accepted", "usage_settled", "settled")
	case "output_unconfirmed":
		return pick(typ, "usage_settled", "settled")
	case "accepted":
		return pick(typ, "output_recorded", "output", "usage_settled", "settled")
	case "output":
		return pick(typ, "response_released", "released", "usage_settled", "settled")
	case "released":
		return pick(typ, "usage_settled", "settled_released", TypeTurnCompleted, "terminal")
	case "settled_released":
		return pick(typ, TypeTurnCompleted, "terminal")
	}
	return ""
}

// pick maps (typ -> next) pairs. turn_interrupted is handled once, in
// transition, so that it is refused after a recorded release.
func pick(typ string, pairs ...string) string {
	for i := 0; i+1 < len(pairs); i += 2 {
		if typ == pairs[i] {
			return pairs[i+1]
		}
	}
	return ""
}

func envelope(i int, e, first Event, add func(int, string, string, ...any)) {
	if v, ok := e["schema_version"].(string); !ok || !semverRe.MatchString(v) {
		add(i, CodeEnvelope, "schema_version must be semantic-version text")
	} else if !strings.HasPrefix(v, "1.") {
		add(i, CodeEnvelope, "unsupported schema_version %q (this verifier handles major 1)", v)
	}
	for _, k := range []string{"tenant_id", "project_id", "matter_id", "turn_id"} {
		if v, ok := e[k].(string); !ok || !idRe.MatchString(v) {
			add(i, CodeEnvelope, "%s must be an opaque lowercase identifier", k)
		} else if v != str(first, k) {
			add(i, CodeEnvelope, "%s differs within the turn", k)
		}
	}
	if t, ok := e["type"].(string); !ok || !typeRe.MatchString(t) {
		add(i, CodeEnvelope, "type must be a lowercase identifier")
	}
	if _, ok := integer(e["seq"]); !ok {
		add(i, CodeEnvelope, "seq must be an integer")
	}
	if ts, ok := e["recorded_at"].(string); !ok || !tsRe.MatchString(ts) {
		add(i, CodeEnvelope, "recorded_at must be RFC 3339 UTC with milliseconds and Z")
	} else if _, err := time.Parse("2006-01-02T15:04:05.000Z", ts); err != nil {
		add(i, CodeEnvelope, "recorded_at is not a valid time")
	}
	if a, ok := asObj(e["actor"]); !ok {
		add(i, CodeEnvelope, "actor must be an object")
	} else {
		if k, _ := a["kind"].(string); k != "user" && k != "service" {
			add(i, CodeEnvelope, "actor.kind must be user or service")
		}
		if id, ok := a["id"].(string); !ok || !idRe.MatchString(id) {
			add(i, CodeEnvelope, "actor.id must be an opaque lowercase identifier")
		}
	}
	if _, ok := asObj(e["payload"]); !ok {
		add(i, CodeEnvelope, "payload must be an object")
	}
	if ph, present := e["prev_hash"]; !present {
		add(i, CodeEnvelope, "prev_hash is required (null for the first event)")
	} else if ph != nil {
		if s, ok := ph.(string); !ok || !shaRe.MatchString(s) {
			add(i, CodeEnvelope, "prev_hash must be null or sha256:<hex>")
		}
	}
	if s, ok := e["event_hash"].(string); !ok || !shaRe.MatchString(s) {
		add(i, CodeEnvelope, "event_hash must be sha256:<hex>")
	}
}

// eventRefs lists the well-formed object references an event declares.
func eventRefs(e Event) []vref {
	p := payload(e)
	var out []vref
	if l, ok := p["objects"].([]any); ok {
		for _, x := range l {
			if r, ok := asRef(x); ok {
				out = append(out, r)
			}
		}
	}
	for _, k := range []string{"request", "input"} {
		if r, ok := asRef(p[k]); ok {
			out = append(out, r)
		}
	}
	return out
}

func allRefs(events []Event) []vref {
	seen := map[vref]bool{}
	var out []vref
	for _, e := range events {
		refs := eventRefs(e)
		if s, ok := payload(e)["request_sha256"].(string); ok && shaRe.MatchString(s) {
			if n, ok := sealedLen(events, s); ok {
				refs = append(refs, vref{s, n})
			}
		}
		for _, r := range refs {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}

func sealedLen(events []Event, sha string) (int64, bool) {
	for _, e := range events {
		if l, ok := payload(e)["objects"].([]any); ok {
			for _, x := range l {
				if r, ok := asRef(x); ok && r.sha == sha {
					return r.bytes, true
				}
			}
		}
	}
	return 0, false
}

// objectRefs lists object hashes an event references (used to fetch them).
func objectRefs(e Event) []string {
	var out []string
	for _, r := range eventRefs(e) {
		out = append(out, r.sha)
	}
	if s, ok := payload(e)["request_sha256"].(string); ok && shaRe.MatchString(s) {
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

var destinationKeys = []string{"provider", "endpoint_id", "model_id"}

func destinationFieldsWellFormed(v any) bool {
	p, ok := asObj(v)
	if !ok {
		return false
	}
	for _, k := range destinationKeys {
		if v, exists := p[k]; exists {
			if name, ok := v.(string); !ok || strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
				return false
			}
		}
	}
	return true
}

func completeDestination(p map[string]any) bool {
	if p == nil || !destinationFieldsWellFormed(p) {
		return false
	}
	for _, k := range destinationKeys {
		if str(p, k) == "" {
			return false
		}
	}
	return true
}

func destinationEqual(a, b map[string]any) bool {
	for _, k := range destinationKeys {
		av, aok := a[k]
		bv, bok := b[k]
		if aok && bok {
			as, aok := av.(string)
			bs, bok := bv.(string)
			if !aok || !bok || as != bs {
				return false
			}
		}
	}
	return true
}

func checkCurrentEvent(events []Event, i int, typ string, p map[string]any, add func(int, string, string, ...any)) {
	switch typ {
	case "turn_received":
		_, summary := p["input_summary"]
		if _, ok := asRef(p["input"]); !ok || summary {
			add(i, CodeRefs, "current evidence requires exact input bytes, not a legacy summary")
		}
		custodian := str(p, "custodian_id")
		if custodian == "" || custodian != str(actorOf(events[i]), "id") {
			add(i, CodeEnvelope, "admission actor does not match the declared custodian")
		}
	case "policy_decision":
		if str(p, "decision") == "allow" {
			d, _ := asObj(p["destination"])
			if !completeDestination(d) || str(p, "route") != str(d, "endpoint_id") {
				add(i, CodeRefs, "policy must identify the actual provider, endpoint, and model, with its route matching the endpoint")
			}
		}
	case "disclosure_intent", "provider_accepted":
		if !completeDestination(p) {
			add(i, CodeRefs, "%s must identify the actual provider, endpoint and model", typ)
		}
	}
}

// DeriveDisclosure computes the disclosure state from the log alone. It is
// defensive against malformed events (it never panics).
func DeriveDisclosure(events []Event) string {
	acked := map[int]bool{}
	for i, e := range events {
		if str(e, "type") == "evidence_ack" {
			if a, ok := integer(payload(e)["acked_seq"]); ok && a >= 0 && a < int64(i) {
				for j := 0; j <= int(a); j++ {
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
