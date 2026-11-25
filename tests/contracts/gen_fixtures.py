"""Generates the golden synthetic fixtures. Run: python3 tests/contracts/gen_fixtures.py"""
import json, os
from model import build_turn, canonical, sha256_bytes

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "contracts")
BASE = {"tenant_id": "t-0001", "project_id": "p-alpha", "matter_id": "m-0001", "turn_id": "turn-0001"}
USER = {"kind": "user", "id": "u-custodian-1"}
SVC = {"kind": "service", "id": "charter-control-plane"}

REQ = b'{"model":"test-model-a","messages":[{"role":"user","content":"Summarize SYNTHETIC-DOC-1 v2"}]}'
OUT_FULL = b"Synthetic summary of SYNTHETIC-DOC-1 v2."
OUT_PART = b"Synthetic summary of SYNTH"
SRC = b"SYNTHETIC-DOC-1 version 2 content"
OBJECTS = {sha256_bytes(b): b.decode() for b in (REQ, OUT_FULL, OUT_PART, SRC)}
ref = lambda b: {"sha256": sha256_bytes(b), "bytes": len(b)}
T = lambda s: f"2026-01-15T10:00:{s:02d}.000Z"


def head():
    return [
        ("turn_received", T(0), USER, {"input_summary": "synthetic prompt"}),
        ("policy_decision", T(1), SVC, {"decision": "allow", "route": "hosted-test-a", "policy_version": "pol-1"}),
        ("usage_reserved", T(2), SVC, {"units": 1000}),
        ("context_sealed", T(3), SVC, {"sources": [{"source_id": "doc-1", "version": 2, "sha256": sha256_bytes(SRC)}],
                                       "objects": [ref(SRC), ref(REQ)], "request_sha256": sha256_bytes(REQ)}),
        ("disclosure_intent", T(4), SVC, {"provider": "test-a", "endpoint_id": "ep-1", **{"request": ref(REQ)}}),
    ]


def ack(s, at):
    s.append(("evidence_ack", T(at), SVC, {"acked_seq": "@prev", "receipt": "synthetic-fsync-1"}))


def complete():
    s = head(); ack(s, 5)
    s.append(("provider_accepted", T(6), SVC, {"endpoint_id": "ep-1"}))
    s.append(("output_recorded", T(7), SVC, {"complete": True, "objects": [ref(OUT_FULL)]})); ack(s, 8)
    s.append(("response_released", T(9), SVC, {}))
    s.append(("usage_settled", T(10), SVC, {"units": 420, "basis": "provider_reported"}))
    s.append(("turn_completed", T(11), SVC, {"outcome": "completed"}))
    return s


def mid_stream():
    s = head(); ack(s, 5)
    s.append(("provider_accepted", T(6), SVC, {"endpoint_id": "ep-1"}))
    s.append(("output_recorded", T(7), SVC, {"complete": False, "objects": [ref(OUT_PART)]})); ack(s, 8)
    s.append(("usage_settled", T(9), SVC, {"units": 1000, "basis": "reserved_max"}))
    s.append(("turn_interrupted", T(10), SVC, {"reason": "provider_stream_error", "disclosure": "disclosed"}))
    return s


def unknown():
    s = head(); ack(s, 5)
    s.append(("usage_settled", T(6), SVC, {"units": 1000, "basis": "reserved_max"}))
    s.append(("turn_interrupted", T(7), SVC, {"reason": "crash_recovery", "disclosure": "unknown"}))
    return s


def pre_ack_crash():
    s = head()
    s.append(("turn_interrupted", T(5), SVC, {"reason": "crash_recovery", "disclosure": "none"}))
    return s


def write(name, obj):
    path = os.path.join(OUT, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True); f.write("\n")


def mutate_steps(steps, edit):
    """Copy steps, apply edit(list) in place, return the new list."""
    out = [(t, a, c, dict(p)) for t, a, c, p in steps]
    edit(out)
    return out


def ix(steps, typ, nth=0):
    return [i for i, s in enumerate(steps) if s[0] == typ][nth]


def negatives():
    """Correctly rehashed logs (build_turn re-chains) that each violate exactly
    one rule. Both verifiers must report the stated code. name -> (code, steps, base, objects)"""
    n = {}
    def add(name, code, steps, base=None, objects=True):
        n[name] = (code, steps, base or BASE, objects)
    # lifecycle
    add("duplicate-turn-received", "LIFECYCLE", mutate_steps(complete(), lambda s: s.insert(2, s[0])))
    add("provider-before-sealed", "LIFECYCLE", mutate_steps(complete(), lambda s: s.insert(3, s.pop(ix(s, "disclosure_intent")))))
    add("completed-without-release", "LIFECYCLE", mutate_steps(complete(), lambda s: s.pop(ix(s, "response_released"))))
    add("interrupted-after-release", "R3", mutate_steps(complete(), lambda s: s.__setitem__(-1, ("turn_interrupted", T(11), SVC, {"reason": "x", "disclosure": "disclosed"}))))
    # policy
    add("repeated-policy-decision", "POLICY", mutate_steps(complete(), lambda s: s.insert(2, s[1])))
    def allow_after_deny(s):
        s[1] = ("policy_decision", T(1), SVC, {"decision": "deny"})
        s.insert(2, ("policy_decision", T(2), SVC, {"decision": "allow"}))
    add("allow-after-deny", "POLICY", mutate_steps(complete(), allow_after_deny))
    add("bad-decision-value", "POLICY", mutate_steps(complete(), lambda s: s[1][3].update(decision="maybe")))
    # references
    add("sealed-missing-request", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "context_sealed")][3].pop("request_sha256")))
    add("sealed-no-objects", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "context_sealed")][3].update(objects=[])))
    add("source-not-sealed", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "context_sealed")][3]["sources"][0].update(sha256=sha256_bytes(b"other"))))
    add("intent-request-mismatch", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "disclosure_intent")][3].update(request=ref(OUT_FULL))))
    add("output-no-objects", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "output_recorded")][3].update(objects=[])))
    add("input-reference-malformed", "REFS", mutate_steps(complete(), lambda s: s[0][3].update(input={"sha256": "nope", "bytes": 1})))
    add("ack-wrong-target", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "evidence_ack")][3].update(acked_seq=99)))
    # lengths
    def intent_len(s):
        s[ix(s, "disclosure_intent")][3]["request"] = {"sha256": sha256_bytes(REQ), "bytes": len(REQ) + 1}
    add("intent-length-differs", "LENGTH", mutate_steps(complete(), intent_len))
    def declared_len(s):
        s[ix(s, "context_sealed")][3]["objects"][0] = {"sha256": sha256_bytes(SRC), "bytes": len(SRC) + 5}
    add("object-declared-length-wrong", "LENGTH", mutate_steps(complete(), declared_len))
    # disclosure
    add("interrupted-disclosure-understated", "DISCLOSURE", mutate_steps(unknown(), lambda s: s[-1][3].update(disclosure="none")))
    add("interrupted-disclosure-overstated", "DISCLOSURE", mutate_steps(pre_ack_crash(), lambda s: s[-1][3].update(disclosure="disclosed")))
    # envelope
    add("bad-actor-kind", "ENVELOPE", mutate_steps(complete(), lambda s: s.__setitem__(0, ("turn_received", T(0), {"kind": "robot", "id": "x"}, {"input_summary": "s"}))))
    add("bad-timestamp", "ENVELOPE", mutate_steps(complete(), lambda s: s.__setitem__(0, ("turn_received", "2026-01-15 10:00:00", USER, {"input_summary": "s"}))))
    add("bad-identifier", "ENVELOPE", mutate_steps(complete(), lambda s: s), base={**BASE, "tenant_id": "TENANT/UPPER"})
    # verifier profile regressions: synthetic, correctly rehashed logs
    add("ack-missing-receipt", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "evidence_ack")][3].pop("receipt", None)))
    def intent_destination_mismatch(s):
        s[ix(s, "policy_decision")][3]["destination"] = {"provider": "test-a", "endpoint_id": "ep-1", "model_id": "test-model"}
        s[ix(s, "disclosure_intent")][3]["provider"] = "other"
    add("intent-destination-mismatch", "REFS", mutate_steps(complete(), intent_destination_mismatch))
    add("acceptance-destination-mismatch", "REFS", mutate_steps(complete(), lambda s: s[ix(s, "provider_accepted")][3].update(endpoint_id="other")))
    add("unknown-under-settlement", "REFS", mutate_steps(unknown(), lambda s: s[ix(s, "usage_settled")][3].update(units=1)))
    add("admission-service-actor", "ENVELOPE", mutate_steps(complete(), lambda s: s.__setitem__(0, (s[0][0], s[0][1], SVC, s[0][3]))))
    add("legacy-summary-claims-exact", "REFS", mutate_steps(complete(), lambda s: s[0][3].update(input_summary="exact input: synthetic prompt")))
    return n


def main():
    os.makedirs(OUT, exist_ok=True)
    cases = {"complete-turn": complete(), "interrupted-mid-stream": mid_stream(),
             "unknown-disclosure": unknown(), "crash-before-intent-ack": pre_ack_crash()}
    for name, steps in cases.items():
        ev_steps = steps
        write(name + ".json", {"description": name, "synthetic": True,
                               "events": build_turn(BASE, ev_steps), "objects": OBJECTS})
    items = [
        {"id": "A", "matter_id": "m-0001", "custodian_id": "c1", "recorded_at": "2026-01-10", "retention_expires_at": 100},
        {"id": "B", "matter_id": "m-0001", "custodian_id": "c2", "recorded_at": "2026-01-11", "retention_expires_at": 100},
        {"id": "C", "matter_id": "m-0002", "custodian_id": "c1", "recorded_at": "2026-01-12", "retention_expires_at": 100},
    ]
    h1 = {"id": "H1", "matter_id": "m-0001", "custodian_ids": [], "window_start": "2026-01-01", "window_end": None}
    h2 = {"id": "H2", "matter_id": "m-0001", "custodian_ids": ["c1"], "window_start": "2026-01-01", "window_end": None}
    vectors = [
        {"name": "utf16-key-order", "value": {"\ue000": 1, "\U00010000": 2},
         "note": "JCS sorts by UTF-16 code units: U+10000 (D800 DC00) sorts before U+E000"},
        {"name": "nested-and-escapes", "value": {"b": [1, {"z": None, "a": True}], "a": "line\nbreak \"q\""}},
        {"name": "negative-int", "value": {"n": -7}},
    ]
    for v in vectors:
        c = canonical(v["value"])
        v["canonical_utf8_hex"], v["sha256"] = c.hex(), sha256_bytes(c)
    write("canonical-vectors.json", {"description": "Cross-language golden vectors for RFC 8785 canonicalization (integers only)", "vectors": vectors})
    for name, (code, steps, base, _) in negatives().items():
        write(f"negative/{name}.json", {"description": name, "expect_code": code, "synthetic": True,
                                        "events": build_turn(base, steps), "objects": OBJECTS})
    write("holds.json", {"description": "A in H1+H2, B only in H1, C unheld control", "items": items, "holds": [h1, h2]})


if __name__ == "__main__":
    main()
