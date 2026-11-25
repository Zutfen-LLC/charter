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
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True); f.write("\n")


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
    write("holds.json", {"description": "A in H1+H2, B only in H1, C unheld control", "items": items, "holds": [h1, h2]})


if __name__ == "__main__":
    main()
