"""Reference model for the Charter evidence contracts (ADR 0001).

Dependency-free so it runs without the scaffold from issue #2. It is an
executable statement of the rules, not the product implementation.
"""
import hashlib
import json
from datetime import datetime

SCHEMA_VERSION = "1.0.0"
CURRENT_PROFILE = "charter-postgres-v1"
POSTGRES_DURABLE_LEVEL = "postgres:fsync=on,synchronous_commit=on"
RETENTION_PROFILE = "charter-s3-compliance-v1"
RETENTION_DURABLE_LEVEL = "s3:object-lock:COMPLIANCE"
RETAINED_RECEIPT_DOMAIN = b"CHARTER-RETAINED-RECEIPT-v1\0"
# Documented default resolution for an omitted model selection
# (docs/model-routing-and-budget.md). A code constant of this contract
# version, not mutable routing configuration.
DEFAULT_REGISTRY_MODEL = "det-a"


MAX_SAFE_INT = 2**53 - 1


def _enc(o) -> str:
    if o is None or isinstance(o, bool):
        return json.dumps(o)
    if isinstance(o, int):
        if abs(o) > MAX_SAFE_INT:
            raise ValueError("integer outside IEEE-754 safe range; use a decimal string")
        return str(o)
    if isinstance(o, float):
        raise ValueError("floats are forbidden in events")
    if isinstance(o, str):
        try:
            o.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("lone surrogates are forbidden")
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, list):
        return "[" + ",".join(_enc(v) for v in o) + "]"
    if isinstance(o, dict):
        # RFC 8785 section 3.2.3: sort by UTF-16 code units, not code points.
        keys = sorted(o, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_enc(k) + ":" + _enc(o[k]) for k in keys) + "}"
    raise ValueError(f"unsupported type {type(o).__name__}")


def canonical(obj) -> bytes:
    """RFC 8785 subset: integers (safe range), strings, bools, null, arrays, objects."""
    return _enc(obj).encode("utf-8")


def sha256_bytes(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def event_hash(event: dict) -> str:
    return sha256_bytes(canonical({k: v for k, v in event.items() if k != "event_hash"}))


def build_turn(base: dict, steps):
    """steps: list of (type, recorded_at, actor, payload). Payload values of
    '@prev' are replaced by the previous event's hash/seq for acks."""
    events, prev = [], None
    for seq, (typ, at, actor, payload) in enumerate(steps):
        payload = dict(payload)
        if payload.get("acked_seq") == "@prev":
            payload["acked_seq"] = seq - 1
            payload["acked_event_hash"] = prev
        ev = {"schema_version": SCHEMA_VERSION, **base, "seq": seq, "type": typ,
              "recorded_at": at, "actor": actor, "payload": payload, "prev_hash": prev}
        ev["event_hash"] = event_hash(ev)
        prev = ev["event_hash"]
        events.append(ev)
    return events


import re

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
TS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$")
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
RECEIPT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
DESTINATION_KEYS = ("provider", "endpoint_id", "model_id")
KNOWN = {"turn_received", "policy_decision", "usage_reserved", "context_sealed", "disclosure_intent",
         "evidence_ack", "provider_accepted", "output_recorded", "response_released", "usage_settled",
         "turn_completed", "turn_interrupted", "outcome_resolved"}
TERMINAL = ("turn_completed", "turn_interrupted")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _ref(v):
    """{sha256, bytes} -> (sha, bytes) or None."""
    if isinstance(v, dict) and isinstance(v.get("sha256"), str) and SHA_RE.fullmatch(v["sha256"]) \
            and _int(v.get("bytes")) and v["bytes"] >= 0:
        return v["sha256"], v["bytes"]
    return None


def _pl(e):
    p = e.get("payload") if isinstance(e, dict) else None
    return p if isinstance(p, dict) else {}


def _refs(v):
    if not isinstance(v, list):
        return None
    out = [_ref(x) for x in v]
    return None if any(r is None for r in out) else out


def strict_loads(text):
    """json.loads that rejects duplicate keys (the Go verifier does too)."""
    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError(f"duplicate key {k!r}")
            d[k] = v
        return d
    return json.loads(text, object_pairs_hook=hook)


def _next_state(state, typ, p):
    if typ == "turn_interrupted":
        return None if state in ("start", "denied", "released", "settled_released", "terminal") else "terminal"
    if state == "intent" and typ == "output_recorded" and p.get("complete") is False:
        return "output_unconfirmed"
    table = {
        "start": {"turn_received": "received"},
        "received": {"policy_decision": "deny" if p.get("decision") == "deny" else "decided"},
        "denied": {"turn_completed": "terminal"},
        "decided": {"usage_reserved": "reserved"},
        "reserved": {"context_sealed": "sealed"},
        "sealed": {"disclosure_intent": "intent"},
        "intent": {"provider_accepted": "accepted", "usage_settled": "settled"},
        "output_unconfirmed": {"usage_settled": "settled"},
        "accepted": {"output_recorded": "output", "usage_settled": "settled"},
        "output": {"response_released": "released", "usage_settled": "settled"},
        "released": {"usage_settled": "settled_released", "turn_completed": "terminal"},
        "settled_released": {"turn_completed": "terminal"},
    }
    if state == "received" and p.get("decision") == "deny":
        table["received"] = {"policy_decision": "denied"}
    return table.get(state, {}).get(typ)


def _destination_fields(p):
    return isinstance(p, dict) and all(k not in p or (isinstance(p[k], str) and p[k] and p[k].strip() == p[k])
                                       for k in DESTINATION_KEYS)


def _destination_equal(a, b):
    return all(k not in a or k not in b or (isinstance(a[k], str) and isinstance(b[k], str) and a[k] == b[k])
               for k in DESTINATION_KEYS)


def _complete_destination(p):
    return _destination_fields(p) and all(k in p for k in DESTINATION_KEYS)


def verify_current_full(events, objects):
    """Require current-profile evidence with exact input and all referenced bytes."""
    if not events or _pl(events[0]).get("evidence_profile") != CURRENT_PROFILE:
        return ["[ENVELOPE] current evidence profile is required"]
    if objects is None:
        return ["[OBJECT] current full verification requires the referenced objects"]
    return verify_turn(events, objects)


def verify_retention_full(events, objects):
    """Require the retained profile and object bytes, not live storage proof."""
    if not events or _pl(events[0]).get("evidence_profile") != RETENTION_PROFILE:
        return ["[ENVELOPE] retention evidence profile is required"]
    if objects is None:
        return ["[OBJECT] retention full verification requires the referenced objects"]
    return verify_turn(events, objects)


def _retained_ack(p, target):
    r = p.get("retained_receipt")
    if not isinstance(r, dict) or set(r) != {
        "deployment", "tenant", "evidence_id", "bucket", "key", "version", "sha256", "length",
        "mode", "retain_until", "seq", "event_hash",
    }:
        return None
    d, b, v, until = (r[k] for k in ("deployment", "bucket", "version", "retain_until"))
    if not isinstance(d, str) or ID_RE.fullmatch(d) is None or not isinstance(b, str) or ID_RE.fullmatch(b) is None:
        return None
    if not isinstance(v, str) or v in ("", "null") or not isinstance(until, str) or r["mode"] != "COMPLIANCE":
        return None
    h, tenant, turn, seq = (target.get(k) for k in ("event_hash", "tenant_id", "turn_id", "seq"))
    if not _int(seq) or seq <= 0 or not _int(r["seq"]) or r["seq"] != seq or not _int(r["length"]):
        return None
    if r["key"] != f"charter/v1/{d}/{tenant}/data/events/{turn}/{h}" or r["tenant"] != tenant or r["event_hash"] != h or r["evidence_id"] != h:
        return None
    try:
        parsed = datetime.strptime(until, "%Y-%m-%dT%H:%M:%SZ")
        if parsed.isoformat(timespec="seconds") + "Z" != until:
            return None
        body = canonical(target)
        if r["sha256"] != sha256_bytes(body) or r["length"] != len(body):
            return None
        if p.get("receipt") != sha256_bytes(RETAINED_RECEIPT_DOMAIN + canonical(r)):
            return None
    except (TypeError, ValueError):
        return None
    return d, b


def verify_turn(events, objects=None):
    """Return violation strings, each "seq N: [CODE] text" or "[CODE] text".
    Same rules and codes as the Go verifier (internal/evidence/verify.go).
    objects=None checks structure; a dict checks declared objects. Legacy logs
    may pass without proving exact original input. To require the current
    profile and input bytes, use verify_current_full."""
    errs = []
    add = lambda i, code, msg: errs.append((f"seq {i}: " if i >= 0 else "") + f"[{code}] {msg}")
    if not events:
        return ["[ENVELOPE] empty log"]
    first = events[0]
    first_payload = _pl(first)
    retained = first_payload.get("evidence_profile") == RETENTION_PROFILE
    current = first_payload.get("evidence_profile") == CURRENT_PROFILE or retained
    if "evidence_profile" in first_payload and not current:
        add(0, "ENVELOPE", "unknown evidence profile")
    retention_identity = None
    acked, sealed, sealed_req, state = set(), None, None, "start"
    released = decided = denied = False
    declared = {}
    reserved_units = None
    governed_budget = False
    non_dispatch = {"route_revoked_before_dispatch", "dispatch_denied", "cancelled_before_dispatch", "dispatch_ownership_lost"}
    policy_destination = intent_destination = None
    types = []
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            add(i, "ENVELOPE", "event is not an object"); continue
        typ = e.get("type") if isinstance(e.get("type"), str) else ""
        types.append(typ)
        p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
        v = e.get("schema_version")
        if not isinstance(v, str) or not SEMVER_RE.fullmatch(v):
            add(i, "ENVELOPE", "schema_version must be semantic-version text")
        elif not v.startswith("1."):
            add(i, "ENVELOPE", "unsupported schema_version")
        for k in ("tenant_id", "project_id", "matter_id", "turn_id"):
            if not isinstance(e.get(k), str) or not ID_RE.fullmatch(e[k]):
                add(i, "ENVELOPE", f"{k} must be an opaque lowercase identifier")
            elif e[k] != first.get(k):
                add(i, "ENVELOPE", f"{k} differs within the turn")
        if not TYPE_RE.fullmatch(typ):
            add(i, "ENVELOPE", "type must be a lowercase identifier")
        if not _int(e.get("seq")):
            add(i, "ENVELOPE", "seq must be an integer")
        ts = e.get("recorded_at")
        if not isinstance(ts, str) or not TS_RE.fullmatch(ts):
            add(i, "ENVELOPE", "recorded_at must be RFC 3339 UTC with milliseconds and Z")
        else:
            import datetime
            try:
                datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                add(i, "ENVELOPE", "recorded_at is not a valid time")
        a = e.get("actor")
        expected_actor = "user" if i == 0 else "service"
        if not isinstance(a, dict) or a.get("kind") != expected_actor \
                or not isinstance(a.get("id"), str) or not ID_RE.fullmatch(a["id"]):
            add(i, "ENVELOPE", "actor must be {kind: user|service, id: identifier}")
        if not isinstance(e.get("payload"), dict):
            add(i, "ENVELOPE", "payload must be an object")
        if "prev_hash" not in e:
            add(i, "ENVELOPE", "prev_hash is required")
        elif e["prev_hash"] is not None and not (isinstance(e["prev_hash"], str) and SHA_RE.fullmatch(e["prev_hash"])):
            add(i, "ENVELOPE", "prev_hash must be null or sha256:<hex>")
        if not isinstance(e.get("event_hash"), str) or not SHA_RE.fullmatch(e["event_hash"]):
            add(i, "ENVELOPE", "event_hash must be sha256:<hex>")
        # chain
        if e.get("seq") != i:
            add(i, "CHAIN", "seq out of order")
        if i == 0:
            if e.get("prev_hash") is not None:
                add(i, "CHAIN", "first event must have a null prev_hash")
        elif e.get("prev_hash") != events[i - 1].get("event_hash"):
            add(i, "CHAIN", "broken chain")
        try:
            if e.get("event_hash") != event_hash(e):
                add(i, "CHAIN", "hash mismatch")
        except ValueError:
            add(i, "CHAIN", "hash mismatch")
        # declared reference lengths
        refs = []
        if isinstance(p.get("objects"), list):
            refs += [r for r in map(_ref, p["objects"]) if r]
        for k in ("request", "input"):
            r = _ref(p.get(k))
            if r:
                refs.append(r)
        for sha, n in refs:
            if sha in declared and declared[sha] != n:
                add(i, "LENGTH", f"object {sha} declared with different lengths")
            declared[sha] = n
        if i == 0 and typ != "turn_received":
            add(i, "LIFECYCLE", "the first event must be turn_received")
        if i > 0 and typ == "turn_received":
            add(i, "LIFECYCLE", "turn_received may appear only once, at seq 0")
        if typ == "turn_received":
            if current and (not _ref(p.get("input")) or "input_summary" in p):
                add(i, "REFS", "current evidence requires exact input bytes, not a legacy summary")
            a = e.get("actor") if isinstance(e.get("actor"), dict) else {}
            if current and (not isinstance(p.get("custodian_id"), str) or not p["custodian_id"] or p["custodian_id"] != a.get("id")):
                add(i, "ENVELOPE", "admission actor does not match the declared custodian")
            if "input" in p:
                if not _ref(p["input"]):
                    add(i, "REFS", "input must be a {sha256, bytes} reference")
            elif not isinstance(p.get("input_summary"), str):
                add(i, "REFS", "turn_received needs an input reference (or a legacy input_summary)")
        elif typ == "policy_decision":
            d = p.get("decision")
            if d == "allow":
                if "destination" in p and not _destination_fields(p["destination"]):
                    add(i, "REFS", "policy destination has invalid identifiers")
                policy_destination = p.get("destination") if isinstance(p.get("destination"), dict) else None
                if policy_destination is not None and not _destination_equal(p, policy_destination):
                    add(i, "REFS", "policy destination conflicts with its corresponding identifiers")
                if current and (not _complete_destination(policy_destination) or p.get("route") != policy_destination["endpoint_id"]):
                    add(i, "REFS", "policy must identify the actual provider, endpoint, and model, with its route matching the endpoint")
            if d not in ("allow", "deny"):
                add(i, "POLICY", "decision must be allow or deny")
            elif i != 1:
                add(i, "POLICY", "the policy decision must be seq 1")
            if decided:
                add(i, "POLICY", "repeated policy decision")
            decided, denied = True, d == "deny"
        elif typ == "usage_reserved":
            if "accounting_version" in p:
                model = p.get("registry_model")
                governed_budget = p["accounting_version"] == "charter-budget-v1" and isinstance(model, str) and ID_RE.fullmatch(model) is not None
                if not governed_budget:
                    add(i, "REFS", "invalid governed budget version or model")
            if not _int(p.get("units")) or p["units"] < 0:
                add(i, "REFS", "usage_reserved.units must be a non-negative integer")
            else:
                reserved_units = p["units"]
        elif typ == "context_sealed":
            objs = _refs(p.get("objects"))
            sealed = dict(objs) if objs else {}
            if not objs:
                add(i, "REFS", "context_sealed.objects must be a non-empty list of {sha256, bytes}")
            sealed_req = p.get("request_sha256")
            if not (isinstance(sealed_req, str) and SHA_RE.fullmatch(sealed_req)):
                add(i, "REFS", "request_sha256 missing or malformed"); sealed_req = None
            elif sealed_req not in sealed:
                add(i, "REFS", "request_sha256 is not among the sealed objects")
            srcs = p.get("sources")
            if not isinstance(srcs, list):
                add(i, "REFS", "context_sealed.sources must be a list"); srcs = []
            for sx in srcs:
                ok = isinstance(sx, dict) and isinstance(sx.get("source_id"), str) and sx["source_id"] \
                    and _int(sx.get("version")) and sx["version"] >= 0 \
                    and isinstance(sx.get("sha256"), str) and SHA_RE.fullmatch(sx["sha256"])
                if not ok:
                    add(i, "REFS", "malformed source reference")
                elif sx["sha256"] not in sealed:
                    add(i, "REFS", "source sha256 is not among the sealed objects")
        elif typ == "disclosure_intent":
            intent_destination = p
            if not _destination_fields(p) or (current and not _complete_destination(p)):
                add(i, "REFS", "disclosure intent has invalid or missing destination identifiers")
            if policy_destination is not None and not _destination_equal(policy_destination, intent_destination):
                add(i, "REFS", "disclosure intent destination differs from policy destination")
            rq = _ref(p.get("request"))
            if not rq:
                add(i, "REFS", "disclosure_intent.request must be a {sha256, bytes} reference")
            elif sealed_req is None:
                add(i, "REFS", "disclosure_intent without a sealed request")
            elif rq[0] != sealed_req:
                add(i, "REFS", "disclosure_intent request does not match the sealed request")
            elif sealed and sealed.get(rq[0]) != rq[1]:
                add(i, "LENGTH", "disclosure_intent request length differs from the sealed object length")
            for k in ("provider", "endpoint_id"):
                if not isinstance(p.get(k), str) or not p[k]:
                    add(i, "REFS", f"disclosure_intent.{k} is required")
        elif typ == "evidence_ack":
            receipt = p.get("receipt")
            if not isinstance(receipt, str) or RECEIPT_RE.fullmatch(receipt) is None:
                add(i, "REFS", "evidence_ack.receipt is required and must be a valid identifier")
            level = p.get("storage_level")
            if ((retained and level != RETENTION_DURABLE_LEVEL) or
                    (not retained and (current or "storage_level" in p) and level != POSTGRES_DURABLE_LEVEL)):
                add(i, "REFS", "evidence_ack.storage_level must identify a supported durable storage class")
            if not retained and "retained_receipt" in p:
                add(i, "REFS", "retained receipt requires a retention profile")
            ak = p.get("acked_seq")
            if not _int(ak) or ak < 0 or ak >= i or not isinstance(events[ak], dict) \
                    or events[ak].get("event_hash") != p.get("acked_event_hash") or not p.get("acked_event_hash"):
                add(i, "REFS", "ack does not match event")
            else:
                target = events[ak]
                if level == POSTGRES_DURABLE_LEVEL:
                    try:
                        expected = sha256_bytes(canonical({"backend": "postgres-append-only", "level": level,
                            **{key: target.get(key) for key in ("tenant_id", "turn_id", "seq", "event_hash")}}))
                    except (ValueError, AttributeError):
                        expected = None
                    if receipt != expected:
                        add(i, "REFS", "evidence_ack receipt does not bind the storage level and target event")
                if retained:
                    identity = _retained_ack(p, target)
                    if identity is None or (retention_identity is not None and identity != retention_identity):
                        add(i, "REFS", "retained receipt does not bind the event bytes and storage identity")
                    else:
                        retention_identity = identity
                if current and (ak != i - 1 or target.get("type") not in ("disclosure_intent", "output_recorded")):
                    add(i, "REFS", "current evidence_ack must target its immediately preceding intent or output event")
                acked.update(range(ak + 1))
        elif typ == "provider_accepted":
            if not _destination_fields(p) or (current and not _complete_destination(p)):
                add(i, "REFS", "provider acceptance has invalid or missing destination identifiers")
            if intent_destination is not None and not _destination_equal(intent_destination, p):
                add(i, "REFS", "provider acceptance destination differs from disclosure intent")
            idx = [j for j, x in enumerate(events[:i]) if isinstance(x, dict) and x.get("type") == "disclosure_intent"]
            if not idx or idx[-1] not in acked:
                add(i, "R1", "provider contacted before acked disclosure_intent")
        elif typ == "output_recorded":
            if "provider_cost_units" in p:
                n = p["provider_cost_units"]
                if not governed_budget or not _int(n) or not 0 <= n <= MAX_SAFE_INT or "provider_accepted" not in types[:i]:
                    add(i, "REFS", "governed provider cost needs a safe integer and confirmed acceptance")
            intents = [j for j, x in enumerate(events[:i]) if isinstance(x, dict) and x.get("type") == "disclosure_intent"]
            if not intents or intents[-1] not in acked:
                add(i, "R1", "output recorded without acknowledged disclosure intent")
            if not isinstance(p.get("complete"), bool):
                add(i, "REFS", "output_recorded.complete must be a boolean")
            o = _refs(p.get("objects"))
            if not o or len(o) != 1:
                add(i, "REFS", "output_recorded.objects must be exactly one {sha256, bytes} reference")
        elif typ == "response_released":
            out = [j for j, x in enumerate(events[:i]) if isinstance(x, dict) and x.get("type") == "output_recorded"]
            if not out or out[-1] not in acked or _pl(events[out[-1]]).get("complete") is not True:
                add(i, "R2", "response released before acked complete output")
            released = True
        elif typ == "usage_settled":
            basis = p.get("basis")
            has_floor = "observed_overrun_floor" in p
            has_unquantified = "unquantified_exposure" in p
            if has_floor or has_unquantified or basis == "observed_minimum":
                intent = max((j for j, kind in enumerate(types[:i]) if kind == "disclosure_intent"), default=-1)
                floor = p.get("observed_overrun_floor")
                if (not governed_budget or intent not in acked or released or "confirmed_no_dispatch" in p or
                        (has_unquantified and (p["unquantified_exposure"] is not True or has_floor or basis != "reserved_max")) or
                        (has_floor and (not _int(floor) or not reserved_units < floor <= MAX_SAFE_INT or
                                        not _int(p.get("units")) or p["units"] != floor or basis not in ("observed_minimum", "provider_reported"))) or
                        (basis == "observed_minimum" and not has_floor)):
                    add(i, "REFS", "invalid governed exposure evidence")
            if "confirmed_no_dispatch" in p:
                reason = p["confirmed_no_dispatch"]
                nxt = events[i+1] if i+1 < len(events) and isinstance(events[i+1], dict) else {}
                if (not isinstance(reason, str) or reason not in non_dispatch or not governed_budget or
                        p.get("basis") != "reserved_max" or derive_disclosure(events[:i]) != "unknown" or
                        "output_recorded" in types[:i] or nxt.get("type") != "turn_interrupted" or _pl(nxt).get("reason") != reason):
                    add(i, "REFS", "invalid governed non-dispatch accounting evidence")
            if governed_budget and p.get("basis") == "provider_reported":
                idx = max((j for j, typ_before in enumerate(types[:i]) if typ_before == "output_recorded"), default=-1)
                n = _pl(events[idx]).get("provider_cost_units") if idx >= 0 and types[idx+1] == "evidence_ack" else None
                if not _int(n) or p.get("units") != n:
                    add(i, "REFS", "provider settlement must match acknowledged governed cost")
            if not _int(p.get("units")) or p["units"] < 0:
                add(i, "REFS", "usage_settled.units must be a non-negative integer")
            elif p.get("basis") == "reserved_max" and p["units"] != reserved_units:
                add(i, "REFS", "usage_settled reserved_max units must equal the full reservation")
            if p.get("basis") not in ("reserved_max", "provider_reported", "observed_minimum"):
                add(i, "REFS", "unsupported usage_settled.basis")
            if derive_disclosure(events[:i]) == "unknown" and p.get("basis") not in ("reserved_max", "observed_minimum"):
                add(i, "REFS", "unknown disclosure cannot use exact settlement")
        elif typ == "turn_completed":
            o = p.get("outcome")
            if o == "completed" and not any(isinstance(x, dict) and x.get("type") == "usage_settled" for x in events[:i]):
                add(i, "LIFECYCLE", "successful completion requires usage_settled")
            if o == "completed" and not released:
                add(i, "LIFECYCLE", "turn_completed(completed) without a recorded release")
            elif o == "denied" and not denied:
                add(i, "LIFECYCLE", "turn_completed(denied) without a deny decision")
            elif o not in ("completed", "denied"):
                add(i, "REFS", "turn_completed.outcome must be completed or denied")
        elif typ == "turn_interrupted":
            if not isinstance(p.get("reason"), str) or not p["reason"]:
                add(i, "REFS", "turn_interrupted.reason is required")
            dv = p.get("disclosure")
            if dv not in ("none", "unknown", "disclosed"):
                add(i, "REFS", "turn_interrupted.disclosure must be none, unknown or disclosed")
            elif dv != derive_disclosure(events[:i]):
                add(i, "DISCLOSURE", f"recorded disclosure {dv!r} but the log derives {derive_disclosure(events[:i])!r}")
            if derive_disclosure(events[:i]) == "unknown" and "usage_settled" not in types[:-1]:
                add(i, "LIFECYCLE", "unknown disclosure must settle the full reservation before interruption")
            if released:
                add(i, "R3", "a turn with a recorded release cannot end interrupted")
        if typ in ("context_sealed", "disclosure_intent", "provider_accepted", "response_released"):
            d = [x for x in events[:i] if isinstance(x, dict) and x.get("type") == "policy_decision"]
            if not d or _pl(d[-1]).get("decision") != "allow":
                add(i, "R4", f"{typ} without a preceding allow policy_decision")
        if typ != "evidence_ack" and typ in KNOWN:
            nxt = _next_state(state, typ, p)
            if nxt is None:
                add(i, "LIFECYCLE", f"{typ} is not allowed after {state}")
            else:
                state = nxt
    terminals = [i for i, t in enumerate(types) if t in TERMINAL]
    if len(terminals) != 1 or terminals[0] != len(events) - 1:
        add(-1, "R3", "exactly one terminal event, last")
    if "response_released" in types and types[-1] != "turn_completed":
        add(-1, "R3", "response released in a turn that did not complete")
    if objects is not None:
        seen = set()
        refs = []
        for e in events:
            p = _pl(e)
            for r in (_refs(p.get("objects")) or []) + [x for x in (_ref(p.get("request")), _ref(p.get("input"))) if x]:
                refs.append(r)
            rs = p.get("request_sha256")
            if isinstance(rs, str) and SHA_RE.fullmatch(rs) and sealed and rs in sealed:
                refs.append((rs, sealed[rs]))
        for sha, n in refs:
            if (sha, n) in seen:
                continue
            seen.add((sha, n))
            data = objects.get(sha)
            if data is None:
                add(-1, "OBJECT", f"missing object {sha}")
            elif sha256_bytes(data) != sha:
                add(-1, "OBJECT", f"changed object {sha} (digest mismatch)")
            elif len(data) != n:
                add(-1, "LENGTH", f"object {sha} is {len(data)} bytes but declared {n}")
    errs.extend(_verify_c06(events, objects))
    return errs


def _verify_c06(events, objects):
    """Strict verifier for the versioned permission-bound excerpt contract."""
    errs = []
    if not events or not isinstance(events[0], dict):
        return errs
    def timestamp(value):
        if not isinstance(value, str) or not TS_RE.fullmatch(value):
            return False
        try:
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return False
        return True
    received = _pl(events[0])
    if "source_binding_version" not in received:
        # A provenance marker is never valid outside a C06-bound turn.
        for e in events:
            if not isinstance(e, dict):
                continue
            p = _pl(e)
            if {"source_provenance_sha256", "source_authorized_at", "model_registry_id"} & p.keys():
                return ["[C06] orphan source provenance marker"]
            if e.get("type") == "context_sealed" and isinstance(p.get("sources"), list) and any(
                    isinstance(s, dict) and "external" in s for s in p["sources"]):
                return ["[C06] orphan external source marker"]
        return errs
    def add(i, message):
        errs.append((f"seq {i}: " if i >= 0 else "") + "[C06] " + message)
    if not _int(received.get("source_binding_version")) or received["source_binding_version"] != 1:
        add(0, "unsupported source binding version")
    if "model_registry_id" in received and (not isinstance(received["model_registry_id"], str) or
                                               not ID_RE.fullmatch(received["model_registry_id"])):
        add(0, "model_registry_id must be an explicit model identifier")
    # Reservation identity is attributable without a sealed context: a
    # legitimate partial or interrupted turn can hold usage_reserved before
    # context_sealed exists, so every reservation is checked before the seal
    # guard below. Sealed turns share the same loop, so the diagnostics cannot
    # diverge between the sealed and pre-seal paths.
    for i, e in enumerate(events):
        if not isinstance(e, dict) or e.get("type") != "usage_reserved":
            continue
        p = _pl(e)
        if p.get("accounting_version") != "charter-budget-v1" or not isinstance(p.get("registry_model"), str) or not ID_RE.fullmatch(p["registry_model"]):
            add(i, "C06 usage reservation requires C05 governed accounting")
            continue
        if isinstance(received.get("model_registry_id"), str):
            # Attributable model identity: the governed accounting
            # reservation must bind the same registry model the turn
            # explicitly requested. Registry identifiers are never
            # provider-native destination model identifiers, so the
            # policy destination is deliberately not compared here.
            if p["registry_model"] != received["model_registry_id"]:
                add(i, "C06 reserved registry model differs from the explicitly requested registry model")
        elif "model_registry_id" not in received:
            # No model was explicitly requested: the reservation must
            # bind the documented default resolution.
            if p["registry_model"] != DEFAULT_REGISTRY_MODEL:
                add(i, "C06 reserved registry model must be the documented default resolution")
    sealed_i = next((i for i, e in enumerate(events) if isinstance(e, dict) and e.get("type") == "context_sealed"), -1)
    if sealed_i < 0:
        # A partial prefix may not yet have a sealed snapshot.
        return errs
    sources = _pl(events[sealed_i]).get("sources")
    if not isinstance(sources, list):
        add(sealed_i, "sealed sources must be an ordered list")
        return errs
    if received.get("evidence_profile") not in ("charter-postgres-v1", "charter-s3-compliance-v1"):
        add(0, "source binding needs an explicit supported evidence profile")
    sealed = _pl(events[sealed_i])
    lengths = {r["sha256"]: r["bytes"] for r in sealed.get("objects", []) if _ref(r)} if isinstance(sealed.get("objects"), list) else {}
    external_seen = False
    bound_scope = None
    excerpts = []
    def text(sha):
        if objects is None or not isinstance(sha, str):
            return ""
        try:
            return objects.get(sha, b"").decode("utf-8")
        except (UnicodeError, AttributeError):
            add(sealed_i, "sealed input or excerpt is not valid UTF-8")
            return ""
    for source in sources:
        if not isinstance(source, dict):
            add(sealed_i, "source entry must be an object"); continue
        sha = source.get("sha256")
        length = source.get("bytes")
        if not isinstance(sha, str) or not _int(length) or length < 0 or lengths.get(sha) != length:
            add(sealed_i, "C06 source byte length does not match sealed object")
        expected = {"sha256", "bytes", "version", "source_id"}
        if set(source) != expected | ({"external"} if "external" in source else set()):
            add(sealed_i, "source descriptor has missing or unknown fields")
        ext = source.get("external")
        if "external" not in source:
            excerpts.append({"source_id": source.get("source_id"), "version": source.get("version"), "text": text(sha)})
            continue
        external_seen = True
        required = {"connector_id", "provider", "external_tenant_id", "site_id", "library_id", "document_id",
                    "provider_version", "etag", "document_sha256", "delegated_subject", "custodian_id", "offset", "length",
                    "extraction", "decision", "observed_at"}
        if not isinstance(ext, dict) or set(ext) != required:
            add(sealed_i, "external source descriptor has missing or unknown fields"); continue
        if (ext["provider"] != "sharepoint" or ext["extraction"] != "utf8-byte-range-v1" or
                ext["decision"] != "allow" or not _int(source.get("version")) or source["version"] != 0 or
                source.get("source_id") != ext["document_id"]):
            add(sealed_i, "external source identity or extraction binding is invalid")
        for key in ("connector_id", "external_tenant_id", "site_id", "library_id", "document_id",
                    "provider_version", "etag", "delegated_subject", "custodian_id"):
            if not isinstance(ext.get(key), str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,256}", ext[key]):
                add(sealed_i, f"external source identifier is invalid: {key}")
        offset, size = ext["offset"], ext["length"]
        if (not _int(offset) or not _int(size) or offset < 0 or not 0 < size <= 64 << 10 or
                offset > (8 << 20) - size or size != length or
                not isinstance(ext["document_sha256"], str) or not SHA_RE.fullmatch(ext["document_sha256"])):
            add(sealed_i, "external byte range or source digest invalid")
        if ext["custodian_id"] != received.get("custodian_id"):
            add(sealed_i, "source custodian differs from admitted identity")
        scope = tuple(ext[k] for k in ("connector_id", "external_tenant_id", "site_id", "library_id", "delegated_subject", "custodian_id"))
        if bound_scope is not None and scope != bound_scope:
            add(sealed_i, "inconsistent external source scope")
        bound_scope = scope
        excerpts.append({"source_id": source.get("source_id"), "provider_version": ext["provider_version"], "text": text(sha)})
        observed = ext.get("observed_at")
        if not timestamp(observed):
            add(sealed_i, "source observation date is invalid")
    if not external_seen:
        add(sealed_i, "source binding version 1 requires an external source")
    fingerprint_sources = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        stable = dict(source)
        if isinstance(source.get("external"), dict):
            stable_external = {k: v for k, v in source["external"].items() if k not in ("observed_at", "decision")}
            stable["external"] = stable_external
        fingerprint_sources.append(stable)
    fingerprint_identity = {
        "v": 3, "tenant_id": events[0].get("tenant_id"), "project_id": events[0].get("project_id"),
        "matter_id": events[0].get("matter_id"), "custodian_id": received.get("custodian_id"),
        "input": received.get("input"), "sources": fingerprint_sources,
        "model_id": received.get("model_registry_id", ""),
    }
    try:
        if received.get("request_fingerprint") != sha256_bytes(canonical(fingerprint_identity)):
            add(0, "stable v3 request fingerprint mismatch")
    except ValueError:
        add(0, "stable v3 request fingerprint is not canonicalizable")
    if objects is not None:
        policy = next((_pl(e) for e in events if isinstance(e, dict) and e.get("type") == "policy_decision"), {})
        dest, inp = policy.get("destination"), received.get("input")
        model = dest.get("model_id") if isinstance(dest, dict) else None
        request_sha = sealed.get("request_sha256")
        try:
            render = canonical({"model": model, "input": text(inp.get("sha256") if isinstance(inp, dict) else None), "excerpts": excerpts})
            if not model or not isinstance(request_sha, str) or render != objects.get(request_sha):
                add(sealed_i, "exact rendered request differs from sealed input or excerpts")
        except ValueError:
            add(sealed_i, "exact rendered request is not canonicalizable")
    try:
        provenance = sha256_bytes(canonical(sources))
    except ValueError:
        add(sealed_i, "sealed sources are not canonicalizable")
        return errs
    sealed_at = events[sealed_i].get("recorded_at", "")
    latest_auth = sealed_at
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            continue
        typ, p = e.get("type"), _pl(e)
        if typ in ("output_recorded", "response_released") and p.get("source_provenance_sha256") != provenance:
            add(i, "output and release must bind the complete sealed source provenance")
        if typ in ("disclosure_intent", "provider_accepted", "response_released"):
            ts = p.get("source_authorized_at")
            if not timestamp(ts):
                add(i, f"{typ}.source_authorized_at must be a valid UTC millisecond timestamp")
            elif not isinstance(latest_auth, str) or not isinstance(e.get("recorded_at"), str) or ts > e["recorded_at"] or ts < latest_auth:
                add(i, f"{typ}.source_authorized_at is out of order")
            else:
                latest_auth = ts
    for source in sources:
        ext = source.get("external") if isinstance(source, dict) else None
        if isinstance(ext, dict) and isinstance(ext.get("observed_at"), str) and isinstance(sealed_at, str) and ext["observed_at"] > sealed_at:
            add(sealed_i, "source observation cannot follow context_sealed")
    return errs


def derive_disclosure(events):
    acked, intent_acked = set(), False
    for i, e in enumerate(events):
        if isinstance(e, dict) and e.get("type") == "evidence_ack":
            a = _pl(e).get("acked_seq")
            if _int(a) and 0 <= a < i:
                acked.update(range(a + 1))
    for i, e in enumerate(events):
        if isinstance(e, dict) and e.get("type") == "disclosure_intent" and i in acked:
            intent_acked = True
    if any(isinstance(e, dict) and e.get("type") == "provider_accepted" for e in events):
        return "disclosed"
    return "unknown" if intent_acked else "none"


# ---- holds and retention -------------------------------------------------

def matches_scope(hold, item):
    """ADR 0001 section 7 matching without the hold-state filter: the C07
    lifecycle applies it to pending/effective/failed holds itself."""
    item = dict(item)
    item.setdefault("state", "active")
    saved = hold.get("state")
    hold = dict(hold, state="active")
    try:
        return matches(hold, item)
    finally:
        if saved is not None:
            hold_hold = hold  # noqa: F841 (documentation only)


def _scope_only(hold, item):
    matter = hold["matter_id"] == item["matter_id"]
    custodians = hold.get("custodian_ids") or []
    cust_ok = not custodians or item["custodian_id"] in custodians
    ws, we = hold.get("window_start"), hold.get("window_end")
    recorded = item["recorded_at"]
    window = (ws is None or recorded >= ws) and (we is None or recorded < we)
    return matter and cust_ok and window


def matches(hold, item):
    if hold["state"] != "active" or hold["matter_id"] != item["matter_id"]:
        return False
    if hold["custodian_ids"] and item["custodian_id"] not in hold["custodian_ids"]:
        return False
    at = item["recorded_at"]
    if at < hold["window_start"]:
        return False
    return hold["window_end"] is None or at < hold["window_end"]


class Store:
    GRACE = 7  # days, in abstract day units for tests

    def __init__(self, items, holds=()):
        self.items = {i["id"]: dict(i, state="active") for i in items}
        self.holds = {h["id"]: dict(h, state="active") for h in holds}
        self.epoch = len(self.holds)
        self.gaps = []

    def held(self, item):
        return any(matches(h, item) for h in self.holds.values())

    def place_hold(self, hold):
        self.epoch += 1
        self.holds[hold["id"]] = dict(hold, state="active", epoch=self.epoch)
        for it in self.items.values():
            if matches(self.holds[hold["id"]], it):
                if it["state"] in ("disposal_pending", "purging"):
                    it["state"] = "active"          # hold wins; bytes still exist
                elif it["state"] == "disposed":
                    self.gaps.append({"hold": hold["id"], "item": it["id"],
                                      "gap": "disposed_before_hold"})

    def release_hold(self, hold_id):
        self.epoch += 1
        self.holds[hold_id]["state"] = "released"

    def sweep(self, now):
        for it in self.items.values():
            if not it.get("terminal", True):
                # In-flight capture: disposal eligibility requires a verified
                # terminal capture state (finding 6A); never swept.
                continue
            if it["state"] == "active" and now >= it["retention_expires_at"] and not self.held(it):
                it["state"], it["observed_epoch"], it["pending_since"] = "disposal_pending", self.epoch, now

    # Purge is two steps. begin_purge tombstones the item (unreadable, bytes kept)
    # and records the hold epoch it observed. finish_purge is the ONLY step that
    # deletes bytes, and it is a conditional delete: it succeeds only if the hold
    # epoch is unchanged since begin_purge. Any acknowledged hold bumps the epoch
    # first, so a hold acknowledged before the finish commits always wins.
    def begin_purge(self, item_id, now, approved_by_records_officer):
        it = self.items[item_id]
        if it["state"] != "disposal_pending" or not approved_by_records_officer:
            return False
        if now < it["pending_since"] + self.GRACE:
            return False
        if self.held(it):
            it["state"] = "active"
            return False
        it["state"], it["observed_epoch"] = "purging", self.epoch
        return True

    def finish_purge(self, item_id):
        it = self.items[item_id]
        if it["state"] != "purging":
            return "not_purging"
        if self.epoch != it["observed_epoch"]:
            # A hold or release committed since begin_purge: re-evaluate, never delete blind.
            if self.held(it):
                it["state"] = "active"
                return "restored"
            it["state"] = "disposal_pending"   # must restart begin_purge under the new epoch
            return "stale_retry"
        it["state"] = "disposed"
        return "disposed"

    def purge(self, item_id, now, approved_by_records_officer):
        return (self.begin_purge(item_id, now, approved_by_records_officer)
                and self.finish_purge(item_id) == "disposed")


# ---- C07 lifecycle: protection states, new-work guard, release cleanup ----

# Hold states (C07): pending = epoch committed, disposal fenced, protection
# not yet verified; effective = protection established and read back; failed =
# establishment failed, retryable, the fence stands; released = claim removed.
HOLD_PENDING, HOLD_EFFECTIVE, HOLD_FAILED, HOLD_RELEASED = "pending", "effective", "failed", "released"


class GuardedStore(Store):
    """The C07 reference lifecycle: Store plus storage-native protection.

    protection(volume) simulates the records transport: it can set and read
    back legal holds on exact (key, version) pairs and delete versions that
    are neither under legal hold nor unexpired base retention. The store
    refuses to acknowledge a hold as effective before every in-scope version
    is verified protected, and it never releases a storage legal hold that
    another protected record still requires.
    """

    def __init__(self, items, holds=()):
        super().__init__(items, holds)
        self.legal_hold = {}      # (key, version) -> "ON"/"OFF"
        self.protect_until = {}   # (key, version) -> expiry tick or None
        self.deleted = set()
        self.storage_down = False
        self.readback_lies = False
        self.reports = {}
        self.shared_object = {}   # item id -> shared object key (default own)
        self.clock = 0            # abstract tick for base-retention simulation
        # C07 review corrections: durable protection ownership ledger and
        # durable disposal plans.
        self.claims = {}          # hold id -> set((key, version))
        self.plans = {}           # item id -> {(key, version): disposition}
        for it in self.items.values():
            # Terminality: capture state of each turn; disposal eligibility
            # requires a verified terminal capture state (finding 6A).
            it.setdefault("terminal", True)

    # -- storage simulation (the records transport) --
    def set_legal_hold(self, key, version, on):
        if self.storage_down:
            raise StorageUnavailable()
        self.legal_hold[(key, version)] = "ON" if on else "OFF"

    def legal_hold_state(self, key, version):
        if self.storage_down:
            raise StorageUnavailable()
        if self.readback_lies:
            return "OFF"
        return self.legal_hold.get((key, version), "")

    def delete_version(self, key, version):
        if (key, version) in self.deleted:
            return "absent"
        if self.legal_hold.get((key, version)) == "ON":
            return "protected"
        until = self.protect_until.get((key, version))
        if until is not None and until > self.clock:
            return "protected"
        self.deleted.add((key, version))
        return "deleted"

    def versions_of(self, item_id):
        # Every item owns four versions. The last one is a content-addressed
        # object: by default private, but shareable by mapping another item
        # onto the same key (content addressing deduplicates identical bytes,
        # so a shared object has ONE key and ONE version id).
        shared = self.shared_object.get(item_id, f"{item_id}-obj")
        return [(f"{item_id}/admissions", f"v-{item_id}-0"),
                (f"{item_id}/events/0", f"v-{item_id}-1"),
                (f"{item_id}/events/h", f"v-{item_id}-2"),
                (f"shared/{shared}", f"v-{shared}-3")]

    def held(self, item):
        """A pending, effective or failed hold all fence disposal; only a
        released hold stops matching (ADR: failure never weakens)."""
        return any(h["state"] in (HOLD_PENDING, HOLD_EFFECTIVE, HOLD_FAILED)
                   and _scope_only(h, item) for h in self.holds.values())

    # -- placement with establishment (two-phase) --
    def place_hold(self, hold):
        """Phase 1: the durable placement. The hold is recorded pending - the
        epoch is committed and disposal is fenced, but protection has not yet
        been established or verified."""
        super().place_hold(hold)
        placed = self.holds[hold["id"]]
        placed["state"] = HOLD_PENDING
        placed["scope_epoch"] = self.epoch  # the scope revision
        return placed

    def place_hold_verified(self, hold, now=0):
        """Phase 1 commits the epoch (Store.place_hold); phase 2 establishes
        and verifies protection. Returns the durable hold dict or raises
        EstablishmentError; the hold is only effective when verified."""
        placed = self.place_hold(hold)
        placed["scope_epoch"] = self.epoch  # scope revision binding
        try:
            report = self._establish(placed, now)
        except StorageUnavailable as e:
            placed["state"] = HOLD_FAILED
            self.reports[hold["id"]] = {"error": str(e)}
            raise EstablishmentError(str(e))
        if report["uncovered"]:
            placed["state"] = HOLD_FAILED
            self.reports[hold["id"]] = report
            raise EstablishmentError("uncovered records")
        placed["state"] = HOLD_EFFECTIVE
        placed["report"] = report
        self.reports[hold["id"]] = report
        return placed

    def change_scope(self, hold_id, custodian_ids=None, window_start=None, window_end=None):
        """A scope change rewrites the scope under a NEW scope revision: the
        hold needs establishment again before it may report effective for
        the new scope, and an establishment verified under the prior scope
        revision can no longer complete the transition (finding 2)."""
        h = self.holds[hold_id]
        if custodian_ids is not None:
            h["custodian_ids"] = custodian_ids
        if window_start is not None:
            h["window_start"] = window_start
        if window_end is not None:
            h["window_end"] = window_end
        h["scope_epoch"] = self.epoch + 1
        self.epoch += 1
        h["state"] = HOLD_PENDING
        return h

    def reestablish(self, hold_id, now=0):
        """Re-establishment (scope change or recovery): the same
        authoritative acceptance rule as placement - uncovered records keep
        the hold from becoming effective, and the completion is bound to the
        scope revision it verified."""
        h = self.holds[hold_id]
        want_epoch = h.get("scope_epoch", 0)
        try:
            report = self._establish(h, now)
        except StorageUnavailable as e:
            h["state"] = HOLD_FAILED
            self.reports[hold_id] = {"error": str(e)}
            raise EstablishmentError(str(e))
        if report["uncovered"]:
            h["state"] = HOLD_FAILED
            self.reports[hold_id] = report
            raise EstablishmentError("uncovered records")
        if h.get("scope_epoch", 0) != want_epoch:
            # A stale establishment completing after a scope change: the
            # newer scope must not be marked effective against it.
            h["state"] = HOLD_PENDING
            raise EstablishmentError("scope revision moved")
        h["state"] = HOLD_EFFECTIVE
        h["report"] = report
        self.reports[hold_id] = report
        return h

    def _establish(self, hold, now):
        report = {"items": [], "disposed_before_hold": [], "uncovered": [],
                  "partially_disposed": [], "protected_versions": [],
                  "already_expired": []}
        for it in self.items.values():
            if not _scope_only(hold, it):
                continue
            if it["state"] == "disposed":
                report["disposed_before_hold"].append(it["id"])
                continue
            if it.get("root_gone"):
                # The live enumeration root is gone (mid-deletion or a
                # restored record): coverage comes from the DURABLE
                # DISPOSAL PLAN (partially disposed - the loss is explicit,
                # the remaining versions are protected), or the record is
                # unverifiable and blocks the effective transition
                # (C07 round-2 finding 1).
                plan = self.plans.get(it["id"])
                if not plan:
                    report["uncovered"].append(it["id"])
                    continue
                missing, protected = 0, 0
                failed = False
                for (key, version), d in sorted(plan.items()):
                    if d in ("deleted", "absent"):
                        continue
                    if (key, version) in self.deleted:
                        # Storage-verified partial loss, recorded in the
                        # plan: the inventory is never destroyed.
                        plan[(key, version)] = "absent"
                        missing += 1
                        continue
                    try:
                        self.set_legal_hold(key, version, True)
                        if self.legal_hold_state(key, version) != "ON":
                            failed = True
                    except StorageUnavailable:
                        failed = True
                    if failed:
                        break
                    self.claims.setdefault(hold["id"], set()).add((key, version))
                    report["protected_versions"].append((key, version))
                    protected += 1
                if failed:
                    report["uncovered"].append(it["id"])
                    continue
                report["partially_disposed"].append(it["id"])
                entry = dict(id=it["id"], custodian_id=it["custodian_id"],
                             recorded_at=it["recorded_at"], versions=protected,
                             partially_disposed=True, missing_versions=missing)
                if now >= it["retention_expires_at"]:
                    entry["already_expired"] = True
                    report["already_expired"].append(it["id"])
                report["items"].append(entry)
                continue
            refs = self.versions_of(it["id"])
            for key, version in refs:
                if (key, version) in self.deleted:
                    report["uncovered"].append(it["id"])
                    break
                self.set_legal_hold(key, version, True)
                if self.legal_hold_state(key, version) != "ON":
                    report["uncovered"].append(it["id"])
                    break
            else:
                report["protected_versions"].extend(refs)
                self.claims.setdefault(hold["id"], set()).update(refs)
                entry = dict(id=it["id"], custodian_id=it["custodian_id"],
                             recorded_at=it["recorded_at"], versions=len(refs))
                if now >= it["retention_expires_at"]:
                    entry["already_expired"] = True
                    report["already_expired"].append(it["id"])
                report["items"].append(entry)
        return report

    # -- new matching work guard --
    def hold_applies(self, matter_id, custodian_id, recorded_at, now=0):
        for h in self.holds.values():
            if h["state"] in (HOLD_PENDING, HOLD_EFFECTIVE, HOLD_FAILED) and \
                    _scope_only(h, {"matter_id": matter_id, "custodian_id": custodian_id,
                                    "recorded_at": recorded_at}):
                return True
        return False

    def admit_new_work(self, item_id, matter_id, custodian_id, now=0, recorded_at=None):
        """New matching work: the admission fails closed unless every version
        of the new turn is protected before the response escapes."""
        recorded = recorded_at if recorded_at is not None else now
        if not self.hold_applies(matter_id, custodian_id, recorded):
            self.items[item_id] = dict(id=item_id, matter_id=matter_id,
                                       custodian_id=custodian_id, recorded_at=now,
                                       retention_expires_at=now + 100, state="active")
            return "admitted"
        refs = self.versions_of(item_id)
        try:
            for key, version in refs:
                self.set_legal_hold(key, version, True)
                if self.legal_hold_state(key, version) != "ON":
                    raise StorageUnavailable("readback")
        except StorageUnavailable as e:
            # Nothing is released: the admission fails closed and the turn is
            # recorded as interrupted evidence of the failed protection.
            raise NewWorkFailClosed(str(e))
        # Protection intent is durably claimed for EVERY matching active
        # hold before the response escapes (finding 3A: release cleanup
        # derives its outstanding set from the claims ledger, never only
        # from the placement-time coverage report).
        for h in self.holds.values():
            if h["state"] == HOLD_RELEASED:
                continue
            if _scope_only(h, {"matter_id": matter_id, "custodian_id": custodian_id,
                               "recorded_at": recorded}):
                self.claims.setdefault(h["id"], set()).update(refs)
        self.items[item_id] = dict(id=item_id, matter_id=matter_id,
                                   custodian_id=custodian_id, recorded_at=recorded,
                                   retention_expires_at=now + 100, state="active",
                                   terminal=True)
        return "admitted-protected"

    # -- release with conservative cleanup (claims-ledger derived) --
    def release_hold_verified(self, hold_id):
        super().release_hold(hold_id)
        return self.reconcile_claims(hold_id)

    def reconcile_claims(self, hold_id):
        """Clear the legal hold of every claimed version that no remaining
        protection requires (any active hold of the store, any non-disposed
        referencing record). Derived from the durable claims ledger - never
        only the historical coverage report - so future matching work,
        narrowed scopes and interrupted releases all converge (finding 3)."""
        hold = self.holds[hold_id]
        report = self.reports.get(hold_id, {})
        pending = []
        for key, version in sorted(self.claims.get(hold_id, set())):
            if self._still_required(key, version, exclude=None):
                continue
            try:
                self.set_legal_hold(key, version, False)
                if self.legal_hold_state(key, version) == "ON":
                    pending.append([key, version])
                    continue
            except StorageUnavailable:
                pending.append([key, version])
                continue
            self.claims[hold_id].discard((key, version))
        report["release_cleanup_pending"] = pending
        return pending

    def _still_required(self, key, version, exclude=None):
        for other_id, other in self.holds.items():
            if other_id == exclude or other["state"] == HOLD_RELEASED:
                continue
            for it in self.items.values():
                if it["state"] == "disposed":
                    continue
                if _scope_only(other, it) and (key, version) in self.versions_of(it["id"]):
                    return True
        return False

    # -- disposal (plan-based, shared-object aware) --
    def classify_presence(self, item_id):
        """Presence classification (finding 4): a storage failure is never
        proof of disposal. Only the plan-verified disposition of every exact
        version may claim absence; unknown observations are unknown."""
        it = self.items.get(item_id)
        if it is None:
            return "unknown"
        if self.storage_down:
            return "unknown"
        plan = self.plans.get(item_id)
        if plan is not None:
            if all(d in ("deleted", "absent") for d in plan.values()) and plan:
                return "absent"
            return "present"
        refs = self.versions_of(item_id)
        if all((key, version) in self.deleted for key, version in refs):
            return "partial"
        return "present"

    def finish_purge_shared(self, item_id, now):
        """The conditional delete, in the two durable phases of the corrected
        implementation: the exact-version plan is committed BEFORE any
        irreversible deletion (finding 5), and the deletes then run under the
        conditional-delete fence with per-version dispositions. It refuses on
        epoch change like Store, and never deletes a version another
        non-disposed record references. A restore over a partially deleted
        plan requires verified completeness; partial loss keeps the plan
        (the exact-version inventory) and a later release and disposal stay
        recoverable (C07 round-2 finding 4)."""
        it = self.items[item_id]
        if it["state"] != "purging":
            return "not_purging"
        if self.epoch != it["observed_epoch"]:
            if self.held(it):
                return self._restore_active(item_id)
            it["state"] = "disposal_pending"
            return "stale_retry"  # the plan is kept: the resume reuses it
        # Plan phase: the exact-version plan, committed before any deletion.
        plan = self.plans.setdefault(item_id, {})
        for key, version in self.versions_of(item_id):
            plan.setdefault((key, version), "planned")
        # Delete phase: per-version dispositions from the plan.
        for key, version in self.versions_of(item_id):
            if plan[(key, version)] in ("deleted", "absent"):
                continue
            shared = any(other["id"] != item_id and other["state"] != "disposed"
                         and (key, version) in self.versions_of(other["id"])
                         for other in self.items.values())
            if shared:
                plan[(key, version)] = "retained_shared"
                continue
            plan[(key, version)] = self.delete_version(key, version)
        if any(d == "protected" for d in plan.values()):
            return "blocked_by_storage"
        if all(d in ("deleted", "absent", "retained_shared") for d in plan.values()):
            it["state"] = "disposed"
            return "disposed"
        return "incomplete"

    def _restore_active(self, item_id):
        """Restore a purging item to active because a hold intervened.
        With a durable plan the restoration requires VERIFIED completeness
        (actual storage state per planned version). Completeness counts
        EVERY planned version, including rows already dispositioned gone
        (a durable record of loss is a loss, not intactness): partial
        deletion keeps the plan with the loss recorded, and every planned
        version gone completes the disposal honestly."""
        it = self.items[item_id]
        plan = self.plans.get(item_id)
        if not plan:
            it["state"] = "active"
            return "restored_active"
        missing = []
        for (key, version), d in sorted(plan.items()):
            if d in ("deleted", "absent"):
                missing.append([key, version])
                continue
            if (key, version) in self.deleted:
                plan[(key, version)] = "absent"
                missing.append([key, version])
        if plan and len(missing) == len(plan):
            it["state"] = "disposed"
            return "disposed_ambiguous"
        it["state"] = "active"
        if missing:
            return "restored_active_partial"
        del self.plans[item_id]  # verified complete: nothing left to lose
        return "restored_active"

    def recover(self, now=0):
        """Startup recovery of the corrected implementation: re-establish
        pending/failed holds under the authoritative acceptance rule,
        comprehensively repair the missing protection of EFFECTIVE holds
        (interrupted, denied or recovered captures whose terminal paths
        could not complete protection - C07 round-2 finding 2), reconcile
        every hold's outstanding protection claims, complete purging items
        from their durable plans, and classify presence so a storage
        failure never becomes proof of disposal (finding 4)."""
        # 1. Holds awaiting verified protection.
        for hold_id in list(self.holds):
            h = self.holds[hold_id]
            if h["state"] in (HOLD_PENDING, HOLD_FAILED):
                try:
                    self.reestablish(hold_id, now)
                except EstablishmentError:
                    pass  # recorded failed/pending; the fence stands
        # 1b. Effective holds: repair any protection their acknowledged
        # guarantees require but the storage lacks (no state transition:
        # an effective hold is never downgraded).
        for hold_id in list(self.holds):
            h = self.holds[hold_id]
            if h["state"] == HOLD_EFFECTIVE:
                try:
                    self._establish(h, now)
                except StorageUnavailable:
                    pass  # retried by the next recovery; claims record progress
        # 2. Outstanding protection claims of every hold converge.
        for hold_id in list(self.holds):
            if self.claims.get(hold_id):
                self.reconcile_claims(hold_id)
        # 3. Purging items complete from their plans.
        for item_id, it in list(self.items.items()):
            if it["state"] == "purging":
                self.finish_purge_shared(item_id, now)
        # 4. Presence classification: only plan-verified absence completes.
        for item_id, it in list(self.items.items()):
            if it["state"] in ("disposal_pending", "purging"):
                if self.classify_presence(item_id) == "absent":
                    it["state"] = "disposed"


class StorageUnavailable(Exception):
    pass


class EstablishmentError(Exception):
    pass


class NewWorkFailClosed(Exception):
    pass
