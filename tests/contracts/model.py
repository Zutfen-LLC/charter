"""Reference model for the Charter evidence contracts (ADR 0001).

Dependency-free so it runs without the scaffold from issue #2. It is an
executable statement of the rules, not the product implementation.
"""
import hashlib
import json

SCHEMA_VERSION = "1.0.0"


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
KNOWN = {"turn_received", "policy_decision", "usage_reserved", "context_sealed", "disclosure_intent",
         "evidence_ack", "provider_accepted", "output_recorded", "response_released", "usage_settled",
         "turn_completed", "turn_interrupted", "outcome_resolved"}
TERMINAL = ("turn_completed", "turn_interrupted")


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _ref(v):
    """{sha256, bytes} -> (sha, bytes) or None."""
    if isinstance(v, dict) and isinstance(v.get("sha256"), str) and SHA_RE.match(v["sha256"]) \
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
    table = {
        "start": {"turn_received": "received"},
        "received": {"policy_decision": "deny" if p.get("decision") == "deny" else "decided"},
        "denied": {"turn_completed": "terminal"},
        "decided": {"usage_reserved": "reserved"},
        "reserved": {"context_sealed": "sealed"},
        "sealed": {"disclosure_intent": "intent"},
        "intent": {"provider_accepted": "accepted", "usage_settled": "settled"},
        "accepted": {"output_recorded": "output", "usage_settled": "settled"},
        "output": {"response_released": "released", "usage_settled": "settled"},
        "released": {"usage_settled": "settled_released", "turn_completed": "terminal"},
        "settled_released": {"turn_completed": "terminal"},
    }
    if state == "received" and p.get("decision") == "deny":
        table["received"] = {"policy_decision": "denied"}
    return table.get(state, {}).get(typ)


def verify_turn(events, objects=None):
    """Return violation strings, each "seq N: [CODE] text" or "[CODE] text".
    Same rules and codes as the Go verifier (internal/evidence/verify.go).
    objects=None is structural-only verification; a dict is full verification."""
    errs = []
    add = lambda i, code, msg: errs.append((f"seq {i}: " if i >= 0 else "") + f"[{code}] {msg}")
    if not events:
        return ["[ENVELOPE] empty log"]
    first = events[0]
    acked, sealed, sealed_req, state = set(), None, None, "start"
    released = decided = denied = False
    declared = {}
    reserved_units = None
    policy_destination = intent_destination = None
    types = []
    for i, e in enumerate(events):
        if not isinstance(e, dict):
            add(i, "ENVELOPE", "event is not an object"); continue
        typ = e.get("type") if isinstance(e.get("type"), str) else ""
        types.append(typ)
        p = e.get("payload") if isinstance(e.get("payload"), dict) else {}
        v = e.get("schema_version")
        if not isinstance(v, str) or not SEMVER_RE.match(v):
            add(i, "ENVELOPE", "schema_version must be semantic-version text")
        elif not v.startswith("1."):
            add(i, "ENVELOPE", "unsupported schema_version")
        for k in ("tenant_id", "project_id", "matter_id", "turn_id"):
            if not isinstance(e.get(k), str) or not ID_RE.match(e[k]):
                add(i, "ENVELOPE", f"{k} must be an opaque lowercase identifier")
            elif e[k] != first.get(k):
                add(i, "ENVELOPE", f"{k} differs within the turn")
        if not TYPE_RE.match(typ):
            add(i, "ENVELOPE", "type must be a lowercase identifier")
        if not _int(e.get("seq")):
            add(i, "ENVELOPE", "seq must be an integer")
        ts = e.get("recorded_at")
        if not isinstance(ts, str) or not TS_RE.match(ts):
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
                or not isinstance(a.get("id"), str) or not ID_RE.match(a["id"]):
            add(i, "ENVELOPE", "actor must be {kind: user|service, id: identifier}")
        if not isinstance(e.get("payload"), dict):
            add(i, "ENVELOPE", "payload must be an object")
        if "prev_hash" not in e:
            add(i, "ENVELOPE", "prev_hash is required")
        elif e["prev_hash"] is not None and not (isinstance(e["prev_hash"], str) and SHA_RE.match(e["prev_hash"])):
            add(i, "ENVELOPE", "prev_hash must be null or sha256:<hex>")
        if not isinstance(e.get("event_hash"), str) or not SHA_RE.match(e["event_hash"]):
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
            if isinstance(p.get("input_summary"), str) and "exact input" in p["input_summary"].lower():
                add(i, "REFS", "legacy input_summary cannot claim exact input bytes")
            if "input" in p:
                if not _ref(p["input"]):
                    add(i, "REFS", "input must be a {sha256, bytes} reference")
            elif not isinstance(p.get("input_summary"), str):
                add(i, "REFS", "turn_received needs an input reference (or a legacy input_summary)")
        elif typ == "policy_decision":
            d = p.get("decision")
            if d == "allow" and isinstance(p.get("destination"), dict):
                policy_destination = p["destination"]
            if d not in ("allow", "deny"):
                add(i, "POLICY", "decision must be allow or deny")
            elif i != 1:
                add(i, "POLICY", "the policy decision must be seq 1")
            if decided:
                add(i, "POLICY", "repeated policy decision")
            decided, denied = True, d == "deny"
        elif typ == "usage_reserved":
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
            if not (isinstance(sealed_req, str) and SHA_RE.match(sealed_req)):
                add(i, "REFS", "request_sha256 missing or malformed"); sealed_req = None
            elif sealed_req not in sealed:
                add(i, "REFS", "request_sha256 is not among the sealed objects")
            srcs = p.get("sources")
            if not isinstance(srcs, list):
                add(i, "REFS", "context_sealed.sources must be a list"); srcs = []
            for sx in srcs:
                ok = isinstance(sx, dict) and isinstance(sx.get("source_id"), str) and sx["source_id"] \
                    and _int(sx.get("version")) and sx["version"] >= 0 \
                    and isinstance(sx.get("sha256"), str) and SHA_RE.match(sx["sha256"])
                if not ok:
                    add(i, "REFS", "malformed source reference")
                elif sx["sha256"] not in sealed:
                    add(i, "REFS", "source sha256 is not among the sealed objects")
        elif typ == "disclosure_intent":
            intent_destination = {k: p[k] for k in ("provider", "endpoint_id", "model_id") if isinstance(p.get(k), str)}
            if policy_destination is not None and any(policy_destination.get(k) != v for k, v in intent_destination.items()):
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
            if not isinstance(p.get("receipt"), str) or not p["receipt"].strip():
                add(i, "REFS", "evidence_ack.receipt is required and must be nonempty")
            if "storage_level" in p and (not isinstance(p["storage_level"], str) or not p["storage_level"].strip()):
                add(i, "REFS", "evidence_ack.storage_level must be nonempty when present")
            ak = p.get("acked_seq")
            if not _int(ak) or ak < 0 or ak >= i or events[ak].get("event_hash") != p.get("acked_event_hash") \
                    or not p.get("acked_event_hash"):
                add(i, "REFS", "ack does not match event")
            else:
                acked.update(range(ak + 1))
        elif typ == "provider_accepted":
            accepted_destination = {k: p[k] for k in ("provider", "endpoint_id", "model_id") if isinstance(p.get(k), str)}
            if intent_destination is not None and any(intent_destination.get(k) != v for k, v in accepted_destination.items()):
                add(i, "REFS", "provider acceptance destination differs from disclosure intent")
            idx = [j for j, x in enumerate(events[:i]) if isinstance(x, dict) and x.get("type") == "disclosure_intent"]
            if not idx or idx[-1] not in acked:
                add(i, "R1", "provider contacted before acked disclosure_intent")
        elif typ == "output_recorded":
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
            if not _int(p.get("units")) or p["units"] < 0:
                add(i, "REFS", "usage_settled.units must be a non-negative integer")
            elif reserved_units is not None and p.get("basis") == "reserved_max" and derive_disclosure(events[:i]) != "none" and p["units"] != reserved_units:
                add(i, "REFS", "usage_settled reserved_max units must equal the full reservation")
            if not isinstance(p.get("basis"), str) or not p["basis"]:
                add(i, "REFS", "usage_settled.basis is required")
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
            if isinstance(rs, str) and SHA_RE.match(rs) and sealed and rs in sealed:
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
