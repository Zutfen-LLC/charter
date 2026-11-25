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


def verify_turn(events, objects=None):
    """Return a list of violation strings; empty means the log verifies."""
    errs, prev = [], None
    acked = set()  # seqs durably acknowledged
    types = [e["type"] for e in events]
    for i, e in enumerate(events):
        if e["seq"] != i:
            errs.append(f"seq {i}: out of order")
        if e["prev_hash"] != prev:
            errs.append(f"seq {i}: broken chain")
        if e["event_hash"] != event_hash(e):
            errs.append(f"seq {i}: hash mismatch")
        prev = e["event_hash"]
        t, p = e["type"], e["payload"]
        if t == "evidence_ack":
            a = p["acked_seq"]
            if a >= i or events[a]["event_hash"] != p["acked_event_hash"]:
                errs.append(f"seq {i}: ack does not match event")
            else:
                acked.update(range(a + 1))
        elif t == "policy_decision":
            if p.get("decision") not in ("allow", "deny"):
                errs.append(f"seq {i}: policy_decision must be allow or deny")
        elif t == "provider_accepted":
            idx = [j for j, x in enumerate(events[:i]) if x["type"] == "disclosure_intent"]
            if not idx or idx[-1] not in acked:
                errs.append(f"seq {i}: R1 provider contacted before acked disclosure_intent")
        elif t == "response_released":
            out = [j for j, x in enumerate(events[:i]) if x["type"] == "output_recorded"]
            if not out or out[-1] not in acked or not events[out[-1]]["payload"]["complete"]:
                errs.append(f"seq {i}: R2 response released before acked complete output")
        if t in ("context_sealed", "disclosure_intent", "provider_accepted", "response_released"):
            d = [x for x in events[:i] if x["type"] == "policy_decision"]
            if not d or d[-1]["payload"].get("decision") != "allow":
                errs.append(f"seq {i}: R4 {t} without a preceding allow policy_decision")
    terminals = [i for i, t in enumerate(types) if t in ("turn_completed", "turn_interrupted")]
    if len(terminals) != 1 or terminals[0] != len(events) - 1:
        errs.append("R3: exactly one terminal event, last")
    if "response_released" in types and types[-1] != "turn_completed":
        errs.append("R3: response released in a turn that did not complete")
    if objects is not None:
        for e in events:
            for ref in e["payload"].get("objects", []):
                data = objects.get(ref["sha256"])
                if data is None:
                    errs.append(f"missing object {ref['sha256']}")
                elif sha256_bytes(data) != ref["sha256"]:
                    errs.append(f"changed object {ref['sha256']}")
    return errs


def derive_disclosure(events):
    acked, intent_acked = set(), False
    for i, e in enumerate(events):
        if e["type"] == "evidence_ack":
            acked.update(range(e["payload"]["acked_seq"] + 1))
    for i, e in enumerate(events):
        if e["type"] == "disclosure_intent" and i in acked:
            intent_acked = True
    if any(e["type"] == "provider_accepted" for e in events):
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
