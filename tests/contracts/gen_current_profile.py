"""Generate synthetic current-profile verifier fixtures without modifying legacy goldens."""
import copy
import json
from pathlib import Path

from model import canonical, event_hash, sha256_bytes

ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "contracts"
PROFILE = "charter-postgres-v1"
LEVEL = "postgres:fsync=on,synchronous_commit=on"
ROUTE = {"provider": "test-a", "endpoint_id": "ep-1", "model_id": "test-model-a"}


def by_type(f, typ):
    return next(e for e in f["events"] if e["type"] == typ)


def seal(f, wrong_ack_target=False):
    prev = None
    for i, e in enumerate(f["events"]):
        e.update(seq=i, prev_hash=prev)
        if e["type"] == "evidence_ack":
            target = f["events"][i - (2 if wrong_ack_target and i == 5 else 1)]
            p = e["payload"]
            p.update(acked_seq=target["seq"], acked_event_hash=target["event_hash"])
            if p.get("receipt") == "@receipt":
                p["receipt"] = sha256_bytes(canonical({"backend": "postgres-append-only", "level": p.get("storage_level", LEVEL),
                    "tenant_id": target["tenant_id"], "turn_id": target["turn_id"],
                    "seq": target["seq"], "event_hash": target["event_hash"]}))
        e["event_hash"] = prev = event_hash(e)
    return f


def current(name):
    f = json.loads((ROOT / name).read_text())
    inp = b"synthetic exact original input"
    sha = sha256_bytes(inp)
    f["objects"][sha] = inp.decode()
    first = by_type(f, "turn_received")
    first["payload"] = {"evidence_profile": PROFILE, "request_id": "synthetic-request", "custodian_id": first["actor"]["id"],
        "input": {"sha256": sha, "bytes": len(inp)}, "objects": [{"sha256": sha, "bytes": len(inp)}]}
    by_type(f, "policy_decision")["payload"].update(route=ROUTE["endpoint_id"], destination=ROUTE.copy())
    by_type(f, "disclosure_intent")["payload"].update(ROUTE)
    for e in f["events"]:
        if e["type"] == "provider_accepted":
            e["payload"].update(ROUTE)
        if e["type"] == "evidence_ack":
            e["payload"].update(storage_level=LEVEL, receipt="@receipt")
    return f


def drop(f, typ, k):
    del by_type(f, typ)["payload"][k]


def update(f, typ, **change):
    by_type(f, typ)["payload"].update(change)


def omit(f, typ):
    f["events"] = [e for e in f["events"] if e["type"] != typ]


def with_unconfirmed_output(unknown, complete):
    f = copy.deepcopy(unknown)
    output = copy.deepcopy(by_type(complete, "output_recorded"))
    output["payload"]["complete"] = False
    for ref in output["payload"]["objects"]:
        f["objects"][ref["sha256"]] = complete["objects"][ref["sha256"]]
    ack = copy.deepcopy(by_type(complete, "evidence_ack"))
    i = next(i for i, e in enumerate(f["events"]) if e["type"] == "usage_settled")
    f["events"][i:i] = [output, ack]
    return f


def cases():
    complete, unknown = current("complete-turn.json"), current("unknown-disclosure.json")
    partial = with_unconfirmed_output(unknown, complete)
    yield "positive-complete", "", seal(copy.deepcopy(complete))
    yield "positive-unknown", "", seal(copy.deepcopy(unknown))
    yield "positive-unconfirmed-partial", "", seal(copy.deepcopy(partial))
    for name, code, source, mutate in (
        ("missing-policy-destination", "REFS", complete, lambda f: drop(f,"policy_decision","destination")),
        ("missing-intent-model", "REFS", complete, lambda f: drop(f,"disclosure_intent","model_id")),
        ("missing-accepted-provider", "REFS", complete, lambda f: drop(f,"provider_accepted","provider")),
        ("conflicting-policy-route", "REFS", complete, lambda f: update(f,"policy_decision",route="different")),
        ("conflicting-accepted-model", "REFS", complete, lambda f: update(f,"provider_accepted",model_id="different")),
        ("nontext-accepted-model", "REFS", complete, lambda f: update(f,"provider_accepted",model_id=23)),
        ("unbound-receipt", "REFS", complete, lambda f: update(f,"evidence_ack",receipt=sha256_bytes(b"unrelated"))),
        ("invalid-receipt", "REFS", complete, lambda f: update(f,"evidence_ack",receipt="invalid storage receipt")),
        ("missing-storage-level", "REFS", complete, lambda f: drop(f,"evidence_ack","storage_level")),
        ("non-durable-storage-level", "REFS", complete, lambda f: update(f,"evidence_ack",storage_level="postgres:fsync=off,synchronous_commit=off")),
        ("ack-wrong-event", "REFS", complete, lambda f: None),
        ("success-no-settlement", "LIFECYCLE", complete, lambda f: omit(f,"usage_settled")),
        ("unknown-no-settlement", "LIFECYCLE", unknown, lambda f: omit(f,"usage_settled")),
        ("unknown-wrong-basis", "REFS", unknown, lambda f: update(f,"usage_settled",basis="provider_reported")),
        ("unknown-under-reserved", "REFS", unknown, lambda f: update(f,"usage_settled",units=1)),
        ("unconfirmed-output-complete", "LIFECYCLE", partial, lambda f: update(f,"output_recorded",complete=True)),
        ("unconfirmed-output-before-intent-ack", "R1", partial, lambda f: f["events"].pop(5)),
        ("admission-custodian-mismatch", "ENVELOPE", complete, lambda f: update(f,"turn_received",custodian_id="different")),
        ("summary-only-current", "REFS", complete, lambda f: (drop(f,"turn_received","input"), update(f,"turn_received",input_summary="description only"))),
        ("unknown-profile", "ENVELOPE", complete, lambda f: update(f,"turn_received",evidence_profile="unknown")),
        ("identifier-trailing-newline", "ENVELOPE", complete, lambda f: [e.update(tenant_id=e["tenant_id"]+"\n") for e in f["events"]]),
    ):
        f = copy.deepcopy(source)
        mutate(f)
        yield name, code, seal(f, name == "ack-wrong-event")


if __name__ == "__main__":
    target = ROOT / "current-profile.json"
    target.write_text("[\n" + ",\n".join(json.dumps({"name": name, "expect_code": code, "events": f["events"], "objects": f["objects"]},
                                         ensure_ascii=False, sort_keys=True, separators=(",", ":")) for name, code, f in cases()) + "\n]\n")
