"""Generate C06 cross-language controls and deliberately rehashed negatives."""
import copy
import json

from gen_current_profile import ROOT, ROUTE, by_type, current, seal
from model import canonical, sha256_bytes


def ref(data):
    return {"sha256": sha256_bytes(data), "bytes": len(data)}


def p(f, typ):
    return by_type(f, typ)["payload"]


def source(f):
    return p(f, "context_sealed")["sources"][0]


def binding(f):
    return source(f)["external"]


def render(f, text):
    request = canonical({"model": ROUTE["model_id"],
                         "input": f["objects"][p(f, "turn_received")["input"]["sha256"]],
                         "excerpts": [{"source_id": source(f)["source_id"],
                                       "provider_version": binding(f)["provider_version"], "text": text}]})
    r = ref(request)
    f["objects"][r["sha256"]] = request.decode()
    sc = p(f, "context_sealed")
    sc["request_sha256"] = r["sha256"]
    sc["objects"] = [ref(f["objects"][source(f)["sha256"]].encode()), r]
    p(f, "disclosure_intent")["request"] = r


def bind(f):
    first = f["events"][0]
    received = first["payload"]
    sources = p(f, "context_sealed")["sources"]
    stable = copy.deepcopy(sources)
    for row in stable:
        for key in ("decision", "observed_at"):
            row["external"].pop(key, None)
    identity = {k: first[k] for k in ("matter_id", "tenant_id", "project_id")}
    # The v3 fingerprint binds the model selection as recorded on admission:
    # the explicitly requested registry model, or the empty string when the
    # selection was omitted (default resolution happens server-side).
    identity.update(v=3, custodian_id=received["custodian_id"], input=received["input"],
                    sources=stable, model_id=received.get("model_registry_id", ""))
    received["request_fingerprint"] = sha256_bytes(canonical(identity))
    for typ in ("output_recorded", "response_released"):
        p(f, typ)["source_provenance_sha256"] = sha256_bytes(canonical(sources))


def build():
    f = current("complete-turn.json")
    received = p(f, "turn_received")
    received.update(source_binding_version=1, model_registry_id="registry-a")
    content = "µ-source".encode()
    r = ref(content)
    f["objects"][r["sha256"]] = content.decode()
    p(f, "context_sealed")["sources"] = [dict(r, source_id="opaque-doc", version=0, external={
        "connector_id": "one-library", "provider": "sharepoint", "site_id": "site", "library_id": "lib",
        "external_tenant_id": "ext", "document_id": "opaque-doc", "provider_version": "1.0", "etag": "etag-1",
        "document_sha256": sha256_bytes(b"prefix:" + content), "delegated_subject": "provider-user",
        "custodian_id": received["custodian_id"], "offset": 7, "length": len(content),
        "extraction": "utf8-byte-range-v1", "decision": "allow", "observed_at": f["events"][0]["recorded_at"],
    })]
    p(f, "usage_reserved").update(accounting_version="charter-budget-v1", registry_model="registry-a")
    for typ in ("disclosure_intent", "provider_accepted", "response_released"):
        p(f, typ)["source_authorized_at"] = by_type(f, typ)["recorded_at"]
    p(f, "output_recorded")["provider_cost_units"] = p(f, "usage_settled")["units"]
    render(f, content.decode())
    bind(f)
    return f


def cases():
    # "det-a" is the documented default resolution for an omitted model
    # selection (docs/model-routing-and-budget.md). Registry identifiers are
    # never provider-native model identifiers: the rendered request keeps
    # binding the destination model (ROUTE["model_id"]).
    for name, diagnostic, mutation, coherent in (
        ("positive", "", lambda f: None, False),
        ("wrong-excerpt", "exact rendered request", lambda f: render(f, "wrong text"), True),
        ("wrong-custodian", "source custodian differs", lambda f: binding(f).update(custodian_id="different-user"), True),
        ("wrong-length", "external byte range", lambda f: binding(f).update(length=1), True),
        ("missing-native-version", "external source identifier", lambda f: binding(f).update(provider_version=""), True),
        ("missing-release-provenance", "output and release must bind", lambda f: p(f, "response_released").pop("source_provenance_sha256"), False),
        ("wrong-fingerprint", "v3 request fingerprint", lambda f: p(f, "turn_received").update(request_fingerprint=sha256_bytes(b"other")), False),
        ("impossible-observation", "source observation date is invalid", lambda f: binding(f).update(observed_at="2026-01-00T00:00:00.000Z"), True),
        ("stale-dispatch-proof", "source_authorized_at is out of order", lambda f: p(f, "provider_accepted").update(source_authorized_at=f["events"][0]["recorded_at"]), False),
        ("mismatched-registry-model", "reserved registry model differs from the explicitly requested registry model",
         lambda f: p(f, "usage_reserved").update(registry_model="registry-b"), True),
        ("omitted-model-default", "",
         lambda f: (p(f, "turn_received").pop("model_registry_id"), p(f, "usage_reserved").update(registry_model="det-a")), True),
        ("omitted-model-nondefault", "reserved registry model must be the documented default resolution",
         lambda f: (p(f, "turn_received").pop("model_registry_id"), p(f, "usage_reserved").update(registry_model="registry-b")), True),
    ):
        f = build()
        mutation(f)
        if coherent:
            bind(f)
        yield dict(seal(f), name=name, diagnostic=diagnostic)


def cut(f, keep):
    """Reduce the complete turn to a pre-seal prefix: no context_sealed."""
    f["events"] = [e for e in f["events"] if e["type"] in keep]
    return f


def terminate(f, stamp, reason="operator-cancelled"):
    """Append a valid terminal interruption to a pre-seal prefix."""
    terminal = copy.deepcopy(f["events"][-1])
    terminal.update(type="turn_interrupted", recorded_at=stamp)
    terminal["payload"] = {"reason": reason, "disclosure": "none"}
    f["events"].append(terminal)
    return f


def pre_seal_cases():
    # A legitimate partial or interrupted C06 turn can reserve usage before
    # context_sealed exists. The requested/reserved registry-model invariant
    # does not depend on context sealing, so these fixtures exercise the
    # reservation checks without any seal: terminal interruptions and
    # nonterminal prefixes (the latter keep the offline verifier's terminal
    # R3 complaint, tolerated explicitly).
    for name, diagnostic, tolerate, mutation, keep, interrupted in (
        ("pre-seal-explicit-binding", "", (),
         lambda f: None, ("turn_received", "policy_decision", "usage_reserved"), True),
        ("pre-seal-default-binding", "", (),
         lambda f: (p(f, "turn_received").pop("model_registry_id"), p(f, "usage_reserved").update(registry_model="det-a")),
         ("turn_received", "policy_decision", "usage_reserved"), True),
        ("pre-seal-interrupt-before-reservation", "", (),
         lambda f: None, ("turn_received", "policy_decision"), True),
        ("pre-seal-mismatched-registry-model",
         "reserved registry model differs from the explicitly requested registry model", (),
         lambda f: p(f, "usage_reserved").update(registry_model="registry-b"),
         ("turn_received", "policy_decision", "usage_reserved"), True),
        ("pre-seal-omitted-model-nondefault",
         "reserved registry model must be the documented default resolution", (),
         lambda f: (p(f, "turn_received").pop("model_registry_id"), p(f, "usage_reserved").update(registry_model="registry-b")),
         ("turn_received", "policy_decision", "usage_reserved"), True),
        ("pre-seal-missing-accounting",
         "C06 usage reservation requires C05 governed accounting", (),
         lambda f: (p(f, "usage_reserved").pop("accounting_version"), p(f, "usage_reserved").pop("registry_model")),
         ("turn_received", "policy_decision", "usage_reserved"), True),
        ("pre-seal-prefix-mismatched-registry-model",
         "reserved registry model differs from the explicitly requested registry model", ("R3",),
         lambda f: p(f, "usage_reserved").update(registry_model="registry-b"),
         ("turn_received", "policy_decision", "usage_reserved"), False),
        ("pre-seal-prefix-valid", "", ("R3",),
         lambda f: None, ("turn_received", "policy_decision", "usage_reserved"), False),
        ("sealed-interrupted", "", (),
         lambda f: None,
         ("turn_received", "policy_decision", "usage_reserved", "context_sealed", "disclosure_intent"), True),
    ):
        f = build()
        mutation(f)
        bind(f)  # keeps the admission fingerprint coherent with the mutation
        stamp = by_type(f, "turn_completed")["recorded_at"]
        cut(f, keep)
        if interrupted:
            terminate(f, stamp)
        yield dict(seal(f), name=name, diagnostic=diagnostic, tolerate=list(tolerate))


if __name__ == "__main__":
    (ROOT / "c06-source-bindings.json").write_text("[\n" + ",\n".join(
        json.dumps(f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for f in list(cases()) + list(pre_seal_cases())) + "\n]\n")
