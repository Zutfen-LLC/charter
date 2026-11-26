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
    identity.update(v=3, custodian_id=received["custodian_id"], input=received["input"],
                    sources=stable, model_id=received["model_registry_id"])
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
    for name, diagnostic, mutation, coherent in (
        ("positive", "", lambda f: None, False),
        ("wrong-excerpt", "exact rendered request", lambda f: render(f, "wrong text"), True),
        ("wrong-custodian", "source custodian differs", lambda f: binding(f).update(custodian_id="different-user"), True),
        ("wrong-length", "external byte range", lambda f: binding(f).update(length=1), True),
        ("missing-native-version", "external source identifier", lambda f: binding(f).update(provider_version=""), True),
        ("missing-release-provenance", "output and release must bind", lambda f: p(f, "response_released").pop("source_provenance_sha256"), False),
        ("wrong-fingerprint", "v3 request fingerprint", lambda f: p(f, "turn_received").update(request_fingerprint=sha256_bytes(b"other")), False),
        ("stale-dispatch-proof", "source_authorized_at is out of order", lambda f: p(f, "provider_accepted").update(source_authorized_at=f["events"][0]["recorded_at"]), False),
    ):
        f = build()
        mutation(f)
        if coherent:
            bind(f)
        yield dict(seal(f), name=name, diagnostic=diagnostic)


if __name__ == "__main__":
    (ROOT / "c06-source-bindings.json").write_text("[\n" + ",\n".join(
        json.dumps(f, ensure_ascii=False, sort_keys=True, separators=(",", ":")) for f in cases()) + "\n]\n")
