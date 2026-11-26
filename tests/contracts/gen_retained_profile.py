"""Generate synthetic offline receipts. Not produced by or proof of storage."""
import copy
import json

from gen_current_profile import ROOT, current
from model import canonical, event_hash, sha256_bytes

PROFILE = "charter-s3-compliance-v1"
LEVEL = "s3:object-lock:COMPLIANCE"
DOMAIN = b"CHARTER-RETAINED-RECEIPT-v1\0"


def case(name, mutate=None, marker=PROFILE):
    f = copy.deepcopy(current("complete-turn.json"))
    first = f["events"][0]["payload"]
    if marker:
        first["evidence_profile"] = marker
    else:
        del first["evidence_profile"]
    prev = None
    for i, e in enumerate(f["events"]):
        e["prev_hash"] = prev
        if e["type"] == "evidence_ack":
            target = f["events"][i - 1]
            data = canonical(target)
            h, tenant, turn = target["event_hash"], target["tenant_id"], target["turn_id"]
            r = {"deployment": "synthetic-deployment", "tenant": tenant, "evidence_id": h,
                 "bucket": "charter-c04-synthetic", "version": f"synthetic-v-{i}", "sha256": sha256_bytes(data),
                 "key": f"charter/v1/synthetic-deployment/{tenant}/data/events/{turn}/{h}",
                 "length": len(data), "mode": "COMPLIANCE", "retain_until": "2030-01-01T00:00:00Z",
                 "seq": target["seq"], "event_hash": h}
            if mutate and i == 5:
                mutate(r)
            e["payload"].update(acked_seq=target["seq"], acked_event_hash=h, storage_level=LEVEL,
                                retained_receipt=r, receipt=sha256_bytes(DOMAIN + canonical(r)))
        e["event_hash"] = prev = event_hash(e)
    f.update(name=name, expect_code="" if name == "positive" else ("ENVELOPE" if not marker else "REFS"))
    return f


if __name__ == "__main__":
    cases = [case("positive"), case("profile-absent", marker=None)]
    for field, value in (("tenant", "someone-else"), ("key", "unrelated"), ("version", "null"),
                         ("sha256", sha256_bytes(b"wrong bytes")), ("length", 0), ("seq", 123),
                         ("mode", "GOVERNANCE"), ("retain_until", "2030-01-01T00:00:00+00:00"),
                         ("unexpected", "unknown field")):
        cases.append(case(f"rehash-wrong-{field}", lambda r: r.update({field: value})))
    (ROOT / "retained-profile.json").write_text(json.dumps(cases, indent=2) + "\n")
