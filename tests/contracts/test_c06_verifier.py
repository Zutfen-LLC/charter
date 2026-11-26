import copy
import unittest

from model import build_turn, verify_turn, verify_current_full
import test_contracts


def rechain(events):
    base = {k: events[0][k] for k in ("tenant_id", "project_id", "matter_id", "turn_id")}
    steps = [(e["type"], e["recorded_at"], e["actor"], dict(e["payload"])) for e in events]
    for typ, _, _, payload in steps:
        if typ == "evidence_ack":
            payload["acked_seq"] = "@prev"
    return build_turn(base, steps)


class C06VerifierTests(unittest.TestCase):
    def test_shared_c06_binding_matrix(self):
        for fixture in test_contracts.load("c06-source-bindings.json"):
            with self.subTest(fixture=fixture["name"]):
                errors = verify_current_full(fixture["events"], test_contracts.objs(fixture))
                if fixture["diagnostic"]:
                    self.assertTrue(all("[C06]" in e for e in errors), errors)
                    self.assertTrue(any(fixture["diagnostic"] in e for e in errors), errors)
                else:
                    self.assertEqual([], errors)

    def test_output_without_source_provenance_is_rejected(self):
        fixture = test_contracts.load("complete-turn.json")
        events = copy.deepcopy(fixture["events"])
        events[0]["payload"]["source_binding_version"] = 1
        events[0]["payload"]["model_registry_id"] = "model-registry-a"
        events = rechain(events)
        errs = verify_turn(events, test_contracts.objs(fixture))
        self.assertTrue(any("C06" in error for error in errs), errs)

    def test_orphan_provenance_marker_is_rejected(self):
        fixture = test_contracts.load("complete-turn.json")
        events = copy.deepcopy(fixture["events"])
        events[0]["payload"]["source_binding_version"] = 1
        events[0]["payload"]["model_registry_id"] = "model-registry-a"
        events[-1]["payload"]["source_provenance_sha256"] = "sha256:" + "0" * 64
        events = rechain(events)
        errs = verify_turn(events, test_contracts.objs(fixture))
        self.assertTrue(any("C06" in error for error in errs), errs)


if __name__ == "__main__":
    unittest.main()
