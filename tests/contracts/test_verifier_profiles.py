import copy
import json
import os
import unittest

from model import build_turn, verify_turn

FX = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "contracts")


def rehashed(name, edit):
    with open(os.path.join(FX, name)) as f:
        fixture = json.load(f)
    events = copy.deepcopy(fixture["events"])
    edit(events)
    steps = []
    for e in events:
        payload = e["payload"]
        if e["type"] == "evidence_ack":
            payload["acked_seq"] = "@prev"
        steps.append((e["type"], e["recorded_at"], e["actor"], payload))
    base = {k: events[0][k] for k in ("tenant_id", "project_id", "matter_id", "turn_id")}
    return build_turn(base, steps), {k: v.encode() for k, v in fixture["objects"].items()}


class VerifierProfileControls(unittest.TestCase):
    def test_evidence_ack_requires_receipt(self):
        events, objects = rehashed("complete-turn.json", lambda e: e[5]["payload"].pop("receipt"))
        self.assertIn("receipt", "\n".join(verify_turn(events, objects)))

    def test_evidence_ack_receipt_must_be_nonempty(self):
        events, objects = rehashed("complete-turn.json", lambda e: e[5]["payload"].update(receipt=""))
        self.assertIn("receipt", "\n".join(verify_turn(events, objects)))

    def test_intent_destination_matches_policy(self):
        def edit(events):
            events[1]["payload"]["destination"] = {"provider": "test-a", "endpoint_id": "ep-1", "model_id": "test-model"}
            events[4]["payload"]["provider"] = "other"
        events, objects = rehashed("complete-turn.json", edit)
        self.assertIn("destination", "\n".join(verify_turn(events, objects)))

    def test_provider_acceptance_matches_intent_destination(self):
        events, objects = rehashed("complete-turn.json", lambda e: e[6]["payload"].update(endpoint_id="other"))
        self.assertIn("destination", "\n".join(verify_turn(events, objects)))

    def test_unknown_disclosure_settles_reserved_maximum(self):
        events, objects = rehashed("unknown-disclosure.json", lambda e: e[6]["payload"].update(units=1))
        self.assertIn("reserved", "\n".join(verify_turn(events, objects)))

    def test_admission_actor_is_user(self):
        def edit(events): events[0].update(actor={"kind": "service", "id": "charter-control-plane"})
        events, objects = rehashed("complete-turn.json", edit)
        self.assertIn("actor", "\n".join(verify_turn(events, objects)))

    def test_recovery_actor_is_service(self):
        def edit(events): events[-1].update(actor={"kind": "user", "id": "u-custodian-1"})
        events, objects = rehashed("unknown-disclosure.json", edit)
        self.assertIn("actor", "\n".join(verify_turn(events, objects)))

    def test_legacy_summary_prose_neither_grants_nor_breaks_exact_verification(self):
        def edit(events): events[0]["payload"]["input_summary"] = "exact input: synthetic prompt"
        events, objects = rehashed("complete-turn.json", edit)
        self.assertEqual(verify_turn(events, objects), [])
