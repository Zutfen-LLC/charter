import copy, json, os, unittest
from model import (Store, build_turn, canonical, derive_disclosure, sha256_bytes, verify_turn)
import gen_fixtures

FX = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "contracts")
def load(n):
    with open(os.path.join(FX, n)) as f:
        return json.load(f)
objs = lambda f: {k: v.encode() for k, v in f["objects"].items()}


class Golden(unittest.TestCase):
    def test_fixtures_match_generator(self):
        # Changing a golden hash is a MAJOR contract change (docs/contracts/versioning.md).
        import tempfile
        old = gen_fixtures.OUT
        with tempfile.TemporaryDirectory() as d:
            gen_fixtures.OUT = d
            gen_fixtures.main()
            for n in os.listdir(d):
                self.assertEqual(open(os.path.join(d, n)).read(), open(os.path.join(FX, n)).read(), n)
        gen_fixtures.OUT = old

    def test_floats_rejected(self):
        with self.assertRaises(ValueError):
            canonical({"x": 1.5})

    def test_canonical_is_key_order_independent(self):
        self.assertEqual(canonical({"b": 1, "a": 2}), canonical({"a": 2, "b": 1}))


class Canonical(unittest.TestCase):
    def test_vectors(self):
        for v in load("canonical-vectors.json")["vectors"]:
            c = canonical(v["value"])
            self.assertEqual(c.hex(), v["canonical_utf8_hex"], v["name"])
            self.assertEqual(sha256_bytes(c), v["sha256"], v["name"])

    def test_utf16_order_not_code_point_order(self):
        self.assertEqual(canonical({"\ue000": 1, "\U00010000": 2}).decode(),
                         '{"\U00010000":2,"\ue000":1}')

    def test_rejects_unsafe_values(self):
        for bad in (2**53, {"s": "\ud800"}, {"f": 1.0}, {"x": object()}):
            with self.assertRaises(ValueError):
                canonical(bad)


class Turns(unittest.TestCase):
    def test_complete_turn_verifies(self):
        f = load("complete-turn.json")
        self.assertEqual(verify_turn(f["events"], objs(f)), [])
        self.assertEqual(derive_disclosure(f["events"]), "disclosed")

    def test_interrupted_mid_stream_verifies_and_not_released(self):
        f = load("interrupted-mid-stream.json")
        self.assertEqual(verify_turn(f["events"], objs(f)), [])
        self.assertNotIn("response_released", [e["type"] for e in f["events"]])
        self.assertEqual(derive_disclosure(f["events"]), "disclosed")

    def test_provider_disclosure_with_unknown_outcome(self):
        f = load("unknown-disclosure.json")
        self.assertEqual(verify_turn(f["events"], objs(f)), [])
        self.assertEqual(derive_disclosure(f["events"]), "unknown")
        last = f["events"][-1]["payload"]
        self.assertEqual((last["reason"], last["disclosure"]), ("crash_recovery", "unknown"))
        settled = [e for e in f["events"] if e["type"] == "usage_settled"][0]
        self.assertEqual(settled["payload"]["basis"], "reserved_max")

    def test_crash_before_intent_ack_is_not_disclosure(self):
        f = load("crash-before-intent-ack.json")
        self.assertEqual(verify_turn(f["events"], objs(f)), [])
        self.assertEqual(derive_disclosure(f["events"]), "none")

    # negative paths
    def test_tampered_event_detected(self):
        ev = copy.deepcopy(load("complete-turn.json")["events"])
        ev[1]["payload"]["route"] = "other"
        self.assertTrue(any("hash mismatch" in e for e in verify_turn(ev)))

    def test_missing_object_detected(self):
        f = load("complete-turn.json"); o = objs(f); o.pop(sha256_bytes(f["objects"][next(iter(f["objects"]))].encode()), None)
        self.assertTrue(any("missing object" in e for e in verify_turn(f["events"], o)))

    def test_changed_object_detected(self):
        f = load("complete-turn.json"); o = objs(f); k = next(iter(o)); o[k] += b"x"
        self.assertTrue(any("changed object" in e for e in verify_turn(f["events"], o)))

    def test_release_before_output_ack_rejected(self):
        f = load("complete-turn.json")
        steps = []
        for e in f["events"]:
            if e["type"] == "evidence_ack" and e["payload"]["acked_seq"] == 7:
                continue
            steps.append((e["type"], e["recorded_at"], e["actor"], dict(e["payload"])))
        for st in steps:
            if st[0] == "evidence_ack":
                st[3]["acked_seq"] = "@prev"
        base = {k: f["events"][0][k] for k in ("tenant_id", "project_id", "matter_id", "turn_id")}
        self.assertTrue(any("R2" in e for e in verify_turn(build_turn(base, steps))))

    def test_denied_turn_cannot_disclose_or_release(self):
        f = load("complete-turn.json")
        steps = []
        for e in f["events"]:
            p = dict(e["payload"])
            if e["type"] == "evidence_ack":
                p["acked_seq"] = "@prev"
            steps.append((e["type"], e["recorded_at"], e["actor"], p))
        steps[1][3]["decision"] = "deny"
        base = {k: f["events"][0][k] for k in ("tenant_id", "project_id", "matter_id", "turn_id")}
        errs = verify_turn(build_turn(base, steps))
        for t in ("context_sealed", "disclosure_intent", "provider_accepted", "response_released"):
            self.assertTrue(any(f"R4 {t}" in e for e in errs), t)

    def test_provider_contact_before_intent_ack_rejected(self):
        f = load("complete-turn.json")
        steps = [(e["type"], e["recorded_at"], e["actor"], dict(e["payload"])) for e in f["events"]
                 if not (e["type"] == "evidence_ack" and e["payload"]["acked_seq"] == 4)]
        base = {k: f["events"][0][k] for k in ("tenant_id", "project_id", "matter_id", "turn_id")}
        self.assertTrue(any("R1" in e for e in verify_turn(build_turn(base, steps))))


class Holds(unittest.TestCase):
    def store(self):
        f = load("holds.json")
        return Store(f["items"], f["holds"]), f["holds"]

    def test_hold_placed_before_sweep(self):          # case A
        s, _ = self.store(); s.holds.clear(); s.place_hold(load("holds.json")["holds"][0])
        s.sweep(200)
        self.assertEqual({i["id"]: i["state"] for i in s.items.values()},
                         {"A": "active", "B": "active", "C": "disposal_pending"})

    def test_hold_between_sweep_and_purge(self):      # case B (concurrent hold/expiry)
        f = load("holds.json"); s = Store(f["items"]); s.sweep(200)
        self.assertTrue(all(i["state"] == "disposal_pending" for i in s.items.values()))
        s.place_hold(f["holds"][0])
        self.assertFalse(s.purge("A", 300, True))
        self.assertEqual(s.items["A"]["state"], "active")
        self.assertTrue(s.purge("C", 300, True))      # unheld control expires
        self.assertEqual(s.items["C"]["state"], "disposed")

    def test_hold_acknowledged_during_inflight_purge(self):   # case F
        f = load("holds.json"); s = Store(f["items"]); s.sweep(200)
        self.assertTrue(s.begin_purge("A", 300, True))        # tombstoned, bytes still present
        s.place_hold(f["holds"][0])                           # hold acked before delete commits
        self.assertEqual(s.items["A"]["state"], "active")
        self.assertEqual(s.finish_purge("A"), "not_purging")  # delete is refused

    def test_stale_epoch_delete_never_blind(self):
        f = load("holds.json"); s = Store(f["items"]); s.sweep(200)
        self.assertTrue(s.begin_purge("B", 300, True))
        s.epoch += 1                                          # unrelated hold change commits
        self.assertEqual(s.finish_purge("B"), "stale_retry")
        self.assertEqual(s.items["B"]["state"], "disposal_pending")
        self.assertTrue(s.begin_purge("B", 300, True))
        self.assertEqual(s.finish_purge("B"), "disposed")

    def test_hold_after_disposal_records_gap(self):   # case C
        f = load("holds.json"); s = Store(f["items"]); s.sweep(200); s.purge("A", 300, True)
        s.place_hold(f["holds"][0])
        self.assertEqual(s.gaps, [{"hold": "H1", "item": "A", "gap": "disposed_before_hold"}])

    def test_purge_requires_records_officer_and_grace(self):
        f = load("holds.json"); s = Store(f["items"]); s.sweep(200)
        self.assertFalse(s.purge("C", 300, False))
        self.assertFalse(s.purge("C", 203, True))

    def test_release_one_of_overlapping_holds(self):  # case D
        s, _ = self.store()
        s.release_hold("H1")
        self.assertTrue(s.held(s.items["A"]))         # still in H2
        self.assertFalse(s.held(s.items["B"]))        # only in H1
        s.sweep(200)
        self.assertEqual(s.items["A"]["state"], "active")
        self.assertEqual(s.items["B"]["state"], "disposal_pending")
        self.assertEqual(s.items["C"]["state"], "disposal_pending")

    def test_release_all_makes_eligible(self):        # case E
        s, _ = self.store(); s.release_hold("H1"); s.release_hold("H2"); s.sweep(200)
        self.assertTrue(all(i["state"] == "disposal_pending" for i in s.items.values()))

    def test_holds_never_cross_matters(self):
        s, _ = self.store()
        self.assertFalse(s.held(s.items["C"]))


if __name__ == "__main__":
    unittest.main()
