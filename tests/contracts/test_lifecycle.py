import copy, json, os, unittest

from model import (EstablishmentError, GuardedStore, NewWorkFailClosed,
                   StorageUnavailable, matches)

FX = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "contracts")


def load(n):
    with open(os.path.join(FX, n)) as f:
        return json.load(f)


def guarded(items, holds=()):
    return GuardedStore([dict(i) for i in items], [dict(h) for h in holds])


ITEMS = [
    {"id": "A", "matter_id": "m-0001", "custodian_id": "c1", "recorded_at": "2026-01-10", "retention_expires_at": 100},
    {"id": "B", "matter_id": "m-0001", "custodian_id": "c2", "recorded_at": "2026-01-11", "retention_expires_at": 100},
    {"id": "C", "matter_id": "m-0002", "custodian_id": "c1", "recorded_at": "2026-01-12", "retention_expires_at": 100},
]
H1 = {"id": "H1", "matter_id": "m-0001", "custodian_ids": [], "window_start": "2026-01-01", "window_end": None}
H2 = {"id": "H2", "matter_id": "m-0001", "custodian_ids": ["c1"], "window_start": "2026-01-01", "window_end": None}


class Establishment(unittest.TestCase):
    def test_effective_requires_verified_protection(self):
        s = guarded(ITEMS, [H1])
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], "effective")
        report = s.reports["H1"]
        self.assertEqual({i["id"] for i in report["items"]}, {"A", "B"})
        for key, version in report["protected_versions"]:
            self.assertEqual(s.legal_hold_state(key, version), "ON")

    def test_storage_outage_leaves_hold_failed_not_effective(self):
        s = guarded(ITEMS, [H1])
        s.storage_down = True
        with self.assertRaises(EstablishmentError):
            s.place_hold_verified(H1, now=0)
        self.assertEqual(s.holds["H1"]["state"], "failed")
        # The fence still blocks disposal: a failed hold never weakens.
        s.storage_down = False
        s.sweep(200)
        self.assertEqual(s.items["A"]["state"], "active")

    def test_readback_lies_block_effective(self):
        s = guarded(ITEMS, [H1])
        s.readback_lies = True
        with self.assertRaises(EstablishmentError):
            s.place_hold_verified(H1, now=0)
        self.assertEqual(s.holds["H1"]["state"], "failed")

    def test_disposed_before_hold_is_reported(self):
        s = guarded(ITEMS)
        s.sweep(200)
        self.assertTrue(s.purge("A", 300, True))
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], "effective")
        self.assertEqual(s.reports["H1"]["disposed_before_hold"], ["A"])

    def test_uncovered_records_block_effective(self):
        s = guarded(ITEMS, [H1])
        # Versions of A vanished before placement.
        for key, version in s.versions_of("A"):
            s.deleted.add((key, version))
        with self.assertRaises(EstablishmentError):
            s.place_hold_verified(H1, now=0)
        self.assertEqual(s.holds["H1"]["state"], "failed")
        self.assertIn("A", s.reports["H1"]["uncovered"])

    def test_already_expired_records_are_reported_not_assumed(self):
        s = guarded(ITEMS, [H1])
        h = s.place_hold_verified(H1, now=150)  # past retention
        self.assertEqual(h["state"], "effective")
        self.assertEqual(set(s.reports["H1"]["already_expired"]), {"A", "B"})


class NewWork(unittest.TestCase):
    def test_matching_new_work_is_protected_on_admission(self):
        s = guarded(ITEMS, [H1])
        s.place_hold_verified(H1, now=0)
        outcome = s.admit_new_work("N1", "m-0001", "c1", now=10, recorded_at="2026-02-01")
        self.assertEqual(outcome, "admitted-protected")
        for key, version in s.versions_of("N1"):
            self.assertEqual(s.legal_hold_state(key, version), "ON")

    def test_unmatching_new_work_is_admitted_without_hold(self):
        s = guarded(ITEMS, [H1])
        s.place_hold_verified(H1, now=0)
        self.assertEqual(s.admit_new_work("N2", "m-0002", "c1", now=10, recorded_at="2026-02-01"), "admitted")
        self.assertEqual(s.legal_hold_state(*s.versions_of("N2")[0]), "")

    def test_new_work_fails_closed_when_protection_fails(self):
        s = guarded(ITEMS, [H1])
        s.place_hold_verified(H1, now=0)
        s.storage_down = True
        with self.assertRaises(NewWorkFailClosed):
            s.admit_new_work("N3", "m-0001", "c1", now=10, recorded_at="2026-02-01")
        self.assertNotIn("N3", s.items)  # nothing escaped

    def test_pending_and_failed_holds_fence_new_work_too(self):
        s = guarded(ITEMS, [dict(H1, id="HP")])
        # Phase-1-only hold: pending, protection not yet established.
        s.place_hold(dict(H1, id="HP"))
        self.assertTrue(s.hold_applies("m-0001", "c1", "2026-02-01"))


class ReleaseCleanup(unittest.TestCase):
    def test_release_keeps_legal_hold_while_another_hold_requires_it(self):
        s = guarded(ITEMS, [H1, H2])
        s.place_hold_verified(H1, now=0)
        s.place_hold_verified(H2, now=0)
        s.release_hold_verified("H1")
        # c1's item A is still held by H2 (custodian-scoped).
        for key, version in s.versions_of("A"):
            if (key, version) in [tuple(p) for p in s.reports["H1"]["protected_versions"]]:
                self.assertEqual(s.legal_hold_state(key, version), "ON")
        # c2's item B had only H1: its protection is cleared.
        for key, version in s.versions_of("B"):
            self.assertEqual(s.legal_hold_state(key, version), "OFF")

    def test_release_cleanup_failure_leaves_protection_in_place(self):
        s = guarded(ITEMS, [H1])
        s.place_hold_verified(H1, now=0)
        s.storage_down = True
        pending = s.release_hold_verified("H1")
        self.assertTrue(pending)  # conservatively over-protected, recorded
        s.storage_down = False
        for key, version in s.versions_of("A"):
            self.assertEqual(s.legal_hold_state(key, version), "ON")

    def test_shared_object_stays_protected_while_the_other_reference_holds(self):
        # Two items share one content-addressed object; only one is held.
        s = guarded(ITEMS, [H2])  # H2 covers custodian c1 (item A)
        s.shared_object["B"] = "A-obj"  # B references the same object version
        s.place_hold_verified(H2, now=0)
        self.assertIn(("shared/A-obj", "v-A-obj-3"), s.versions_of("B"))
        # While A is held, releasing another hold on the shared matter keeps
        # the shared version protected (B still references it under H1).
        s.place_hold_verified(dict(H1, id="H1b"), now=0)
        s.release_hold_verified("H2")
        self.assertEqual(s.legal_hold_state("shared/A-obj", "v-A-obj-3"), "ON")


class SharedDisposal(unittest.TestCase):
    def test_disposal_of_unheld_reference_keeps_shared_bytes(self):
        s = guarded(ITEMS)
        s.shared_object["B"] = "A-obj"  # B (active) references A's object
        s.sweep(200)
        # A disposes while its shared object version is also referenced by
        # the still-active B: the bytes must survive.
        s.begin_purge("A", 300, True)
        outcome = s.finish_purge_shared("A", 300)
        self.assertEqual(outcome, "disposed")
        key, version = "shared/A-obj", "v-A-obj-3"
        self.assertNotIn((key, version), s.deleted)

    def test_disposal_blocked_by_base_retention_reports_honestly(self):
        s = guarded(ITEMS)
        s.sweep(200)
        s.begin_purge("A", 300, True)
        # Unexpired base retention refuses the delete.
        for key, version in s.versions_of("A"):
            s.protect_until[(key, version)] = 10_000
        self.assertEqual(s.finish_purge_shared("A", 300), "blocked_by_storage")
        self.assertEqual(s.items["A"]["state"], "purging")  # never claimed disposed


class ReportFixtures(unittest.TestCase):
    def test_positive_report_is_valid(self):
        f = load("lifecycle-report.json")
        r = f["positive"]["report"]
        self.assertEqual(f["positive"]["hold"]["state"], "effective")
        self.assertEqual(r["uncovered"], [])
        self.assertEqual(r["disposed_before_hold"], ["D"])
        # Every in-scope item is either covered or reported as a gap.
        covered = {i["turn_id"] for i in r["items"]}
        gaps = set(r["disposed_before_hold"]) | set(r["uncovered"])
        in_scope = {i["id"] for i in f["in_scope_items"]
                    if i["matter_id"] == f["matter_id"]}
        self.assertEqual(in_scope - covered - gaps, set())

    def test_negative_report_violates_the_effective_invariant(self):
        f = load("lifecycle-report.json")
        n = f["negative_effective_with_uncovered"]
        self.assertEqual(n["hold"]["state"], "effective")
        # An effective hold may not have uncovered records: the fixture pins
        # the tampered shape the verifier must reject.
        self.assertNotEqual(n["report"]["uncovered"], [])


class ModelParity(unittest.TestCase):
    def test_guarded_store_matches_reference_matching(self):
        s = guarded(ITEMS, [H1, H2])
        self.assertTrue(matches(s.holds["H1"], ITEMS[0]))
        self.assertTrue(matches(s.holds["H2"], ITEMS[0]))
        self.assertFalse(matches(s.holds["H2"], ITEMS[1]))
        self.assertFalse(matches(s.holds["H1"], ITEMS[2]))

    def test_state_machine_cases_still_hold_under_guarded_store(self):
        # The C03 reference state machine cases A-G remain valid when the
        # guarded (C07) store runs them: protection never weakens them.
        from test_contracts import Holds
        f = load("holds.json")
        for hold in f["holds"]:
            s = GuardedStore([dict(i) for i in f["items"]])
            s.place_hold(hold)
            for it in s.items.values():
                if matches(s.holds[hold["id"]], it):
                    self.assertEqual(it["state"], "active")
        self.assertTrue(issubclass(GuardedStore, type(Holds().store()[0])))


if __name__ == "__main__":
    unittest.main()
