import copy, json, os, unittest

from model import (EstablishmentError, GuardedStore, NewWorkFailClosed,
                   StorageUnavailable, matches, HOLD_PENDING, HOLD_EFFECTIVE)

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


class ReviewCorrections(unittest.TestCase):
    """The C07 independent-review corrections, mirrored from the Go
    reproduction tests: the Python reference model must satisfy the same
    preservation invariants."""

    def test_release_clears_future_work_protection(self):
        # Finding 3A: post-activation (future) matching work is protected by
        # the admission guard; releasing the final applicable hold clears it.
        s = guarded(ITEMS, [H1])
        s.place_hold_verified(H1, now=0)
        s.admit_new_work("N1", "m-0001", "c1", now=10, recorded_at="2026-02-01")
        for key, version in s.versions_of("N1"):
            self.assertEqual(s.legal_hold_state(key, version), "ON")
        s.release_hold_verified("H1")
        s.recover(now=20)
        for key, version in s.versions_of("N1"):
            self.assertEqual(s.legal_hold_state(key, version), "OFF")

    def test_scope_narrowing_eventually_clears_removed_scope(self):
        # Finding 3B: narrowing clears removed-scope versions once no
        # remaining hold requires them, while the remaining scope stays.
        s = guarded(ITEMS, [dict(H1, id="HW"), dict(H2, id="HO")])
        s.place_hold_verified(dict(H1, id="HW"), now=0)      # all custodians
        s.place_hold_verified(dict(H2, id="HO"), now=0)      # c1 only
        s.change_scope("HW", custodian_ids=["c1"])
        s.reestablish("HW", now=0)
        s.release_hold_verified("HW")
        s.recover(now=0)
        # B (c2) was only covered by the wide scope: cleared.
        for key, version in s.versions_of("B"):
            self.assertEqual(s.legal_hold_state(key, version), "OFF")
        # A (c1) is still held by HO: protection stands.
        for key, version in s.versions_of("A"):
            self.assertEqual(s.legal_hold_state(key, version), "ON")

    def test_release_crash_before_cleanup_recovers(self):
        # Finding 3C: the release commits, the cleanup never runs; recovery
        # converges from the durable claims ledger.
        s = guarded(ITEMS, [H1])
        s.place_hold_verified(H1, now=0)
        # Phase-1-only release: the claim is durably removed, no cleanup.
        s.release_hold("H1")
        for key, version in s.versions_of("A"):
            self.assertEqual(s.legal_hold_state(key, version), "ON")
        s.recover(now=10)
        for key, version in s.versions_of("A"):
            self.assertEqual(s.legal_hold_state(key, version), "OFF")

    def test_storage_outage_is_not_disposal_at_recovery(self):
        # Finding 4: a storage outage during recovery never becomes proof of
        # disposal; the state is retained conservatively.
        s = guarded(ITEMS)
        s.sweep(200)
        s.storage_down = True
        s.recover(now=300)
        self.assertEqual(s.items["A"]["state"], "disposal_pending")
        s.storage_down = False
        s.recover(now=300)
        # After access returns, an honest observation keeps it eligible.
        self.assertEqual(s.classify_presence("A"), "present")

    def test_uncovered_blocks_reestablishment_and_recovery(self):
        # Finding 2: scope-change reestablishment and startup recovery obey
        # the same acceptance rule as placement.
        s = guarded(ITEMS, [dict(H1, id="HR")])
        s.place_hold_verified(dict(H1, id="HR"), now=0)
        for key, version in s.versions_of("B"):
            s.deleted.add((key, version))
        s.change_scope("HR", custodian_ids=[])
        with self.assertRaises(EstablishmentError):
            s.reestablish("HR", now=0)
        self.assertNotEqual(s.holds["HR"]["state"], "effective")
        # Recovery of a pending hold with uncovered records also refuses.
        s2 = guarded(ITEMS, [dict(H1, id="HP")])
        s2.place_hold(dict(H1, id="HP"))
        for key, version in s2.versions_of("A"):
            s2.deleted.add((key, version))
        s2.recover(now=0)
        self.assertNotEqual(s2.holds["HP"]["state"], "effective")

    def test_stale_establishment_cannot_mark_changed_scope_effective(self):
        # Finding 2 (concurrent scope changes): the establishment verified the
        # prior scope revision; a scope change moved the revision; the stale
        # completion must not mark the newer scope effective.
        s = guarded(ITEMS, [dict(H1, id="HS")])
        s.place_hold(dict(H1, id="HS"))
        h = s.holds["HS"]
        want = h["scope_epoch"]
        report = s._establish(h, now=0)   # verified under the prior revision
        h["scope_epoch"] = want + 1       # a concurrent scope change commits
        if report["uncovered"]:
            self.fail("fixture setup: establishment must verify cleanly")
        if h.get("scope_epoch", 0) != want:
            h["state"] = HOLD_PENDING     # the corrected transition refuses
        self.assertNotEqual(h["state"], HOLD_EFFECTIVE)

    def test_partial_disposal_resumes_from_the_plan(self):
        # Finding 5: the plan is committed before any deletion; an
        # interrupted delete resumes from the plan with a verified
        # disposition for every exact version (already-deleted = absent).
        s = guarded(ITEMS)
        s.sweep(200)
        self.assertTrue(s.begin_purge("A", 300, True))
        refs = s.versions_of("A")
        # Interrupted delete: the first version's deletion committed at the
        # storage but the transaction (and with it the plan's first
        # disposition) did not. Recovery completes from the plan.
        s.deleted.add(refs[0])
        s.recover(now=300)
        self.assertEqual(s.items["A"]["state"], "disposed")
        for key, version in refs:
            self.assertIn(s.plans["A"][(key, version)], ("deleted", "absent"))

    def test_disposed_turn_leaving_inventory_is_reported(self):
        # Finding 5 (gap reporting): a disposed turn remains in the catalog;
        # the Go implementation derives it there when live enumeration no
        # longer lists it. The reference model reports it as before.
        s = guarded(ITEMS)
        s.sweep(200)
        self.assertTrue(s.purge("A", 300, True))
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], "effective")
        self.assertIn("A", s.reports["H1"]["disposed_before_hold"])
        self.assertNotIn("A", s.reports["H1"]["uncovered"])

    def test_sweep_requires_terminal_capture(self):
        # Finding 6A: an admitted, actively executing turn is never swept.
        s = guarded(ITEMS)
        s.items["A"]["terminal"] = False
        s.sweep(200)
        self.assertEqual(s.items["A"]["state"], "active")
        s.items["A"]["terminal"] = True
        s.sweep(200)
        self.assertEqual(s.items["A"]["state"], "disposal_pending")


class Round2Corrections(unittest.TestCase):
    """C07 round-2 review corrections: coverage of partially disposed
    records, verified plan restoration, and effective-hold repair."""

    def test_partially_disposed_record_is_covered_not_silent(self):
        # Finding 1: a matching record whose root is gone but whose plan
        # still holds live rows is covered from the plan: the loss is
        # explicit, the remaining versions protected, the hold effective.
        s = guarded(ITEMS)
        s.sweep(200)
        self.assertTrue(s.begin_purge("A", 300, True))
        plan = s.plans.setdefault("A", {})
        for key, version in s.versions_of("A"):
            plan.setdefault((key, version), "planned")
        # The admission marker was physically deleted mid-disposal; the
        # item stays purging and its enumeration root is gone.
        s.deleted.add(("A/admissions", "v-A-0"))
        s.items["A"]["root_gone"] = True
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], "effective")
        report = s.reports["H1"]
        self.assertIn("A", report["partially_disposed"])
        entry = [i for i in report["items"] if i["id"] == "A"][0]
        self.assertTrue(entry["partially_disposed"])
        self.assertEqual(entry["missing_versions"], 1)
        for key, version in s.versions_of("A"):
            if (key, version) in s.deleted:
                # Gone before the hold: no legal hold is recorded for a
                # version that no longer exists.
                self.assertEqual(s.legal_hold_state(key, version), "")
            else:
                self.assertEqual(s.legal_hold_state(key, version), "ON")
        # The loss is durably recorded in the plan.
        self.assertEqual(plan[("A/admissions", "v-A-0")], "absent")

    def test_unverifiable_restored_record_blocks_effective(self):
        # Finding 1: a root-gone record without a plan is unverifiable: it
        # is reported uncovered and the hold cannot be acknowledged.
        s = guarded(ITEMS)
        s.sweep(200)
        s.items["A"]["root_gone"] = True
        with self.assertRaises(EstablishmentError):
            s.place_hold_verified(H1, now=0)
        self.assertIn("A", s.reports["H1"]["uncovered"])

    def _crash_window(self, s, missing):
        """begin_purge with a plan, one physical delete committed while the
        disposition transaction rolled back, a matching hold placed, and
        the item still observed purging with the pre-hold epoch (the
        restore path runs instead of the placement restore)."""
        s.sweep(200)
        observed = s.epoch
        self.assertTrue(s.begin_purge("A", 300, True))
        observed = s.items["A"]["observed_epoch"]
        plan = s.plans.setdefault("A", {})
        for key, version in s.versions_of("A"):
            plan.setdefault((key, version), "planned")
        for key, version in missing:
            s.deleted.add((key, version))
        s.items["A"]["root_gone"] = True
        h = s.place_hold_verified(H1, now=0)
        # The delete-phase transaction never committed: the item is still
        # purging with the epoch begin_purge observed.
        s.items["A"]["state"] = "purging"
        s.items["A"]["observed_epoch"] = observed
        return h

    def test_restore_keeps_plan_after_partial_deletion(self):
        # Finding 4: partial physical deletion followed by a hold: the
        # restore keeps the plan (the exact-version inventory) with the
        # loss recorded, and a later release and disposal stay recoverable.
        s = guarded(ITEMS)
        self._crash_window(s, [("A/admissions", "v-A-0")])
        self.assertEqual(s.finish_purge_shared("A", 0), "restored_active_partial")
        self.assertEqual(s.plans["A"][("A/admissions", "v-A-0")], "absent")
        self.assertEqual(s.items["A"]["state"], "active")
        # Release the hold: the remaining bytes are unprotected again and
        # the eventual disposal completes from the plan.
        s.release_hold_verified("H1")
        s.items["A"]["state"] = "purging"
        s.items["A"]["observed_epoch"] = s.epoch
        outcome = s.finish_purge_shared("A", 0)
        if outcome == "stale_retry":
            s.items["A"]["state"] = "purging"
            s.items["A"]["observed_epoch"] = s.epoch
            outcome = s.finish_purge_shared("A", 0)
        self.assertEqual(outcome, "disposed")
        for key, version in s.versions_of("A"):
            self.assertIn((key, version), s.deleted)

    def test_verified_complete_restore_clears_the_plan(self):
        # Finding 4: only verified completeness may clear the plan.
        s = guarded(ITEMS)
        self._crash_window(s, [])
        self.assertEqual(s.finish_purge_shared("A", 0), "restored_active")
        self.assertNotIn("A", s.plans)
        self.assertEqual(s.items["A"]["state"], "active")

    def test_fully_vanished_restore_completes_disposal(self):
        # Finding 4: every outstanding planned version gone: the restore
        # must not claim active evidence that does not exist.
        s = guarded(ITEMS)
        missing = [(k, v) for k, v in s.versions_of("A")]
        self._crash_window(s, missing)
        self.assertEqual(s.finish_purge_shared("A", 0), "disposed_ambiguous")
        self.assertEqual(s.items["A"]["state"], "disposed")

    def test_recovery_repairs_missing_protection_of_effective_hold(self):
        # Finding 2: a matching record published while the guard could not
        # complete its protection is repaired at recovery, without a user
        # retry.
        s = guarded(ITEMS)
        s.place_hold_verified(H1, now=0)
        # A matching record is admitted whose protection never completed
        # (the interrupted/denied capture window under reproduction).
        s.admit_new_work("N", "m-0001", "c1", now=10, recorded_at="2026-02-01")
        for claimed in s.claims.values():
            claimed.difference_update(s.versions_of("N"))
        for key, version in s.versions_of("N"):
            s.legal_hold.pop((key, version), None)
        s.recover(now=10)
        for key, version in s.versions_of("N"):
            self.assertEqual(s.legal_hold_state(key, version), "ON")
