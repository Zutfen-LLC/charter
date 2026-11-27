import os
import unittest

from model import (EstablishmentError, GuardedStore, HOLD_EFFECTIVE,
                   HOLD_PENDING)

FX = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "contracts")


def guarded(items, holds=()):
    return GuardedStore([dict(i) for i in items], [dict(h) for h in holds])


ITEMS = [
    {"id": "A", "matter_id": "m-0001", "custodian_id": "c1", "recorded_at": "2026-01-10", "retention_expires_at": 100},
    {"id": "B", "matter_id": "m-0001", "custodian_id": "c2", "recorded_at": "2026-01-11", "retention_expires_at": 100},
    {"id": "C", "matter_id": "m-0002", "custodian_id": "c1", "recorded_at": "2026-01-12", "retention_expires_at": 100},
]
H1 = {"id": "H1", "matter_id": "m-0001", "custodian_ids": [], "window_start": "2026-01-01", "window_end": None}
H2 = {"id": "H2", "matter_id": "m-0002", "custodian_ids": [], "window_start": "2026-01-01", "window_end": None}


class Round3Corrections(unittest.TestCase):
    """C07 round-3 review corrections mirrored in the reference model.

    The Go evidence (charter-c07-correction3/red/) carries the RED
    reproductions at the reviewed head 702bb2f; the Python tests here pin
    the corrected semantics (finding-1's chain-broken fallback parity and
    the finding-3/finding-4 corrections are naturally RED at the reviewed
    model too)."""

    # ---- finding 3: plan-backed terminality for interrupted disposals ----

    def test_sweep_resumes_interrupted_disposal_after_terminal_evidence_loss(self):
        # The terminal evidence was deleted mid-disposal: the live probe
        # reports non-terminal (missing evidence), but the durable plan is
        # positive proof of previously verified terminality, so the record
        # stays eligible after release and reaches a verified disposition.
        s = guarded(ITEMS)
        s.sweep(200)
        self.assertTrue(s.begin_purge("A", 300, True))
        # The plan phase commits before any deletion.
        refs = s.versions_of("A")
        s.finish_purge_shared("A", 300) if False else None  # (plan committed below)
        plan = s.plans.setdefault("A", {})
        for kv in refs:
            plan.setdefault(kv, "planned")
        # Interrupted after the admission and the terminal slot marker were
        # deleted; the live terminality probe now reports non-terminal.
        s.deleted.add(refs[0])
        s.deleted.add(refs[1])
        s.items["A"]["root_gone"] = True
        s.items["A"]["terminal"] = False
        # A matching hold is placed, then released (its claims reconcile).
        s.items["A"]["state"] = "active"
        h = s.place_hold_verified(H1, now=300)
        self.assertEqual(h["state"], HOLD_EFFECTIVE)
        s.release_hold("H1")
        s.reconcile_claims("H1")
        # The ordinary sweep still marks the record: the plan backs its
        # previously verified terminality (C07 round-3 finding 3).
        s.sweep(400)
        self.assertEqual(s.items["A"]["state"], "disposal_pending")
        self.assertTrue(s.begin_purge("A", 500, True))
        outcome = s.finish_purge_shared("A", 500)
        self.assertEqual(s.items["A"]["state"], "disposed")
        self.assertIn(outcome, ("disposed", None))

    def test_in_flight_capture_is_never_swept_by_plan_backed_terminality(self):
        # An in-flight capture has no plan: the live probe's non-terminal
        # answer stays authoritative and it is never swept.
        s = guarded(ITEMS)
        s.items["A"]["terminal"] = False
        s.sweep(200)
        self.assertEqual(s.items["A"]["state"], "active")

    # ---- finding 4: effective-hold repair gaps are durably recorded ----

    def test_recover_records_pending_repair_for_uncovered_records(self):
        # An effective hold's coverage pass leaves a matching record
        # UNCOVERED with a nil error (its inventory is unverifiable):
        # recovery records PENDING repair state and an attributable audit
        # row instead of silently discarding the condition.
        s = guarded(ITEMS, [H1])
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], HOLD_EFFECTIVE)
        # A matching record whose live enumeration root is gone and which
        # has no plan is unverifiable -> uncovered with no error.
        s.admit_new_work("N", "m-0001", "c1", now=10, recorded_at="2026-02-01")
        s.items["N"]["root_gone"] = True
        s.recover(now=10)
        report = s.holds["H1"]["report"]
        self.assertIn("N", report.get("repair_pending", []))
        actions = [a["action"] for a in s.reverify_audit if a["hold_id"] == "H1"]
        self.assertIn("hold.protection_repair_pending", actions)

    def test_pending_repair_resolves_without_erasing_history(self):
        # The gap is repaired on a subsequent recovery: the pending state
        # resolves (verified repair) and the audit trail keeps the
        # historical pending evidence.
        s = guarded(ITEMS, [H1])
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], HOLD_EFFECTIVE)
        s.admit_new_work("N", "m-0001", "c1", now=10, recorded_at="2026-02-01")
        s.items["N"]["root_gone"] = True
        s.recover(now=10)
        self.assertIn("N", s.holds["H1"]["report"].get("repair_pending", []))
        # The record becomes verifiable again; the next recovery resolves
        # the outstanding repair state.
        s.items["N"]["root_gone"] = False
        s.recover(now=20)
        self.assertEqual(s.holds["H1"]["report"].get("repair_pending"), [])
        actions = [a["action"] for a in s.reverify_audit if a["hold_id"] == "H1"]
        self.assertIn("hold.protection_repair_pending", actions)
        self.assertIn("hold.protection_repair_complete", actions)

    def test_failed_repair_is_distinguished_from_pending(self):
        # A coverage pass that ERRORS records FAILED repair (the error
        # detail), distinct from a PENDING repair (uncovered, no error).
        s = guarded(ITEMS, [H1])
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], HOLD_EFFECTIVE)
        s.admit_new_work("N", "m-0001", "c1", now=10, recorded_at="2026-02-01")
        s.storage_down = True
        s.recover(now=10)
        s.storage_down = False
        self.assertEqual(s.holds["H1"]["report"].get("repair_error"),
                         "storage unavailable")
        self.assertFalse(s.holds["H1"]["report"].get("repair_pending"))

    # ---- finding 1: chain-broken siblings keep fencing shared references ----

    def test_chain_broken_sibling_fences_admission_only_shared_object(self):
        # Two records share one exact content-addressed version; the
        # sibling's chain is broken (its verified enumeration is
        # unavailable and it has no disposal plan), so its reference set
        # resolves through the namespace fallback - which includes the
        # admission-carried references. The disposal of the first record
        # must retain the shared version.
        s = guarded(ITEMS)
        s.shared_object["A"] = "shared-r3"
        s.shared_object["B"] = "shared-r3"
        s.items["B"]["chain_broken"] = True
        s.sweep(200)
        self.assertTrue(s.begin_purge("A", 300, True))
        outcome = s.finish_purge_shared("A", 300)
        self.assertEqual(s.items["A"]["state"], "disposed")
        shared = [kv for kv in s.plans["A"] if kv[0] == "shared/shared-r3"]
        self.assertTrue(shared)
        for kv in shared:
            self.assertEqual(s.plans["A"][kv], "retained_shared")

    def test_chain_broken_required_record_blocks_protection_removal(self):
        # A held, chain-broken record still requires its admission-only
        # shared object: releasing the other hold does not clear the
        # shared version's legal hold.
        s = guarded(ITEMS, [H1, H2])
        s.shared_object["A"] = "shared-r3b"
        s.shared_object["C"] = "shared-r3b"
        h1 = s.place_hold_verified(H1, now=0)
        h2 = s.place_hold_verified(H2, now=0)
        self.assertEqual(h1["state"], HOLD_EFFECTIVE)
        self.assertEqual(h2["state"], HOLD_EFFECTIVE)
        shared = ("shared/shared-r3b", "v-shared-r3b-3")
        self.assertEqual(s.legal_hold_state(*shared), "ON")
        # C's chain breaks: its reference set resolves through the fallback.
        s.items["C"]["chain_broken"] = True
        s.release_hold("H1")
        s.reconcile_claims("H1")
        # H2 still requires the shared version through C's fallback
        # reference set (admission-carried).
        self.assertEqual(s.legal_hold_state(*shared), "ON")
        self.assertEqual(s.holds["H2"]["state"], HOLD_EFFECTIVE)

    def test_released_hold_leaves_no_unowned_protection_in_model(self):
        # Model hygiene for the ownership ledger: after both holds release,
        # every claimed version converges (no legal hold stays ON with no
        # owner).
        s = guarded(ITEMS, [H1, H2])
        s.shared_object["A"] = "shared-r3c"
        s.shared_object["C"] = "shared-r3c"
        s.place_hold_verified(H1, now=0)
        s.place_hold_verified(H2, now=0)
        shared = ("shared/shared-r3c", "v-shared-r3c-3")
        self.assertEqual(s.legal_hold_state(*shared), "ON")
        s.release_hold("H1")
        s.reconcile_claims("H1")
        s.release_hold("H2")
        s.reconcile_claims("H2")
        self.assertEqual(s.legal_hold_state(*shared), "OFF")


if __name__ == "__main__":
    unittest.main()
