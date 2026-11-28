import os
import unittest

from model import (EstablishmentError, GuardedStore, HOLD_EFFECTIVE,
                   HOLD_RELEASED)

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


class Round4Corrections(unittest.TestCase):
    """C07 round-4 review corrections mirrored in the reference model.

    The Go evidence (charter-c07-correction4/red/) carries the RED
    reproductions at the reviewed head 09c02b4 (unit level and on the
    pinned real storage); the Python tests here pin the corrected
    semantics: the durable disposal plan is the AUTHORITATIVE reference
    set throughout interrupted disposal (a truncated live enumeration
    never overrides known durable references), live plan-backed coverage
    reports partial loss, release-cleanup reports converge to the
    committed claims ledger including zero claims, and released holds
    never publish repair state."""

    # ---- finding 1 (CRITICAL): the plan is the authoritative reference set ----

    def test_disposal_retry_preserves_shared_version_of_deleted_suffix(self):
        # Terminal records A and B share the exact content-addressed object
        # (B's admission references the version A's deleted suffix also
        # referenced). A's disposal is interrupted with the admission and
        # event-zero data protected; after the protection is removed, the
        # ordinary disposal retry must PRESERVE B's shared version: the
        # deleter's version set (the durable plan) is exactly what the
        # shared-reference protection evaluates.
        s = guarded(ITEMS)
        s.shared_object["B"] = s.shared_object.get("A", "A-obj")
        s.sweep(200)
        self.assertTrue(s.begin_purge("A", 300, True))
        refs = s.versions_of("A")
        plan = s.plans.setdefault("A", {})
        for kv in refs:
            plan.setdefault(kv, "planned")
        # Interrupted: the event slot and event data were physically deleted
        # (the rolled-back dispositions stay 'planned' - the durable plan
        # keeps fencing them), the shared object survived.
        s.deleted.add(refs[1])
        s.deleted.add(refs[2])
        shared = refs[3]
        self.assertNotIn(shared, s.deleted)
        s.items["A"]["state"] = "purging"
        # The ordinary disposal retry.
        outcome = s.finish_purge_shared("A", 500)
        self.assertIn(outcome, ("disposed", None))
        self.assertEqual(s.items["A"]["state"], "disposed")
        # B's shared object version survives the retry.
        self.assertNotIn(shared, s.deleted,
                         "REVIEW FINDING 1: the disposal retry deleted the "
                         "shared object version referenced by the surviving "
                         "record")
        self.assertEqual(s.plans["A"].get(shared), "retained_shared")
        # B's evidence is intact.
        for key, version in s.versions_of("B"):
            self.assertNotIn((key, version), s.deleted)

    def test_partially_disposed_sibling_plan_fences_disposal(self):
        # Inverse direction: a partially disposed sibling (B) with a
        # SURVIVING root whose durable plan lists the shared version its
        # truncated live walk no longer enumerates: the sibling's durable
        # plan fences the disposal of another record (A) referencing the
        # same exact version.
        s = guarded(ITEMS)
        s.shared_object["A"] = s.shared_object.get("B", "B-obj")
        s.sweep(200)
        self.assertTrue(s.begin_purge("B", 300, True))
        refs = s.versions_of("B")
        plan = s.plans.setdefault("B", {})
        for kv in refs:
            plan.setdefault(kv, "planned")
        # B interrupted: its slot and data deleted (dispositions rolled
        # back to 'planned'), the shared object survives in the plan.
        s.deleted.add(refs[1])
        s.deleted.add(refs[2])
        shared = refs[3]
        s.items["B"]["state"] = "purging"
        s.items["B"]["chain_broken"] = True  # the truncated walk's refusal
        # Dispose A: the shared version must be retained because the
        # partially disposed sibling's durable plan still references it.
        self.assertTrue(s.begin_purge("A", 400, True))
        outcome = s.finish_purge_shared("A", 400)
        self.assertIn(outcome, ("disposed", None))
        self.assertNotIn(shared, s.deleted,
                         "REVIEW FINDING 1: the disposal of A deleted the "
                         "shared object version the partially disposed "
                         "sibling still lists in its durable plan")
        self.assertEqual(s.plans["A"].get(shared), "retained_shared")

    def test_plan_fences_versions_of_rolled_back_interrupted_deletion(self):
        # A rolled-back interrupted deletion leaves its physically deleted
        # versions UNDISPOSITIONED in the plan: those durable identities
        # keep fencing (the truncated live enumeration must not override
        # known durable references) until a verified disposition records
        # the loss. The sibling's reference set includes the plan's
        # outstanding rows even though the bytes are gone.
        s = guarded(ITEMS)
        s.sweep(200)
        self.assertTrue(s.begin_purge("B", 300, True))
        refs = s.versions_of("B")
        plan = s.plans.setdefault("B", {})
        for kv in refs:
            plan.setdefault(kv, "planned")
        s.deleted.add(refs[1])
        s.deleted.add(refs[2])
        s.items["B"]["chain_broken"] = True
        # The sibling's resolved reference set is the plan's outstanding
        # rows (the physically deleted slot and data included: not yet
        # verifiably gone by disposition).
        resolved = s.resolve_reference_set(s.items["B"])
        self.assertIn(refs[1], resolved)
        self.assertIn(refs[2], resolved)
        self.assertIn(refs[3], resolved)

    # ---- finding 2 (HIGH): live plan-backed coverage reports partial loss ----

    def test_live_plan_coverage_reports_partial_loss(self):
        # A LIVE record with a durable disposal plan (an interrupted
        # disposal whose admission root survived) is covered from the
        # plan: every outstanding planned version is probed, the present
        # ones protected and the verifiably gone ones reported as partial
        # loss - a truncated live enumeration is never silently passed as
        # complete coverage.
        s = guarded(ITEMS)
        s.sweep(200)
        self.assertTrue(s.begin_purge("A", 300, True))
        refs = s.versions_of("A")
        plan = s.plans.setdefault("A", {})
        for kv in refs:
            plan.setdefault(kv, "planned")
        s.deleted.add(refs[1])
        s.deleted.add(refs[2])
        s.items["A"]["state"] = "active"
        # The admission root survives: the record is LIVE (root_gone is
        # NOT set).
        h = s.place_hold_verified(H1, now=300)
        self.assertEqual(h["state"], HOLD_EFFECTIVE)
        entry = [e for e in h["report"]["items"] if e["id"] == "A"][0]
        self.assertIn("A", h["report"]["partially_disposed"],
                      "REVIEW FINDING 2: a live record with a durable "
                      "disposal plan was covered from its truncated live "
                      "enumeration instead of the plan")
        self.assertGreaterEqual(entry.get("missing_versions", 0), 2,
                                "REVIEW FINDING 2: the interrupted "
                                "disposal's partial loss is not reported "
                                "from the durable plan (%r)" % (entry,))
        # The surviving versions are protected.
        for kv in (refs[0], refs[3]):
            self.assertEqual(s.legal_hold_state(*kv), "ON")

    # ---- finding 3 (MEDIUM): cleanup reports converge to the ledger ----

    def test_recover_clears_stale_cleanup_report_with_zero_claims(self):
        # A release whose cleanup was faulted left a durable
        # release_cleanup_pending report; a subsequent retry cleared every
        # claim (the ledger is empty) but the report was never refreshed.
        # Recovery must converge the report to the committed ledger -
        # including the zero-claims state.
        s = guarded(ITEMS)
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], HOLD_EFFECTIVE)
        refs = s.versions_of("A")
        # The faulted release: the claims ledger keeps its entries (the
        # native clear failed), the report records them as pending.
        s.storage_down = True
        s.release_hold_verified("H1")
        report = s.reports["H1"]
        self.assertTrue(report.get("release_cleanup_pending"))
        # The retry succeeded out-of-band: the ledger is empty, but the
        # published report is stale.
        s.storage_down = False
        s.claims["H1"] = set()
        self.assertTrue(report.get("release_cleanup_pending"))
        # Recovery converges the report to the committed ledger.
        s.recover(now=10)
        self.assertEqual(report.get("release_cleanup_pending"), [],
                         "REVIEW FINDING 3: release_cleanup_pending remains "
                         "stale despite zero outstanding claims")

    def test_released_hold_never_publishes_repair_state(self):
        # Repair results describe an EFFECTIVE hold's coverage obligations:
        # a released hold never publishes repair state, and recovery never
        # resolves or rewrites a released hold's historical repair report.
        s = guarded(ITEMS, [H1])
        h = s.place_hold_verified(H1, now=0)
        self.assertEqual(h["state"], HOLD_EFFECTIVE)
        # An outstanding repair condition, then the hold is released.
        s.holds["H1"]["report"]["repair_pending"] = ["N"]
        s.release_hold("H1")
        s.recover(now=10)
        self.assertEqual(s.holds["H1"]["state"], HOLD_RELEASED)
        # The released hold's report is neither completed nor rewritten by
        # recovery: it keeps its historical state and never receives a new
        # repair publication.
        self.assertEqual(s.holds["H1"]["report"].get("repair_pending"), ["N"])
        actions = [a["action"] for a in s.reverify_audit
                   if a["hold_id"] == "H1"
                   and a["action"] in ("hold.protection_repair_complete",
                                       "hold.protection_repair_pending",
                                       "hold.protection_repair_failed")]
        self.assertEqual(actions, [],
                         "REVIEW FINDING 3: recovery published repair-state "
                         "transitions for a released hold")


if __name__ == "__main__":
    unittest.main()
