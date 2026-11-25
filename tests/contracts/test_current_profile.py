import json
import unittest
from pathlib import Path

from model import event_hash, verify_current_full, verify_turn

FIXTURE = Path(__file__).resolve().parents[2] / 'fixtures' / 'contracts' / 'current-profile.json'


class CurrentProfileSemantics(unittest.TestCase):
    def test_legacy_is_not_complete_current_evidence(self):
        f = json.loads(FIXTURE.with_name('complete-turn.json').read_text())
        objects = {k: v.encode() for k, v in f['objects'].items()}
        self.assertEqual(verify_turn(f['events']), [])
        self.assertEqual(verify_turn(f['events'], objects), [])
        self.assertIn('current evidence profile', '\n'.join(verify_current_full(f['events'], objects)))

    def test_current_profile_cases(self):
        cases = json.loads(FIXTURE.read_text())
        self.assertEqual(len(cases), 23)
        for case in cases:
            with self.subTest(name=case['name']):
                prev = None
                for event in case['events']:
                    self.assertEqual(event['prev_hash'], prev)
                    self.assertEqual(event_hash(event), event['event_hash'])
                    prev = event['event_hash']
                objects = {k: v.encode() for k, v in case['objects'].items()}
                errors = verify_turn(case['events'], objects)
                if case['expect_code']:
                    self.assertIn('[' + case['expect_code'] + ']', '\n'.join(errors))
                else:
                    self.assertEqual(errors, [])
                    self.assertEqual(verify_current_full(case['events'], objects), [])
                    self.assertIn('[OBJECT]', '\n'.join(verify_current_full(case['events'], None)))
