import json
import unittest
from pathlib import Path

import model


class RetainedProfile(unittest.TestCase):
    def test_shared_retained_profile_cases(self):
        fixture = Path(__file__).resolve().parents[2] / 'fixtures' / 'contracts' / 'retained-profile.json'
        cases = json.loads(fixture.read_text())
        self.assertEqual(len(cases), 11)
        for case in cases:
            with self.subTest(name=case['name']):
                events = case['events']
                prev = None
                for event in events:
                    self.assertEqual(event['prev_hash'], prev)
                    self.assertEqual(model.event_hash(event), event['event_hash'])
                    prev = event['event_hash']
                objs = {k: v.encode() for k, v in case['objects'].items()}
                if not case['expect_code']:
                    self.assertEqual(model.verify_turn(events, objs), [])
                    self.assertEqual(model.verify_retention_full(events, objs), [])
                    self.assertTrue(model.verify_retention_full(events, None))
                    self.assertTrue(model.verify_current_full(events, objs))
                else:
                    errs = model.verify_retention_full(events, objs)
                    self.assertIn(f"[{case['expect_code']}]", '\n'.join(errs))
