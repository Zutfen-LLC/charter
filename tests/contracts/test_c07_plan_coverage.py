import unittest

from model import HOLD_EFFECTIVE
from test_round4_corrections import H1, ITEMS, guarded


class PlannedCoverage(unittest.TestCase):
    def test_plan_is_not_a_disposition(self):
        for missing in (0, 1, 4):
            with self.subTest(missing=missing):
                store = guarded(ITEMS[:1])
                store.sweep(200)
                self.assertTrue(store.begin_purge('A', 300, True))
                refs = store.versions_of('A')
                store.plans['A'] = dict.fromkeys(refs, 'planned')
                store.deleted.update(refs[:missing])
                store.items['A']['root_gone'] = missing > 0
                hold = store.place_hold_verified(H1, now=300)
                self.assertEqual(hold['state'], HOLD_EFFECTIVE)
                report = store.reports[hold['id']]
                self.assertEqual(hold['report'], report)
                self.assertEqual(report['partially_disposed'], ['A'] if missing == 1 else [])
                self.assertEqual(report['disposed_before_hold'], ['A'] if missing == 4 else [])
                self.assertEqual(set(report['protected_versions']), set(refs[missing:]))
                if missing == 4:
                    self.assertEqual(report['items'], [])
                else:
                    item, = report['items']
                    self.assertEqual(item['versions'], len(refs) - missing)
                    self.assertEqual(item.get('missing_versions', 0), missing)
                    self.assertEqual(item.get('partially_disposed', False), missing > 0)
