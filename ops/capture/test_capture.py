import datetime as dt
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import capture


class CapturePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.now = dt.datetime(2026, 11, 12, 20, tzinfo=dt.timezone.utc).timestamp()

    def segment(self, number, age, size=20):
        stamp = dt.datetime.fromtimestamp(self.now-age, dt.timezone.utc).strftime('%Y%m%d%H%M%S')
        path = self.root / f'packets-20261112T200000Z-abcd1234_{number:05d}_{stamp}.pcap'
        path.write_bytes(b'x'*size)
        os.utime(path, (self.now-age, self.now-age))
        return path

    def prune(self, age=3600, budget=1000, active=None, free=1000, floor=0):
        return capture.prune(self.root, age, budget, floor, now=self.now,
                             active=active, disk_free=lambda: free)

    def test_age_and_size_delete_oldest_completed_only(self):
        expired = self.segment(1, 4000)
        oldest = self.segment(2, 100)
        recent = self.segment(3, 50)
        active = self.segment(4, 0)
        result = self.prune(budget=40, active=active)
        self.assertEqual(result['deleted'], 2)
        self.assertFalse(expired.exists())
        self.assertFalse(oldest.exists())
        self.assertTrue(recent.exists() and active.exists())

    def test_low_disk_never_removes_active_or_unrelated_files(self):
        completed = self.segment(1, 10)
        active = self.segment(2, 0)
        unrelated = self.root / 'account-database'
        unrelated.write_bytes(b'leave alone')
        self.prune(active=active, free=0, floor=100)
        self.assertFalse(completed.exists())
        self.assertTrue(active.exists() and unrelated.exists())

    def test_rotation_during_pruning_does_not_delete_new_active_file(self):
        old = self.segment(1, 100)
        previous_active = self.segment(2, 50)
        snapshot = capture.files(self.root)
        new_active = self.segment(3, 0)
        capture.prune(self.root, 3600, 0, 0, now=self.now, active=previous_active,
                      disk_free=lambda: 1000, entries=snapshot)
        self.assertFalse(old.exists())
        self.assertTrue(previous_active.exists() and new_active.exists())

    def test_symlinks_are_never_exported_or_pruned(self):
        target = self.root / 'private'
        target.write_bytes(b'leave alone')
        link = self.segment(1, 4000)
        link.unlink()
        link.symlink_to(target)
        self.assertEqual(capture.files(self.root), [])
        self.prune()
        self.assertTrue(target.exists() and link.is_symlink())

    def test_incident_selection_includes_overlapping_boundary_segment(self):
        old = self.segment(1, 600)
        overlap = self.segment(2, 300)
        os.utime(overlap, (self.now-200, self.now-200))
        recent = self.segment(3, 100)
        selected = capture.select_files(self.root, self.now-250, self.now-50)
        self.assertNotIn(old, selected)
        self.assertEqual(selected, [overlap, recent])

    def test_filter_tracks_custom_ports_and_disabled_second_title(self):
        with patch.dict(os.environ, {'ANGELWARE_PORT': '1234', 'ANGELWARE_STUN_ALT_PORT': '1235',
                                     'ANGELWARE_BRO': 'off', 'ANGELWARE_RELAY_PORTS': '30000-30010'}, clear=True):
            expression = capture.capture_filter()
            self.assertIn('tcp port 1234', expression)
            self.assertIn('port 1235', expression)
            self.assertIn('portrange 30000-30010', expression)
            self.assertNotIn('2273', expression)
            os.environ['ANGELWARE_RELAY_PORTS'] = '30010-30000'
            with self.assertRaises(ValueError):
                capture.capture_filter()


if __name__ == '__main__':
    unittest.main()
