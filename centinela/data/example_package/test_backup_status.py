"""Unit tests of the backup_status example check, without a machine.

Run them from anywhere, with Centinela on the import path (the single-file install works as a path):
    PYTHONPATH=/usr/local/bin/centinela python3 -m unittest test_backup_status
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # the check and its helpers sit next to this file

import backup_status  # noqa: E402
from backup_status_lib import status  # noqa: E402
from centinela.core import CRIT, Config  # noqa: E402
from centinela.testing import FakeCtx  # noqa: E402

NOW = 1_800_000_000


class BackupStatusTests(unittest.TestCase):
    def check(self, report, extra=""):
        """Run the check against a status file holding `report` (a dict, a string, or None for no file)."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "status.json")
            if report is not None:
                with open(path, "w") as fh:
                    fh.write(report if isinstance(report, str) else json.dumps(report))
            ctx = FakeCtx('[backup_status]\nfile = "%s"\n%s' % (path, extra))
            return backup_status.run(ctx, now=NOW)

    def test_silent_until_configured(self):
        self.assertFalse(backup_status.applicable(Config()))

    def test_a_recent_good_backup_says_nothing(self):
        self.assertEqual(self.check({"ok": True, "finished": NOW - 3600}), [])

    def test_a_failed_backup_is_critical_and_says_why(self):
        fs = self.check({"ok": False, "finished": NOW, "message": "disk full"})
        self.assertEqual((fs[0].id, fs[0].level), ("failed", CRIT))
        self.assertIn("disk full", fs[0].text)

    def test_an_old_backup_is_critical_and_the_limit_is_configurable(self):
        report = {"ok": True, "finished": NOW - 30 * 3600}
        self.assertEqual(self.check(report)[0].id, "stale")
        self.assertEqual(self.check(report, "max_age_hours = 48\n"), [])

    def test_a_missing_or_broken_file_is_reported_not_ignored(self):
        self.assertEqual(self.check(None)[0].id, "missing")
        self.assertEqual(self.check("{nope")[0].id, "unreadable")
        self.assertEqual(self.check({"ok": "yes"})[0].id, "unreadable")

    def test_the_helper_alone(self):
        self.assertEqual(status.parse('{"ok": true, "finished": 5}').finished, 5.0)
        with self.assertRaises(ValueError):
            status.parse('{"ok": true, "finished": "yesterday"}')
        self.assertEqual(status.age_hours(status.Report(True, NOW + 10, ""), NOW), 0.0)  # a clock a bit off is not negative


if __name__ == "__main__":
    unittest.main()
