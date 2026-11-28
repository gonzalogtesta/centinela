"""Example check package: critical when your backup job reports a failure, or has not reported lately.

A check can be several files: this one is a module (this file) and a helper package next to it
(backup_status_lib/), and it ships with its own unit test (test_backup_status.py, kept OUTSIDE the
drop-in directory because every .py file in there is loaded as a check).

Install:  centinela --print example-package | sudo sh              # into /etc/centinela/checks.d
          centinela --print example-package-test > test_backup_status.py
Config:   [backup_status]
          file = "/var/backups/status.json"    # written by your backup job: {"ok": true, "finished": 1767225600}
          max_age_hours = 26                   # optional, default 26

Import your helpers at the top of the file: the directory is on the import path only while this file loads.
"""
import shlex
import time

from backup_status_lib import status

from centinela.core import CRIT, Finding

NAME = "backup_status"
DESC = "the backup job's status file says the last run worked and is recent"
NEEDS = ('files',)  # reads one file; see "What Restricted loses" in the README


def applicable(cfg):
    return bool(cfg.get("backup_status", "file", ""))  # no file configured, no check


def run(ctx, now=None):
    path = ctx.cfg.get("backup_status", "file", "")
    limit = ctx.cfg.int("backup_status", "max_age_hours", 26)
    look = "ls -l %s" % shlex.quote(path)
    try:
        with open(path) as fh:
            report = status.parse(fh.read())
    except OSError as exc:
        return [Finding(NAME, "missing", CRIT, "cannot read %s (%s)" % (path, exc.strerror), look)]
    except ValueError as exc:
        return [Finding(NAME, "unreadable", CRIT, "%s: %s" % (path, exc), "cat %s" % shlex.quote(path))]
    if not report.ok:
        return [Finding(NAME, "failed", CRIT, "the last backup failed%s" % (": " + report.message if report.message else ""),
                        look)]
    hours = status.age_hours(report, now or time.time())
    if hours > limit:
        return [Finding(NAME, "stale", CRIT, "the last backup finished %.0f hours ago (limit %d)" % (hours, limit), look)]
    return []
