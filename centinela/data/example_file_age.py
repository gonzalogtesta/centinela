"""Example check: critical when a file has not been updated recently (a backup, a log, a heartbeat file).

Install:  centinela --print example-file-age | sudo tee /etc/centinela/checks.d/file_age.py
Config:   [file_age]
          files = ["/var/backups/db.sql.gz:26h", "/var/log/myjob.log:15m"]   # path:max age (m, h or d)
"""
import os
import shlex
import time

from centinela.core import CRIT, Finding, short_hash

NAME = "file_age"
DESC = "listed files were modified within their maximum age"
UNITS = {"m": 60, "h": 3600, "d": 86400}


def applicable(cfg):
    return bool(cfg.list("file_age", "files"))


def parse(entry):
    """'/path:26h' -> ('/path', 93600). Raises ValueError on a malformed entry."""
    path, _, age = entry.rpartition(":")
    if not path or len(age) < 2 or age[-1] not in UNITS:
        raise ValueError(entry)
    return path, int(age[:-1]) * UNITS[age[-1]]


def run(ctx, now=None):
    now = now or time.time()
    findings = []
    for entry in ctx.cfg.list("file_age", "files"):
        try:
            path, limit = parse(entry)
        except ValueError:
            findings.append(Finding(NAME, "bad-" + short_hash(entry), CRIT,
                                    "[file_age] entry %r is not path:age (age like 26h, 15m or 2d)" % entry))
            continue
        try:
            age = now - os.stat(path).st_mtime
        except OSError:
            findings.append(Finding(NAME, "missing-" + short_hash(path), CRIT, "%s does not exist" % path,
                                    "ls -l %s" % shlex.quote(path)))
            continue
        if age > limit:
            findings.append(Finding(NAME, "old-" + short_hash(path), CRIT,
                                    "%s was last updated %.0f hours ago (limit %.0f)" % (path, age / 3600, limit / 3600),
                                    "ls -l %s" % shlex.quote(path)))
    return findings
