"""systemd units in the failed state."""
from __future__ import annotations

import fnmatch
import shlex
import shutil

from ..core import WARN, Finding

NAME = "units"
DESC = "failed systemd units"
NEEDS = ()  # what it needs when not root: see install.py
FREQUENT = True  # cheap and local: also runs on the frequent timer


def applicable(cfg):
    return shutil.which("systemctl") is not None


def parse_failed(out):
    units = []
    for line in out.splitlines():
        cols = line.replace("●", " ").split()
        if cols and "." in cols[0]:
            units.append(cols[0])
    return units


def run(ctx):
    ignore = ctx.cfg.list("units", "ignore")
    _, out, _ = ctx.run(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"])
    return [
        Finding(NAME, unit, WARN, "systemd unit %s has failed" % unit,
                "journalctl -u %s -n 30 --no-pager" % shlex.quote(unit))
        for unit in parse_failed(out)
        if not any(fnmatch.fnmatch(unit, p) for p in ignore)
    ]
