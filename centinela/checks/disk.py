"""Disk space and inode usage per real filesystem."""
from __future__ import annotations

import fnmatch
import shlex
import sys

from ..core import CRIT, WARN, Finding

NAME = "disk"
DESC = "filesystem space/inode usage above thresholds"

EXCLUDE = ["-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs", "-x", "iso9660"]


def applicable(cfg):
    return sys.platform.startswith("linux")


def parse_df(out):
    """-> list of (device, percent, mount); skips '-' (no inodes) rows."""
    rows, seen = [], set()
    for line in out.splitlines()[1:]:
        cols = line.split(None, 5)
        if len(cols) < 6 or not cols[4].endswith("%"):
            continue
        dev = cols[0]
        if dev in seen:  # bind mounts of the same device
            continue
        seen.add(dev)
        rows.append((dev, int(cols[4][:-1]), cols[5]))
    return rows


def run(ctx):
    warn = ctx.cfg.int("disk", "warn_percent", 80)
    crit = ctx.cfg.int("disk", "crit_percent", 90)
    ignore = ctx.cfg.list("disk", "ignore_mounts", "/snap/*")
    findings = []
    for kind, flag in (("disk", "-P"), ("inodes", "-Pi")):
        rc, out, _ = ctx.run(["df", flag] + EXCLUDE)
        for _, pct, mount in parse_df(out):
            if pct < warn or any(fnmatch.fnmatch(mount, p) for p in ignore):
                continue
            findings.append(Finding(
                NAME, "%s-%s" % (kind, mount), CRIT if pct >= crit else WARN,
                "%s %s is %d%% full" % ("inodes on" if kind == "inodes" else "disk", mount, pct),
                "sudo du -xh --max-depth=1 %s | sort -rh | head -15" % shlex.quote(mount)))
    return findings
