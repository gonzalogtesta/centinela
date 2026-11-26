"""Disk space (and, on Linux, inodes) per real filesystem.

A finding needs the percentage AND little space left: 90% of a 20 GB disk is 2 GB free, 90% of a 4 TB disk
is 400 GB. Inodes are judged by percentage alone.
"""
from __future__ import annotations

import fnmatch
import shlex
import sys

from ..core import CRIT, WARN, Finding

NAME = "disk"
DESC = "filesystem space/inode usage above thresholds"
FREQUENT = True  # cheap and local: also runs on the frequent timer

EXCLUDE = ["-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay", "-x", "efivarfs", "-x", "iso9660"]
# macOS mounts read-only system and helper volumes, and disk images, that are full or irrelevant by design.
MACOS_IGNORE = ["/System/Volumes/Preboot", "/System/Volumes/VM", "/System/Volumes/Update*", "/System/Volumes/xarts",
                "/System/Volumes/iSCPreboot", "/System/Volumes/Hardware", "/Library/Developer/CoreSimulator/*",
                "/Volumes/com.apple.TimeMachine.*"]


def applicable(cfg):
    return sys.platform.startswith("linux") or sys.platform == "darwin"


def parse_df(out):
    """-> list of (device, percent, mount, free, total); skips '-' (no inodes) rows and bind mounts of one device.
    `free` and `total` are in the unit df printed: 1K blocks for space, inodes for -i."""
    rows, seen = [], set()
    for line in out.splitlines()[1:]:
        cols = line.split(None, 5)
        if len(cols) < 6 or not cols[4].endswith("%"):
            continue
        dev = cols[0]
        if dev in seen:  # bind mounts of the same device
            continue
        seen.add(dev)
        try:
            total, free = int(cols[1]), int(cols[3])
        except ValueError:
            total = free = 0
        rows.append((dev, int(cols[4][:-1]), cols[5], free, total))
    return rows


def human(kb):
    gb = kb / (1024 * 1024)
    return "%.1f TB" % (gb / 1024) if gb >= 1024 else "%.1f GB" % gb if gb >= 1 else "%d MB" % (kb // 1024)


def space_level(cfg, pct, free_kb):
    """CRIT, WARN or None: the percentage is reached and (unless the floor is 0) little space is left."""
    free_gb = free_kb / (1024 * 1024)
    for level, name, default_pct, default_gb in ((CRIT, "crit", 90, 10), (WARN, "warn", 80, 20)):
        limit, floor = cfg.int("disk", name + "_percent", default_pct), cfg.int("disk", name + "_free_gb", default_gb)
        if limit > 0 and pct >= limit and (floor <= 0 or free_gb <= floor):
            return level
    return None


def run(ctx):
    mac = sys.platform == "darwin"
    configured = ctx.cfg.has("disk", "ignore_mounts")
    ignore = ctx.cfg.list("disk", "ignore_mounts") if configured else (MACOS_IGNORE if mac else ["/snap/*"])
    findings = []
    # macOS has no GNU -x filters; -l keeps to local filesystems. Its inodes are dynamic, so only Linux checks them.
    passes = [("disk", ["df", "-Pk", "-l"])] if mac else [("disk", ["df", "-P"] + EXCLUDE), ("inodes", ["df", "-Pi"] + EXCLUDE)]
    warn_inodes, crit_inodes = ctx.cfg.int("disk", "warn_percent", 80), ctx.cfg.int("disk", "crit_percent", 90)
    for kind, argv in passes:
        rc, out, _ = ctx.run(argv)
        for _, pct, mount, free, total in parse_df(out):
            if any(fnmatch.fnmatch(mount, p) for p in ignore):
                continue
            if kind == "disk":
                level = space_level(ctx.cfg, pct, free)
                text = "disk %s is %d%% full (%s free of %s)" % (mount, pct, human(free), human(total))
            else:
                level = CRIT if pct >= crit_inodes else WARN if pct >= warn_inodes else None
                text = "inodes on %s is %d%% full" % (mount, pct)
            if level:
                findings.append(Finding(NAME, "%s-%s" % (kind, mount), level, text,
                                        "sudo du -xh -d 1 %s | sort -rh | head -15" % shlex.quote(mount) if mac
                                        else "sudo du -xh --max-depth=1 %s | sort -rh | head -15" % shlex.quote(mount)))
    return findings
