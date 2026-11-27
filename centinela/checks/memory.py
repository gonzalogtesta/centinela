"""Memory in use, judged by the percentage AND by how much is actually left.

90% used is 200 MB free on a 2 GB machine and 6 GB on a 64 GB one, so a finding needs both: a high
percentage and little memory available. Available memory leaves out the file cache that the system
gives back when asked (Linux MemAvailable); on macOS it is the system's own memory_pressure figure.
"""
from __future__ import annotations

import re
import shutil
import sys

from ..core import CRIT, WARN, Finding, Skip

NAME = "memory"
DESC = "memory used above thresholds (percent and absolute), heavy swap use"
NEEDS = ()  # what it needs when not root: see install.py
FREQUENT = True  # cheap and local: also runs on the frequent timer

MEMINFO = "/proc/meminfo"


def applicable(cfg):
    if sys.platform.startswith("linux"):
        return True
    return sys.platform == "darwin" and shutil.which("memory_pressure") is not None


def parse_meminfo(text):
    """-> {'MemTotal': kB, ...}"""
    return {k: int(v) for k, v in re.findall(r"^(\w+):\s+(\d+)", text, re.M)}


def read_linux(text):
    """-> (total_mb, available_mb, swap_total_mb, swap_used_mb)"""
    info = parse_meminfo(text)
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable")
    if available is None:  # kernels before 3.14
        available = info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0)
    swap = info.get("SwapTotal", 0)
    return total // 1024, available // 1024, swap // 1024, (swap - info.get("SwapFree", 0)) // 1024


def read_macos(ctx):
    """-> (total_mb, available_mb, 0, 0). Uses the percentage macOS itself reports as free."""
    rc, out, _ = ctx.run(["sysctl", "-n", "hw.memsize"])
    if rc != 0 or not out.strip().isdigit():
        raise Skip("cannot read the memory size")
    total = int(out.strip()) // (1024 * 1024)
    rc, out, _ = ctx.run(["memory_pressure"])
    match = re.search(r"free percentage:\s*(\d+)%", out)
    if rc != 0 or not match:
        raise Skip("memory_pressure gave no free percentage")
    return total, total * int(match.group(1)) // 100, 0, 0


def human(mb):
    return "%.1f GB" % (mb / 1024) if mb >= 1024 else "%d MB" % mb


def level(used, free_mb, pct, floor_mb):
    """True when the percentage is reached and (unless the floor is 0) little is left."""
    return pct > 0 and used >= pct and (floor_mb <= 0 or free_mb <= floor_mb)


def evaluate(cfg, total, available, swap_total=0, swap_used=0):
    if total <= 0:
        return []
    used = 100 * (total - available) / total
    top = ("ps -eo pid,%mem,rss,comm --sort=-%mem | head -15" if sys.platform.startswith("linux")
           else "ps -Ao pid,%mem,rss,comm -m | head -15")
    findings = []
    for lvl, name in ((CRIT, "crit"), (WARN, "warn")):
        if level(used, available, cfg.int("memory", name + "_percent", 95 if name == "crit" else 90),
                 cfg.int("memory", name + "_free_mb", 512 if name == "crit" else 1024)):
            findings.append(Finding(NAME, "memory", lvl, "memory is %d%% used: %s available of %s"
                                    % (used, human(available), human(total)), top))
            break
    swap_pct, swap_floor = cfg.int("memory", "swap_warn_percent", 80), cfg.int("memory", "swap_warn_mb", 512)
    if swap_total > 0 and swap_pct > 0 and 100 * swap_used / swap_total >= swap_pct and swap_used >= swap_floor:
        findings.append(Finding(NAME, "swap", WARN, "swap is %d%% used (%s of %s)"
                                % (100 * swap_used / swap_total, human(swap_used), human(swap_total)),
                                "swapon --show; " + top))
    return findings


def run(ctx):
    if sys.platform.startswith("linux"):
        try:
            with open(MEMINFO) as fh:
                reading = read_linux(fh.read())
        except OSError as exc:
            raise Skip("cannot read %s: %s" % (MEMINFO, exc))
    else:
        reading = read_macos(ctx)
    return evaluate(ctx.cfg, *reading)
