"""Sustained CPU load: the load average per CPU, not an instant percentage.

Centinela runs now and then, so a CPU percentage at that instant says nothing. The load average already
covers the last 1, 5 or 15 minutes (default 15). About 1.0 per CPU means every CPU is kept busy.
"""
from __future__ import annotations

import os
import sys

from ..core import CRIT, WARN, Finding

NAME = "load"
DESC = "load average per CPU above thresholds"


def applicable(cfg):
    return hasattr(os, "getloadavg")


def limit(cfg, key, default):
    try:
        return float(cfg.get("load", key, default))
    except ValueError:
        return default


def window(cfg):
    return cfg.int("load", "window", 15) if cfg.int("load", "window", 15) in (1, 5, 15) else 15


def evaluate(cfg, load, cpus):
    per_cpu = load / max(cpus, 1)
    top = ("ps -eo pid,pcpu,comm --sort=-pcpu | head -15" if sys.platform.startswith("linux")
           else "ps -Ao pid,pcpu,comm -r | head -15")
    for lvl, name, default in ((CRIT, "crit", 2.0), (WARN, "warn", 1.0)):
        top_limit = limit(cfg, name + "_per_cpu", default)
        if top_limit > 0 and per_cpu >= top_limit:
            return [Finding(NAME, "load", lvl, "load average is %.2f over %d min on %d CPU(s): %.2f per CPU"
                            % (load, window(cfg), cpus, per_cpu), "uptime; " + top)]
    return []


def run(ctx):
    index = {1: 0, 5: 1, 15: 2}[window(ctx.cfg)]
    return evaluate(ctx.cfg, os.getloadavg()[index], os.cpu_count() or 1)
