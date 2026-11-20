"""Upgradable packages (security ones are critical), stale apt index, reboot-required."""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
import shutil
import time

from ..core import CRIT, WARN, Finding, short_hash

NAME = "apt"
DESC = "upgradable packages, security updates, reboot-required"

DEFAULT_WATCH = "nginx nginx-* docker-ce docker-ce-cli containerd.io docker-compose-plugin openssh-* linux-image-* raspberrypi-kernel"
LINE = re.compile(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: (.+)\]")
UPDATE = "sudo apt-get update && sudo apt-get upgrade"


def applicable(cfg):
    return shutil.which("apt") is not None


def parse_upgradable(out):
    """-> list of (package, suites, new_version)"""
    pkgs = []
    for line in out.splitlines():
        m = LINE.match(line)
        if m:
            pkgs.append((m.group(1), m.group(2).split(","), m.group(3)))
    return pkgs


def _install_cmd(names):
    if len(names) > 8:
        return UPDATE
    return "sudo apt-get update && sudo apt-get install --only-upgrade " + " ".join(shlex.quote(n) for n in names)


def run(ctx):
    cfg = ctx.cfg
    findings = []
    _, out, _ = ctx.run(["apt", "list", "--upgradable"])
    pkgs = parse_upgradable(out)

    security = sorted(p for p, suites, _ in pkgs if any("security" in s for s in suites))
    if security:
        findings.append(Finding(
            NAME, "security-" + short_hash(*security), CRIT,
            "%d security update(s) pending: %s" % (len(security), ", ".join(security[:8])),
            _install_cmd(security)))

    patterns = cfg.list("apt", "watch", DEFAULT_WATCH)
    names = sorted(p for p, _, _ in pkgs if p not in security)
    watched = [n for n in names if any(fnmatch.fnmatch(n, pat) for pat in patterns)]
    if watched:
        findings.append(Finding(
            NAME, "watched-" + short_hash(*watched), WARN,
            "upgrade available for key package(s): %s" % ", ".join(watched[:8]),
            _install_cmd(watched)))
    others = [n for n in names if n not in watched]
    if others:
        findings.append(Finding(
            NAME, "other", WARN,
            "%d other upgradable package(s)" % len(others), UPDATE))

    stamp = cfg.get("apt", "stamp_file", "/var/lib/apt/periodic/update-success-stamp")
    max_age = cfg.int("apt", "max_index_age_days", 7)
    try:
        age_days = (time.time() - os.stat(stamp).st_mtime) / 86400
    except OSError:
        age_days = None  # no stamp (e.g. minimal images): cannot judge
    if age_days is not None and age_days > max_age:
        findings.append(Finding(
            NAME, "stale-index", WARN,
            "apt package index is %d days old, so this digest may miss updates" % age_days,
            "sudo apt-get update"))

    flag = cfg.get("apt", "reboot_flag", "/run/reboot-required")
    if os.path.exists(flag):
        try:
            with open(flag + ".pkgs") as fh:
                why = ", ".join(sorted({l.strip() for l in fh if l.strip()})[:4])
        except OSError:
            why = "unknown packages"
        findings.append(Finding(NAME, "reboot", WARN, "reboot required (%s)" % why, "sudo systemctl reboot"))
    return findings
