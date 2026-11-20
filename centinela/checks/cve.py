"""High-urgency Debian CVEs with a fix available, via debsecan (Debian security tracker data).

Covers Debian-packaged software only; nginx.org and docker-ce packages are
covered by the nginx and docker checks, and container contents by Trivy in CI.
"""
from __future__ import annotations

import re
import shlex
import shutil

from ..core import CRIT, WARN, Finding, Skip

NAME = "cve"
DESC = "debsecan: high-urgency CVEs in installed Debian packages that have a fix"

ORDER = ["unimportant", "low", "medium", "high"]
LINE = re.compile(r"^(CVE-\d{4}-\d+|TEMP-\S+)\s+(\S+)\s+\((.*)\)\s*$")
PKG = re.compile(r"^[a-z0-9][a-z0-9+.\-]*$")


def applicable(cfg):
    return shutil.which("debsecan") is not None


def parse_summary(out):
    """-> list of (cve, package, urgency, remote)"""
    rows = []
    for line in out.splitlines():
        m = LINE.match(line.strip())
        if not m:
            continue
        notes = m.group(3)
        u = re.search(r"(\w+) urgency", notes)
        rows.append((m.group(1), m.group(2), u.group(1) if u else "", "remotely exploitable" in notes))
    return rows


def codename():
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if line.startswith("VERSION_CODENAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def run(ctx):
    cfg = ctx.cfg
    suite = cfg.get("cve", "suite") or codename()
    if not suite:
        raise Skip("cannot determine Debian suite; set [cve] suite")
    minimum = cfg.get("cve", "min_urgency", "high")
    argv = ["debsecan", "--suite", suite, "--format", "summary"]
    if cfg.bool("cve", "only_fixed", True):
        argv.append("--only-fixed")
    rc, out, err = ctx.run(argv, timeout=180)
    if rc != 0:
        raise Skip("debsecan failed: %s" % err.strip()[:100])

    by_pkg = {}
    for cve, pkg, urgency, remote in parse_summary(out):
        if urgency in ORDER and ORDER.index(urgency) >= ORDER.index(minimum) and PKG.match(pkg):
            by_pkg.setdefault(pkg, []).append((cve, remote))
    findings = []
    for pkg, items in sorted(by_pkg.items()):
        remote = any(r for _, r in items)
        cves = sorted({c for c, _ in items})
        findings.append(Finding(
            NAME, pkg, CRIT if remote else WARN,
            "%s: %s%s" % (pkg, ", ".join(cves[:3]) + (" +%d" % (len(cves) - 3) if len(cves) > 3 else ""),
                          " (remotely exploitable)" if remote else " (high urgency)"),
            "sudo apt-get update && sudo apt-get install --only-upgrade " + shlex.quote(pkg)))
    return findings
