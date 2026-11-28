"""The kernel killed a process because the machine ran out of memory.

The memory check sees pressure at the moment it runs; an OOM kill is the proof that it already
happened between two runs. Read from the kernel log: `journalctl -k`, or `dmesg` when the journal
is not readable. Both need root or the right group (systemd-journal, adm) or CAP_SYSLOG; without
them the check says it could not run instead of looking healthy.
"""
from __future__ import annotations

import re
import shlex
import shutil
import sys
from collections import OrderedDict

from ..core import CRIT, Finding, Skip

NAME = "oom"
DESC = "processes killed by the kernel for lack of memory (kernel log)"
NEEDS = ('journal',)  # what it needs when not root: see install.py
FREQUENT = True  # cheap and local: also runs on the frequent timer

KILLED = re.compile(r"(?P<cg>Memory cgroup )?[Oo]ut of memory: Killed process (?P<pid>\d+) \((?P<comm>[^)]+)\)")
JOURNAL_BLIND = ("not seeing messages", "insufficient permissions", "No journal files were found")


def applicable(cfg):
    return sys.platform.startswith("linux") and bool(shutil.which("journalctl") or shutil.which("dmesg"))


def window_days(cfg):
    return max(1, cfg.int("oom", "window_days", 7))


def parse(text):
    """-> {comm: {"count": n, "last": 'timestamp', "cgroup": bool}} from kernel log lines, oldest first."""
    found = OrderedDict()
    for line in text.splitlines():
        m = KILLED.search(line)
        if not m:
            continue
        iso = re.match(r"^(\d{4}-\d\d-\d\d)T(\d\d:\d\d)", line)
        stamp = "%s %s" % iso.groups() if iso else (re.match(r"^\[([^\]]+)\]", line) or [None, ""])[1]
        item = found.setdefault(m.group("comm"), {"count": 0, "last": "", "cgroup": False})
        item["count"] += 1
        item["last"] = stamp or item["last"]
        item["cgroup"] = item["cgroup"] or bool(m.group("cg"))
    return found


def read_log(ctx, days):
    """The kernel log text, or raise Skip when it cannot be read."""
    rc, out, err = ctx.run(["journalctl", "-k", "-o", "short-iso", "--no-pager", "--since", "-%dd" % days], timeout=60)
    if rc == 0 and not any(hint in err for hint in JOURNAL_BLIND):
        return out
    rc2, out2, err2 = ctx.run(["dmesg", "-T"], timeout=30)
    if rc2 == 0 and out2.strip():
        return out2
    if rc == 127 and rc2 == 127:
        raise Skip("neither journalctl nor dmesg is available")
    raise Skip("cannot read the kernel log (needs root, the systemd-journal or adm group, or CAP_SYSLOG)")


def run(ctx):
    days = window_days(ctx.cfg)
    ignore = set(ctx.cfg.list("oom", "ignore"))
    findings = []
    for comm, item in parse(read_log(ctx, days)).items():
        if comm in ignore:
            continue
        where = " (inside a container or cgroup memory limit)" if item["cgroup"] else ""
        findings.append(Finding(
            NAME, "kill-" + re.sub(r"[^A-Za-z0-9_.-]", "_", comm), CRIT,
            "the kernel killed %r for lack of memory %d time(s) in the last %d day(s), last at %s%s"
            % (comm, item["count"], days, item["last"] or "an unknown time", where),
            "journalctl -k --since %s --no-pager | grep -i -B3 -A12 'out of memory'" % shlex.quote("-%dd" % days)))
    return findings
