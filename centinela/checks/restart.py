"""Services still running a binary/library that was replaced by an upgrade."""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
import shutil
import sys

from ..core import WARN, Finding

NAME = "restart"
DESC = "services running an old binary after an upgrade (needrestart, or /proc fallback)"
NEEDS = ('root',)  # what it needs when not root: see install.py

DEFAULT_IGNORE = "user@*.service getty@*.service"
DEFAULT_PROCS = "nginx sshd"
CGROUP_UNIT = re.compile(r"([^/]+\.service)\s*$")


def applicable(cfg):
    return sys.platform.startswith("linux")


def parse_needrestart(out):
    """-> (services, kernel_current, kernel_expected, kernel_status) or None if not needrestart output."""
    if "NEEDRESTART-VER" not in out:
        return None
    svcs, kcur, kexp, ksta = [], "", "", 0
    for line in out.splitlines():
        key, _, val = line.partition(":")
        val = val.strip()
        if key == "NEEDRESTART-SVC":
            svcs.append(val)
        elif key == "NEEDRESTART-KCUR":
            kcur = val
        elif key == "NEEDRESTART-KEXP":
            kexp = val
        elif key == "NEEDRESTART-KSTA":
            ksta = int(val) if val.isdigit() else 0
    return svcs, kcur, kexp, ksta


def scan_proc(names, proc="/proc"):
    """Fallback: processes whose exe was replaced on disk. -> {unit_or_pid: comm}"""
    found = {}
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return found
    for pid in pids:
        try:
            exe = os.readlink("%s/%s/exe" % (proc, pid))
        except OSError:
            continue
        if not exe.endswith(" (deleted)"):
            continue
        comm = os.path.basename(exe[: -len(" (deleted)")])
        if not any(fnmatch.fnmatch(comm, n) for n in names):
            continue
        unit = ""
        try:
            with open("%s/%s/cgroup" % (proc, pid)) as fh:
                m = CGROUP_UNIT.search(fh.read().strip().splitlines()[-1])
                unit = m.group(1) if m else ""
        except (OSError, IndexError):
            pass
        found[unit or "pid %s" % pid] = comm
    return found


def _finding(unit, comm=""):
    note = ""
    if unit.startswith(("ssh", "sshd")):
        note = " (keep your current SSH session open)"
    elif unit.startswith("docker"):
        note = " (restarts containers unless live-restore is on)"
    if unit.endswith(".service"):
        return Finding(NAME, unit, WARN, "%s is running an outdated binary/library%s" % (unit, note),
                       "sudo systemctl restart " + shlex.quote(unit))
    return Finding(NAME, unit, WARN, "%s (%s) is running a deleted binary" % (unit, comm),
                   "ps -fp %s" % unit.split()[-1])


def run(ctx):
    cfg = ctx.cfg
    ignore = cfg.list("restart", "ignore", DEFAULT_IGNORE)
    findings = []
    parsed = None
    if shutil.which("needrestart"):
        rc, out, _ = ctx.run(["needrestart", "-b"], timeout=120)
        parsed = parse_needrestart(out) if rc == 0 else None
    if parsed:
        svcs, kcur, kexp, ksta = parsed
        for svc in svcs:
            if not any(fnmatch.fnmatch(svc, pat) for pat in ignore):
                findings.append(_finding(svc))
        if ksta in (2, 3) and not os.path.exists(cfg.get("apt", "reboot_flag", "/run/reboot-required")):
            findings.append(Finding(NAME, "kernel", WARN,
                                    "running kernel %s, newer installed: %s" % (kcur, kexp),
                                    "sudo systemctl reboot"))
    else:
        for unit, comm in scan_proc(cfg.list("restart", "proc_names", DEFAULT_PROCS)).items():
            findings.append(_finding(unit, comm))
    return findings
