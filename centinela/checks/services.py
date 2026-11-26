"""Services that must be running. This is where fail2ban (or anything else) is declared.

Off until you list services (the setup wizard does it): a machine is never judged on services
it was not told about.

required: not installed or not active is critical (e.g. fail2ban on a public VPS).
watch:    only checked when installed (e.g. nginx, which a Raspberry Pi may not have).
known:    running services you have seen and do not care about (globs allowed).
freeze:   with freeze = true, any running service not in required/watch/known is reported.
"""
from __future__ import annotations

import fnmatch
import shlex
import shutil

from ..core import CRIT, WARN, Finding

NAME = "services"
DESC = "required/watched systemd services are active (fail2ban, nginx, docker, ssh...)"
FREQUENT = True  # cheap and local: also runs on the frequent timer


def configured(cfg):
    return bool(cfg.list("services", "required") or cfg.list("services", "watch") or cfg.bool("services", "freeze", False))


def applicable(cfg):
    return shutil.which("systemctl") is not None and configured(cfg)


def unit_name(name):
    return name if "." in name else name + ".service"


def parse_show(out):
    return dict(line.partition("=")[::2] for line in out.splitlines())


def parse_running(out):
    return [cols[0] for cols in (l.split() for l in out.splitlines()) if cols and "." in cols[0]]


def run(ctx):
    required = ctx.cfg.list("services", "required")
    watch = ctx.cfg.list("services", "watch")
    findings = []
    for names, must_exist in ((required, True), (watch, False)):
        for name in names:
            unit = unit_name(name)
            _, out, _ = ctx.run(["systemctl", "show", "-p", "LoadState", "-p", "ActiveState", unit])
            info = parse_show(out)
            if info.get("LoadState") != "loaded":
                if must_exist:
                    findings.append(Finding(NAME, unit + "-missing", CRIT, "required service %s is not installed" % unit,
                                            "systemctl list-unit-files " + shlex.quote(unit)))
                continue
            state = info.get("ActiveState", "unknown")
            if state != "active":
                u = shlex.quote(unit)
                cmd = ("journalctl -u %s -n 30 --no-pager" % u if state == "failed"
                       else "sudo systemctl start %s" % u)
                findings.append(Finding(NAME, unit, CRIT, "service %s is %s" % (unit, state), cmd))

    if ctx.cfg.bool("services", "freeze", False):
        allowed = [unit_name(n) for n in required + watch + ctx.cfg.list("services", "known")]
        _, out, _ = ctx.run(["systemctl", "list-units", "--type=service", "--state=running",
                             "--no-legend", "--plain", "--no-pager"])
        for unit in parse_running(out):
            if not any(fnmatch.fnmatchcase(unit, p) for p in allowed):
                findings.append(Finding(NAME, "unexpected-" + unit, WARN,
                                        "unexpected service %s is running; not in watch/known" % unit,
                                        "systemctl status %s --no-pager" % shlex.quote(unit)))
    return findings
