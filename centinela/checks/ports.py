"""Listening TCP/UDP ports against the list you approved (see `centinela setup`).

[ports]
expected = ["tcp/22", "tcp/6379@local"]   # monitored: must listen; "@local" = loopback only
known    = ["udp/68"]                     # seen and ignored: never reported
freeze   = true                           # anything else that starts listening is reported

Off until expected or known is set. A snapshot at each run, so a listener that opens
and closes between two runs is not seen.
"""
from __future__ import annotations

import re
import shutil
import sys
from collections import namedtuple

from ..core import CRIT, WARN, Finding, Skip

NAME = "ports"
DESC = "listening ports vs the approved list; frozen = alert on new listeners"
FREQUENT = True  # cheap and local: also runs on the frequent timer

ENTRY = re.compile(r"^(tcp|udp)/(\d{1,5})(@local)?$")
Listener = namedtuple("Listener", "proto port scope process")


def applicable(cfg):
    return (sys.platform.startswith("linux") and shutil.which("ss") is not None
            and bool(cfg.list("ports", "expected") or cfg.list("ports", "known")))


def parse_ss(out):
    """`ss -H -lntu[p]` -> sorted Listeners; IPv4/IPv6 twins merge. scope: 'local' (loopback) or 'any'."""
    seen = {}
    for line in out.splitlines():
        cols = line.split()
        if len(cols) < 5 or cols[0] not in ("tcp", "udp"):
            continue
        addr, _, port = cols[4].rpartition(":")
        if not port.isdigit():
            continue
        addr = addr.strip("[]").split("%")[0]
        scope = "local" if addr.startswith("127.") or addr == "::1" else "any"
        proc = re.search(r'users:\(\("([^"]+)"', line)
        key = (cols[0], int(port), scope)
        if not seen.get(key):
            seen[key] = proc.group(1) if proc else ""
    return [Listener(p, n, s, proc) for (p, n, s), proc in sorted(seen.items())]


def entry(listener):
    return "%s/%d%s" % (listener.proto, listener.port, "@local" if listener.scope == "local" else "")


def allows(entries, listener):
    """'tcp/22' allows any scope; 'tcp/6379@local' only loopback."""
    base = "%s/%d" % (listener.proto, listener.port)
    return base in entries or (listener.scope == "local" and base + "@local" in entries)


def listing(ctx):
    rc, out, _ = ctx.run(["ss", "-H", "-lntup"])  # -p (process names) needs root
    if rc != 0:
        rc, out, err = ctx.run(["ss", "-H", "-lntu"])
        if rc != 0:
            raise Skip("ss failed: %s" % err.strip()[:80])
    return parse_ss(out)


def run(ctx):
    cfg = ctx.cfg
    expected = [e for e in cfg.list("ports", "expected") if ENTRY.match(e)]
    known = [e for e in cfg.list("ports", "known") if ENTRY.match(e)]
    freeze = cfg.bool("ports", "freeze", False)
    listeners = listing(ctx)
    findings = []

    for e in expected:
        proto, port = ENTRY.match(e).group(1), int(ENTRY.match(e).group(2))
        if not any(l.proto == proto and l.port == port for l in listeners):
            findings.append(Finding(NAME, "missing-" + e, CRIT, "expected listener %s is not listening" % e,
                                    "sudo ss -lntup 'sport = :%d'" % port))
    for l in listeners:
        who = " (%s)" % l.process if l.process else ""
        look = "sudo ss -lntup 'sport = :%d'" % l.port
        if allows(expected, l) or allows(known, l):
            continue
        if any(e.startswith("%s/%d" % (l.proto, l.port)) for e in expected):
            findings.append(Finding(NAME, "exposed-%s/%d" % (l.proto, l.port), CRIT,
                                    "%s/%d%s is now listening on all interfaces; approved for loopback only"
                                    % (l.proto, l.port, who), look))
        elif freeze:
            where = "all interfaces" if l.scope == "any" else "loopback"
            findings.append(Finding(NAME, "unexpected-%s-%s" % (entry(l), l.scope), CRIT if l.scope == "any" else WARN,
                                    "unexpected listener %s/%d%s on %s; not in the approved list"
                                    % (l.proto, l.port, who, where), look))
    return findings
