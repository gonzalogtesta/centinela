"""The firewall rules in force now, compared with the set you approved.

`ufw status` and ufw's files say what ufw *meant* to load. The rules the kernel enforces live in memory,
and anything with root can add or remove one without touching those files. This reads the live ruleset
(`nft list ruleset`, else `iptables-save`), strips what changes on its own (counters, Docker, fail2ban,
Kubernetes, ...) and compares it with a copy you approved with `centinela firewall approve`.

Reading the live rules needs root, or CAP_NET_ADMIN. Nothing is ever changed.
"""
from __future__ import annotations

import argparse
import difflib
import fnmatch
import hashlib
import os
import re
import sys

from .core import Blocked, Config, Ctx, Skip
from .state import locked, write_private

APPROVED = "firewall.rules"
# Chains, tables and sets whose content changes by itself: containers starting, bans, pods.
IGNORE_CHAINS = ("DOCKER*", "docker*", "f2b-*", "fail2ban*", "KUBE-*", "CNI-*", "cali-*", "cilium*", "CILIUM*",
                 "flannel*", "LIBVIRT*", "libvirt*")
# Rules in other chains that exist because of a container network or a veth pair.
IGNORE_LINES = (r"docker0", r"br-[0-9a-f]{12}", r"veth[0-9a-f]+")
NOISE = re.compile(r"counter packets \d+ bytes \d+|\s+expires \S+|\s+timeout \S+")


class RuleError(Exception):
    """The live rules could not be read; the message says why."""


def matches(name, patterns):
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def normalize_nft(text, chains, lines):
    """`nft list ruleset` without comments, counters, timeouts and the blocks that change by themselves."""
    out, stack, skipping = [], [], 0
    for raw in text.splitlines():
        line = NOISE.sub(lambda m: "counter" if m.group(0).startswith("counter") else "", raw).strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("{"):
            words = line[:-1].split()
            name = words[-1] if len(words) > 1 else ""  # "table inet filter {" -> filter, "chain input {" -> input
            hide = matches(name, chains) if words[0] in ("table", "chain", "set", "map") else False
            stack.append(hide)
            skipping += hide
            if not skipping:
                out.append("  " * (len(stack) - 1) + " ".join(line.split()))
            continue
        if line == "}":
            if stack:
                skipping -= stack.pop()
            if not skipping:
                out.append("  " * len(stack) + "}")
            continue
        if not skipping and not any(re.search(p, line) for p in lines):
            out.append("  " * len(stack) + " ".join(line.split()))
    return "\n".join(out)


def normalize_iptables(text, chains, lines):
    """`iptables-save` without timestamps, packet counters, and ignored chains."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(":"):
            parts = line.split()
            if matches(parts[0][1:], chains):
                continue
            line = " ".join(parts[:2])  # ":INPUT ACCEPT [0:0]" -> ":INPUT ACCEPT"
        elif line.startswith(("-A ", "-I ")):
            if matches(line.split()[1], chains) or any(re.search(p, line) for p in lines):
                continue
        out.append(" ".join(line.split()))
    return "\n".join(out)


def read_live(ctx):
    """The normalized live ruleset. Raises RuleError when it cannot be read."""
    chains = ctx.cfg.list("firewall", "ignore_chains", list(IGNORE_CHAINS))
    lines = ctx.cfg.list("firewall", "ignore_lines", list(IGNORE_LINES))
    problems = []
    try:
        rc, out, err = ctx.run(["nft", "list", "ruleset"], timeout=30)
        if rc == 0 and out.strip():
            return normalize_nft(out, chains, lines)
        problems.append("nft: " + ((err or out).strip().splitlines() or ["no output"])[0][:80] if rc != 127 else "")
        parts = []
        for tool in ("iptables-save", "ip6tables-save"):
            rc, out, err = ctx.run([tool], timeout=30)
            if rc == 127:
                continue
            if rc != 0:
                raise RuleError("%s: %s" % (tool, ((err or out).strip().splitlines() or ["failed"])[0][:80]))
            parts.append(normalize_iptables(out, chains, lines))
        if parts:
            return "\n".join(p for p in parts if p)
    except Blocked as exc:  # before Skip: Blocked is a kind of Skip
        raise RuleError(str(exc))
    except Skip:
        raise RuleError("timed out reading the rules")
    raise RuleError("; ".join(p for p in problems if p) or "neither nft nor iptables-save is installed")


def approved_path(ctx):
    return os.path.join(ctx.state_dir, APPROVED) if ctx.state_dir else None


def load_approved(path):
    try:
        with open(path) as fh:
            return fh.read().rstrip("\n")
    except OSError:
        return None


def changes(old, new):
    """(added, removed) lines between two normalized rulesets."""
    added, removed = [], []
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].strip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].strip())
    return added, removed


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:8]


def main(argv):
    ap = argparse.ArgumentParser(prog="centinela firewall", description=__doc__.strip().splitlines()[0])
    ap.add_argument("action", choices=("show", "diff", "approve"),
                    help="show: the live rules as compared; diff: live against approved; approve: save the live rules as the approved set")
    ap.add_argument("--config", default=os.environ.get("CENTINELA_CONF", "/etc/centinela/centinela.toml"))
    ap.add_argument("--state", help="state file; the approved rules are saved next to it")
    args = ap.parse_args(argv)
    cfg = Config.load(args.config)
    state_path = args.state or cfg.get("general", "state_file", "/var/lib/centinela/state.json")
    ctx = Ctx(cfg)
    ctx.state_dir = os.path.dirname(state_path) or "."
    try:
        live = read_live(ctx)
    except RuleError as exc:
        print("centinela: cannot read the firewall rules: %s (run with sudo)" % exc, file=sys.stderr)
        return 2
    path = approved_path(ctx)
    if args.action == "show":
        print(live)
        return 0
    approved = load_approved(path)
    if args.action == "diff":
        if approved is None:
            print("Nothing approved yet. Review `centinela firewall show`, then `sudo centinela firewall approve`.")
            return 1
        added, removed = changes(approved, live)
        for line in removed:
            print("- " + line)
        for line in added:
            print("+ " + line)
        print("" if added or removed else "The live rules match the approved set.")
        return 1 if added or removed else 0
    if not live.strip():
        print("centinela: the live ruleset is empty; not approving an empty firewall", file=sys.stderr)
        return 2
    try:
        os.makedirs(ctx.state_dir, mode=0o700, exist_ok=True)
        with locked(state_path):
            write_private(path, live + "\n")
    except OSError as exc:
        print("centinela: cannot write %s: %s (use sudo?)" % (path, exc), file=sys.stderr)
        return 2
    print("Approved %d lines (%s) in %s. From now on a different ruleset is reported." % (
        len(live.splitlines()), digest(live), path))
    return 0
