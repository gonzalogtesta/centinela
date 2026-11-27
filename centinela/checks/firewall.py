"""ufw is active, and (once you approved them) the rules in force are the ones you approved.

Disable this module on hosts where neither applies."""
from __future__ import annotations

import os
import re
import shutil
import sys

from .. import rules
from ..core import CRIT, WARN, Finding, Skip

NAME = "firewall"
DESC = "ufw is active; the firewall rules in force match the ones you approved"
NEEDS = ('files', 'netadmin')  # what it needs when not root: see install.py
FREQUENT = True  # cheap and local: also runs on the frequent timer

UFW_CONF = "/etc/ufw/ufw.conf"


def applicable(cfg):
    return shutil.which("ufw") is not None or os.path.exists(os.path.join(
        os.path.dirname(cfg.get("general", "state_file", "/var/lib/centinela/state.json")), rules.APPROVED))


def enabled_in_config(path=None):
    """ENABLED=yes/no from ufw's config, which an account with read access can see; None if unreadable."""
    try:
        with open(path or UFW_CONF) as fh:
            text = fh.read()
    except OSError:
        return None
    found = re.search(r"^\s*ENABLED\s*=\s*(\w+)", text, re.M | re.I)
    return found.group(1).lower() == "yes" if found else None


def run(ctx):
    findings = rules_findings(ctx)
    try:
        return findings + ufw_findings(ctx)
    except Skip as exc:
        if not rules.approved_path(ctx) or rules.load_approved(rules.approved_path(ctx)) is None:
            raise
        print("centinela: firewall: %s" % exc, file=sys.stderr)  # the approved-rules comparison above still ran
        return findings


def rules_findings(ctx):
    """Compare the live ruleset with the approved one; nothing happens until `centinela firewall approve`."""
    path = rules.approved_path(ctx)
    approved = rules.load_approved(path) if path else None
    if approved is None:
        return []
    try:
        live = rules.read_live(ctx)
    except rules.RuleError as exc:  # approved but unreadable is a blind spot, not health
        return [Finding(NAME, "rules-unreadable", WARN, "approved firewall rules cannot be read now (%s); they are "
                        "not being checked" % exc, "sudo centinela firewall show")]
    if live == approved:
        return []
    added, removed = rules.changes(approved, live)
    sample = ""
    if ctx.cfg.bool("firewall", "show_changes", True):
        shown = ["+ " + l for l in added[:2]] + ["- " + l for l in removed[:2]]
        sample = ": " + "; ".join(l[:70] for l in shown[:3])
    return [Finding(NAME, "rules-changed-" + rules.digest(live), CRIT,
                    "firewall rules differ from the approved set (+%d -%d lines)%s" % (len(added), len(removed), sample),
                    "sudo centinela firewall diff   # if the change is yours: sudo centinela firewall approve")]


def ufw_findings(ctx):
    rc, out, err = ctx.run(["ufw", "status"])
    if rc == 127:
        raise Skip("ufw is not installed")
    if rc != 0:
        on = enabled_in_config()
        if on is None:
            raise Skip("ufw status failed (needs root) and %s cannot be read: %s" % (UFW_CONF, (err or out).strip()[:80]))
        print("centinela: firewall: not root, reading %s (the rules loaded now are not checked)" % UFW_CONF,
              file=sys.stderr)
        if on:
            return []
        return [Finding(NAME, "ufw-inactive", CRIT, "ufw is disabled in %s" % UFW_CONF,
                        "sudo ufw status verbose  # confirm your SSH port is allowed, then: sudo ufw enable")]
    first = out.strip().splitlines()[0].lower() if out.strip() else ""
    if first == "status: active":
        return []
    return [Finding(NAME, "ufw-inactive", CRIT, "ufw is not active (%s)" % (first or "no output"),
                    "sudo ufw status verbose  # confirm your SSH port is allowed, then: sudo ufw enable")]
