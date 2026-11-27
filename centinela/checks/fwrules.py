"""The firewall rules in force are the ones you approved.

Nothing is reported until you approve a set with `sudo centinela firewall approve`
(see `centinela firewall show` and `diff`). Settings stay in the [firewall] section."""
from __future__ import annotations

import os
import shutil

from .. import rules
from ..core import CRIT, WARN, Finding

NAME = "fwrules"
DESC = "the firewall rules in force match the ones you approved"
NEEDS = ('netadmin',)  # what it needs when not root: see install.py
FREQUENT = True  # cheap and local: also runs on the frequent timer


def applicable(cfg):
    return shutil.which("ufw") is not None or os.path.exists(os.path.join(
        os.path.dirname(cfg.get("general", "state_file", "/var/lib/centinela/state.json")), rules.APPROVED))


def run(ctx):
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
