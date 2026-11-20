"""ufw is active. Disable this module on hosts that use nftables/firewalld directly."""
from __future__ import annotations

import shutil

from ..core import CRIT, Finding, Skip

NAME = "firewall"
DESC = "ufw status is active"


def applicable(cfg):
    return shutil.which("ufw") is not None


def run(ctx):
    rc, out, err = ctx.run(["ufw", "status"])
    if rc != 0:
        raise Skip("ufw status failed (needs root): %s" % (err or out).strip()[:80])
    first = out.strip().splitlines()[0].lower() if out.strip() else ""
    if first == "status: active":
        return []
    return [Finding(NAME, "ufw-inactive", CRIT, "ufw is not active (%s)" % (first or "no output"),
                    "sudo ufw status verbose  # confirm your SSH port is allowed, then: sudo ufw enable")]
