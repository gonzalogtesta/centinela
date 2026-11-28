"""ufw is active.

Disable this module on hosts without ufw. The firewall rules in force are checked by the
separate fwrules module."""
from __future__ import annotations

import re
import shutil
import sys

from ..core import CRIT, Finding, Skip

NAME = "ufw"
DESC = "ufw is active"
NEEDS = ('ufw',)  # what it needs when not root: see install.py
FREQUENT = True  # cheap and local: also runs on the frequent timer

UFW_CONF = "/etc/ufw/ufw.conf"


def applicable(cfg):
    return shutil.which("ufw") is not None


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
    rc, out, err = ctx.run(["ufw", "status"])
    if rc == 127:
        raise Skip("ufw is not installed")
    if rc != 0:
        on = enabled_in_config()
        if on is None:
            raise Skip("ufw status failed (needs root) and %s cannot be read: %s" % (UFW_CONF, (err or out).strip()[:80]))
        print("centinela: ufw: not root, reading %s (the rules loaded now are not checked)" % UFW_CONF,
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
