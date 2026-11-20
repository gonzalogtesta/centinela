"""Let's Encrypt certificates close to expiry. Reads the PEMs directly: no certbot lock, no changes."""
from __future__ import annotations

import os
import shlex
import shutil
from datetime import datetime, timezone

from ..core import CRIT, WARN, Finding, Skip

NAME = "certbot"
DESC = "certificates in /etc/letsencrypt/live expiring soon"


def applicable(cfg):
    return os.path.isdir(cfg.get("certbot", "live_dir", "/etc/letsencrypt/live"))


def parse_enddate(out):
    """'notAfter=Feb  1 12:00:00 2027 GMT' -> aware datetime"""
    raw = out.strip().partition("=")[2]
    return datetime.strptime(" ".join(raw.split()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def run(ctx, now=None):
    if not shutil.which("openssl"):
        raise Skip("openssl not installed")
    live = ctx.cfg.get("certbot", "live_dir", "/etc/letsencrypt/live")
    warn_days = ctx.cfg.int("certbot", "warn_days", 21)
    crit_days = ctx.cfg.int("certbot", "crit_days", 7)
    now = now or datetime.now(timezone.utc)
    try:
        names = sorted(n for n in os.listdir(live) if os.path.isdir(os.path.join(live, n)))
    except PermissionError:
        raise Skip("cannot read %s (needs root)" % live)
    findings = []
    for name in names:
        rc, out, _ = ctx.run(["openssl", "x509", "-noout", "-enddate", "-in", os.path.join(live, name, "cert.pem")])
        if rc != 0:
            continue
        end = parse_enddate(out)
        days = (end - now).days
        if days >= warn_days:
            continue
        level = CRIT if days < crit_days else WARN
        state = "EXPIRED" if end <= now else "expires in %dd" % days
        findings.append(Finding(NAME, name, level, "certificate %s %s (%s)" % (name, state, end.date()),
                                "sudo certbot renew --cert-name " + shlex.quote(name)))
    return findings
