"""Who is this server? Builds the label shown at the top of every message."""
from __future__ import annotations

import re
import socket
import sys

from .core import Skip

PUBLIC_IP_URL = "https://api.ipify.org"
KNOWN = ("host", "ip", "public_ip", "os")


def local_ip():
    """Address of the interface used for the default route. UDP connect sends no packet."""
    for family, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((probe, 9))
                return sock.getsockname()[0]
        except OSError:
            continue
    return ""


def os_name():
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return ""


def describe(cfg, http_get=None):
    """'my-vps (10.0.0.5, 203.0.113.9)' from [general] host_name and [notify] show."""
    show = cfg.list("notify", "show", "host") or ["host"]
    name = cfg.get("general", "host_name") or socket.gethostname()
    extras = []
    for item in show:
        if item == "ip":
            extras.append(local_ip())
        elif item == "os":
            extras.append(os_name())
        elif item == "public_ip" and http_get:
            try:
                ip = http_get(cfg.get("notify", "public_ip_url", PUBLIC_IP_URL), 5).strip()
                extras.append(ip if re.fullmatch(r"[0-9a-fA-F:.]{3,45}", ip) else "")
            except Skip as exc:
                print("centinela: public_ip unavailable: %s" % exc, file=sys.stderr)
        elif item not in KNOWN:
            print("centinela: unknown [notify] show item %r (use %s)" % (item, ", ".join(KNOWN)), file=sys.stderr)
    extras = [e for e in extras if e]
    return "%s (%s)" % (name, ", ".join(extras)) if extras else name
