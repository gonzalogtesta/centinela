"""Installed nginx vs nginx.org security advisories and the latest release of its track."""
from __future__ import annotations

import re
import shutil
import sys

from ..core import CRIT, WARN, Finding, Skip, short_hash, vtuple

NAME = "nginx"
DESC = "nginx.org advisories vs installed version; behind latest stable/mainline"
NEEDS = ()  # what it needs when not root: see install.py

ADVISORIES = "https://nginx.org/en/security_advisories.html"
DOWNLOADS = "https://nginx.org/en/download.html"
UPGRADE = "sudo apt-get update && sudo apt-get install --only-upgrade nginx"

_LI = re.compile(r"<li><p>(.*?)</p></li>", re.S)
_BR = re.compile(r"<br\s*/?>", re.I)
_TAG = re.compile(r"<[^>]+>")
_CVE = re.compile(r"CVE-\d{4}-\d+")
_VER = r"\d+(?:\.\d+)*"


def applicable(cfg):
    return shutil.which(cfg.get("nginx", "binary", "nginx")) is not None


def installed_version(text):
    m = re.search(r"nginx/(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else None


def _items(raw):
    return [i.strip() for i in raw.split(",") if i.strip() and "windows" not in i.lower()]


def parse_advisories(html):
    out = []
    for block in _LI.findall(html):
        parts = [_TAG.sub("", p).strip() for p in _BR.split(block)]
        adv = {"title": parts[0], "severity": "", "vulnerable": [], "safe": [], "cves": []}
        for p in parts[1:]:
            low = p.lower()
            if low.startswith("severity:"):
                adv["severity"] = p.split(":", 1)[1].strip().lower()
            elif low.startswith("not vulnerable:"):
                adv["safe"] = _items(p.split(":", 1)[1])
            elif low.startswith("vulnerable:"):
                adv["vulnerable"] = _items(p.split(":", 1)[1])
            adv["cves"] += _CVE.findall(p)
        if adv["vulnerable"]:
            out.append(adv)
    return out


def affects(version, adv):
    """True if `version` is in a vulnerable range and not fixed on its own branch."""
    v = vtuple(version)
    for item in adv["safe"]:  # '1.30.7+': fixed from 1.30.7 on the 1.30 branch
        m = re.fullmatch(r"(%s)\+" % _VER, item)
        if m:
            fixed = vtuple(m.group(1))
            if fixed[:2] == v[:2] and v >= fixed:
                return False
    for item in adv["vulnerable"]:
        m = re.fullmatch(r"(%s)(?:-(%s))?" % (_VER, _VER), item)
        if m and vtuple(m.group(1)) <= v <= vtuple(m.group(2) or m.group(1)):
            return True
    return False


def fixed_in(version, adv):
    v = vtuple(version)
    fixes = [i[:-1] for i in adv["safe"] if i.endswith("+")]
    same = [f for f in fixes if vtuple(f)[:2] == v[:2]]
    track = [f for f in fixes if vtuple(f)[1] % 2 == v[1] % 2]  # stay on stable (even) or mainline (odd)
    return (same or track or fixes or ["a newer release"])[0]


def parse_downloads(html):
    """-> {'mainline': '1.31.9', 'stable': '1.30.7'}"""
    out = {}
    for track, heading in (("mainline", "Mainline version"), ("stable", "Stable version")):
        i = html.find(heading)
        m = re.search(r"nginx-(\d+\.\d+\.\d+)\.tar\.gz", html[i:]) if i >= 0 else None
        if m:
            out[track] = m.group(1)
    return out


def run(ctx):
    cfg = ctx.cfg
    rc, out, err = ctx.run([cfg.get("nginx", "binary", "nginx"), "-v"])
    version = installed_version(out + err)
    if not version:
        raise Skip("cannot read nginx version from 'nginx -v'")
    findings, any_ok = [], False

    try:
        advisories = parse_advisories(ctx.http_get(cfg.get("nginx", "advisories_url", ADVISORIES)))
        any_ok = True
    except Skip as exc:
        print("centinela: nginx advisories unavailable: %s" % exc, file=sys.stderr)
        advisories = []
    for adv in advisories:
        if not affects(version, adv):
            continue
        ident = adv["cves"][0] if adv["cves"] else short_hash(adv["title"])
        level = CRIT if adv["severity"] in ("critical", "major", "high") else WARN
        findings.append(Finding(
            NAME, "advisory-" + ident, level,
            "nginx %s is vulnerable: %s (%s, %s); fixed in %s"
            % (version, adv["title"][:70], ident, adv["severity"] or "unrated", fixed_in(version, adv)),
            UPGRADE))

    try:
        latest = parse_downloads(ctx.http_get(cfg.get("nginx", "downloads_url", DOWNLOADS)))
        any_ok = True
    except Skip as exc:
        print("centinela: nginx download page unavailable: %s" % exc, file=sys.stderr)
        latest = {}
    track = "mainline" if vtuple(version)[1] % 2 else "stable"  # odd minor = mainline
    newest = latest.get(track)
    if newest and vtuple(version) < vtuple(newest) and not findings:
        findings.append(Finding(
            NAME, "behind-" + newest, WARN,
            "nginx %s is behind the latest %s %s" % (version, track, newest), UPGRADE))

    if not any_ok:
        raise Skip("nginx.org unreachable")
    return findings
