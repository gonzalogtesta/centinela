"""Containers not running or unhealthy, and containers running an image you did not trust.

Needs only the container list, which Docker keeps in files an account with read access can open.
The image tags behind Docker Hub are the separate docker-images check (it asks the network)."""
from __future__ import annotations

import fnmatch
import re
import shutil

from ..core import CRIT, Finding
from ._docker import PS_FORMAT, Container, Unreachable, list_containers, parse_ps, parse_tag, q  # noqa: F401

NAME = "docker"
DESC = "containers down/unhealthy, or running an image you did not trust"
NEEDS = ('files',)  # the container files are enough: see install.py
FREQUENT = True  # cheap and local: also runs on the frequent timer


def applicable(cfg):
    return shutil.which("docker") is not None


def check_containers(ctx, containers):
    cfg = ctx.cfg
    ignore = cfg.list("docker", "ignore_containers")
    allow_exit0 = cfg.bool("docker", "allow_exit_zero", False)
    findings = []
    for c in containers:
        if any(fnmatch.fnmatch(c.name, p) for p in ignore):
            continue
        logs = "docker logs --tail 50 " + q(c.name)
        if c.state != "running":
            if c.state == "exited" and allow_exit0 and "Exited (0)" in c.status:
                continue
            findings.append(Finding(NAME, "down-" + c.name, CRIT,
                                    "container %s is %s (%s)" % (c.name, c.state, c.status), logs))
        elif "(unhealthy)" in c.status:
            findings.append(Finding(NAME, "unhealthy-" + c.name, CRIT,
                                    "container %s is unhealthy (%s)" % (c.name, c.status), logs))
    return findings

REGISTRY_PREFIXES = ("index.docker.io/", "registry-1.docker.io/", "docker.io/")

IMAGE_ID = re.compile(r"^(sha256:)?[0-9a-f]{12,64}$")

def image_forms(image):
    """Spellings a pattern may use: as shown, without @digest, without docker.io/ and library/."""
    forms = {image, image.split("@", 1)[0]}
    for form in list(forms):
        for prefix in REGISTRY_PREFIXES:
            if form.startswith(prefix):
                form = form[len(prefix):]
        forms.add(form[len("library/"):] if form.startswith("library/") else form)
    return forms

def generalize(image):
    """Turn a pinned tag into a pattern: 'redis:7.4' -> 'redis:7.*', 'app:20261118-ab' -> 'app:*'.

    Pure major tags ('redis:7'), 'latest', 'bookworm' and untagged names stay exact.
    """
    ref = image.split("@", 1)[0]
    if ":" not in ref.rsplit("/", 1)[-1]:
        return ref
    name, tag = ref.rsplit(":", 1)
    v = "v" if re.match(r"v\d", tag) else ""
    parsed = parse_tag(tag[len(v):])
    if parsed:
        ver, suffix = parsed
        if ver[0] >= 1000:  # date or build number
            return name + ":*"
        if len(ver) >= 2:
            return "%s:%s%d.*%s" % (name, v, ver[0], "-" + suffix if suffix else "")
        return ref
    return name + ":*" if re.match(r"(v?\d|sha-|[0-9a-f]{7,}$)", tag) else ref

def norm_repo(name):
    """'Docker.io/library/Redis' -> 'redis': the spelling image names and rules are compared in."""
    name = name.lower()
    for prefix in REGISTRY_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name[len("library/"):] if name.startswith("library/") else name

def split_image(image):
    """'ghcr.io/Me/App:1.2@sha256:...' -> ('ghcr.io/me/app', '1.2'); no tag means 'latest'."""
    ref = image.split("@", 1)[0]
    name, tag = ref.rsplit(":", 1) if ":" in ref.rsplit("/", 1)[-1] else (ref, "latest")
    return norm_repo(name), tag

def image_rules(cfg):
    """[docker.images] -> {repo: [tag globs]}. `redis = "7.4"` is exactly redis:7.4 (fixed);
    `myapp = "1.*"` any 1.x; `worker = "*"` any tag; a list allows several."""
    rules = {}
    for repo, rule in cfg.table("docker", "images").items():
        rules[norm_repo(str(repo))] = [str(r) for r in rule] if isinstance(rule, list) else [str(rule)]
    return rules

def matching_rule(image, rules):
    repo, tag = split_image(image)
    return next((r for r in rules.get(repo, []) if fnmatch.fnmatchcase(tag, r)), None)

def is_exact(rule):
    return not any(ch in rule for ch in "*?[")

def check_trusted(ctx, containers):
    """Running containers whose image is allowed by none of [docker.images], trusted_images, ignore_images.

    Off if nothing is listed or docker.freeze_images = false (default: on once something is trusted).

    A snapshot at run time: a container that starts and exits between two runs is not seen.
    Applies to every container, including those in ignore_containers.
    """
    trusted = ctx.cfg.list("docker", "trusted_images")
    rules = image_rules(ctx.cfg)
    patterns = trusted + ctx.cfg.list("docker", "ignore_images")  # ignored = seen and not cared about
    if not (patterns or rules) or not ctx.cfg.bool("docker", "freeze_images", bool(trusted or rules)):
        return []
    groups = {}
    for c in containers:
        if c.state in ("running", "restarting") and matching_rule(c.image, rules) is None and not any(
                fnmatch.fnmatchcase(form, p) for form in image_forms(c.image) for p in patterns):
            groups.setdefault(c.image, []).append(c)
    findings = []
    for image, cs in sorted(groups.items()):
        names = ", ".join(c.name for c in cs[:3]) + (" +%d more" % (len(cs) - 3) if len(cs) > 3 else "")
        note = " (an image id: its tag was moved or removed)" if IMAGE_ID.match(image) else ""
        findings.append(Finding(
            NAME, "untrusted-" + image, CRIT,
            "unexpected image %s%s running in %s (%s); not in the trusted list" % (image, note, names, cs[0].status),
            "docker inspect " + q(cs[0].name)))
    return findings


def run(ctx):
    try:
        containers = list_containers(ctx, NAME)
    except Unreachable:
        return [Finding(NAME, "daemon", CRIT, "docker daemon is not reachable",
                        "systemctl status docker --no-pager")]
    return check_containers(ctx, containers) + check_trusted(ctx, containers)
