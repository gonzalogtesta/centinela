"""Images behind the newest tag of their major on Docker Hub, and base images rebuilt upstream.

Only Docker Hub images are compared (ghcr.io, quay.io, locally built images
are skipped silently). The base image of your own app image is detected
automatically when possible (see find_base); otherwise list it with
docker.watch_images (globs matched against `docker image ls`), docker.extra_images
or docker.dockerfiles. Settings stay in the [docker] section.
"""
from __future__ import annotations

import fnmatch
import json
import re
import shutil
import sys

from ..core import WARN, Finding, HttpError, Skip
from ._docker import Ref, Unreachable, display, list_containers, norm, parse_ref, parse_tag, q
from .docker import image_rules, is_exact, matching_rule

NAME = "docker-images"
DESC = "image tags behind the latest of the same major on Docker Hub; base images rebuilt under the same tag"
NEEDS = ('files', 'docker')  # what it needs when not root: see install.py

HUB = "https://hub.docker.com/v2/repositories"


def applicable(cfg):
    return shutil.which("docker") is not None


def newest_same_major(cur_tag, names, track="major"):
    """Newest tag with the same major (or major.minor), suffix and precision as cur_tag."""
    cur = parse_tag(cur_tag)
    if not cur:
        return None
    ver, suffix = cur
    prec = len(ver)
    keep = 1 if track == "major" else min(2, prec)
    best = None
    for name in names:
        cand = parse_tag(name)
        if not cand or cand[1] != suffix or len(cand[0]) != prec or cand[0][:keep] != ver[:keep]:
            continue
        if cand[0] > ver and (best is None or cand[0] > parse_tag(best)[0]):
            best = name
    return best

def hub_tags(ctx, repo, major):
    url = "%s/%s/tags?page_size=100&ordering=last_updated&name=%d." % (HUB, repo, major)
    names = []
    for _ in range(ctx.cfg.int("docker", "hub_pages", 3)):
        data = json.loads(ctx.http_get(url))
        names += [r["name"] for r in data.get("results", [])]
        url = data.get("next")
        if not url or not url.startswith("https://hub.docker.com/"):
            break
    return names

def dockerfile_images(path):
    images = []
    try:
        with open(path) as fh:
            for line in fh:
                m = re.match(r"\s*FROM\s+(?:--\S+\s+)*(\S+)", line, re.I)
                if m and m.group(1).lower() != "scratch" and "$" not in m.group(1):
                    images.append(m.group(1))
    except OSError:
        pass
    return images

def watched_images(ctx, patterns):
    """Local images (`docker image ls`) matching any glob, e.g. "python:3.12*".

    Old tags pile up with rotating pulls/deploys, so only the newest local version
    per repository and variant (-slim, -alpine, ...) is kept; non-version tags such
    as "latest" or "bookworm" are each kept on their own.
    """
    if not patterns:
        return []
    rc, out, _ = ctx.run(["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
    if rc != 0:
        return []
    names = {n for n in out.split() if "<none>" not in n and any(fnmatch.fnmatch(n, p) for p in patterns)}
    best = {}
    for name in sorted(names):
        ref = parse_ref(name)
        parsed = parse_tag(ref.tag)
        key = (ref.registry, ref.repo, parsed[1] if parsed else ref.tag)
        version = parsed[0] if parsed else ()
        if key not in best or version > best[key][0]:
            best[key] = (version, name)
    return sorted(name for _, name in best.values())

BASE_LABEL = "org.opencontainers.image.base.name"

def local_image_records(ctx, limit=300):
    """`docker image inspect` of every local image (one call), or [] on any failure."""
    rc, out, _ = ctx.run(["docker", "image", "ls", "--no-trunc", "-q"])
    ids = sorted(set(out.split()))[:limit]
    if rc != 0 or not ids:
        return []
    rc, out, _ = ctx.run(["docker", "image", "inspect"] + ids, timeout=60)
    try:
        return json.loads(out) if rc == 0 else []
    except ValueError:
        return []

def find_base(app_image, records):
    """Best guess at the Dockerfile FROM of a local image, or None.

    Docker does not record FROM. Two hints: the OCI base-name label some builders
    set, or a Docker Hub image whose layers are the first layers of this one.
    A heuristic: it needs the base image still present locally under its tag.
    """
    app = next((r for r in records if norm(app_image) in (r.get("RepoTags") or [])), None)
    if not app:
        return None
    label = ((app.get("Config") or {}).get("Labels") or {}).get(BASE_LABEL)
    if label:
        return label
    layers = (app.get("RootFS") or {}).get("Layers") or []
    app_repo = parse_ref(app_image).repo
    best = None  # (layer count, tags)
    for r in records:
        lay = (r.get("RootFS") or {}).get("Layers") or []
        tags = [t for t in r.get("RepoTags") or [] if not t.endswith(":<none>")
                and parse_ref(t).registry is None and parse_ref(t).repo != app_repo]  # not older builds of the app
        if tags and lay and len(lay) < len(layers) and layers[: len(lay)] == lay and (best is None or len(lay) > best[0]):
            best = (len(lay), tags)
    if not best:
        return None
    versioned = sorted((t for t in best[1] if parse_tag(parse_ref(t).tag)),
                       key=lambda t: len(parse_tag(parse_ref(t).tag)[0]))
    return (versioned or best[1])[0]  # least precise version tag: usually the one you pinned

def _update_cmd(ref_str, container, base_of=None):
    if base_of:  # a base image only reaches the app by rebuilding it
        if container and container.workdir and container.service:
            return "cd %s && docker compose build --pull %s && docker compose up -d %s" % (
                q(container.workdir), q(container.service), q(container.service))
        return "docker pull %s  # then rebuild %s" % (q(ref_str), base_of)
    if container and container.workdir and container.service:
        return "cd %s && docker compose pull %s && docker compose up -d %s" % (
            q(container.workdir), q(container.service), q(container.service))
    return "docker pull " + q(ref_str)

def check_images(ctx, containers):
    cfg = ctx.cfg
    ignore = cfg.list("docker", "ignore_images")
    by_image = {}
    for c in containers:
        by_image.setdefault(c.image, (c, None))
    if cfg.bool("docker", "detect_base", True):
        records = local_image_records(ctx)
        for image, (c, _) in list(by_image.items()):
            base = find_base(image, records) if not image.startswith("sha256:") else None
            if base:
                by_image.setdefault(base, (c, image))
    extra = list(cfg.list("docker", "extra_images"))
    extra += watched_images(ctx, cfg.list("docker", "watch_images"))
    for df in cfg.list("docker", "dockerfiles"):
        extra += dockerfile_images(df)
    for image in extra:
        by_image.setdefault(image, (None, None))

    findings = []
    for image, (container, base_of) in sorted(by_image.items()):
        if image.startswith("sha256:") or any(fnmatch.fnmatch(image, p) for p in ignore):
            continue
        ref = parse_ref(image)
        if ref.registry is not None:
            continue
        try:
            findings += _check_image(ctx, image, ref, container, base_of)
        except HttpError as exc:
            if exc.code != 404:  # 404 = not on Docker Hub (locally built): not our business
                print("centinela: docker hub: %s" % exc, file=sys.stderr)
        except Skip as exc:
            print("centinela: docker hub unavailable for %s: %s" % (image, exc), file=sys.stderr)
    return findings

def _check_image(ctx, image, ref, container, base_of=None):
    cfg = ctx.cfg
    track = str(cfg.table("docker", "track").get(ref.repo.replace("library/", ""), "major"))
    shown = display(ref)
    what = "base image %s (of %s)" % (shown, base_of) if base_of else "image %s" % shown
    rule = matching_rule(image, image_rules(cfg))
    pinned = rule is not None and is_exact(rule)   # "fixed to 7.4": no nagging about newer tags, rebuilds still reported
    parsed = parse_tag(ref.tag)
    if parsed and not pinned:
        newest = newest_same_major(ref.tag, hub_tags(ctx, ref.repo, parsed[0][0]), track)
        if newest:
            new_ref = display(Ref(None, ref.repo, newest))
            return [Finding(NAME, "newer-%s-%s" % (shown, newest), WARN,
                            "%s is behind %s (same %s); bump the tag in your compose/Dockerfile"
                            % (what, new_ref, track), "docker pull " + q(new_ref))]
    # Same tag rebuilt upstream (base-image security rebuilds): compare digests.
    rc, out, _ = ctx.run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image])
    if rc != 0:
        return []
    local = {d.split("@", 1)[-1] for d in json.loads(out or "[]")}
    remote = json.loads(ctx.http_get("%s/%s/tags/%s" % (HUB, ref.repo, ref.tag))).get("digest", "")
    if local and remote and remote not in local:
        return [Finding(NAME, "rebuilt-%s-%s" % (shown, remote[7:15]), WARN,
                        "%s has a newer build on Docker Hub under the same tag" % what,
                        _update_cmd(image, container, base_of))]
    return []


def run(ctx):
    try:
        containers = list_containers(ctx, NAME + " (image rebuilds are not checked)")
    except Unreachable:
        raise Skip("docker daemon is not reachable (the docker check reports it)")
    return check_images(ctx, containers)
