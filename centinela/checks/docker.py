"""Containers not running, and images behind the newest tag of their major on Docker Hub.

Only Docker Hub images are compared (ghcr.io, quay.io, locally built images
are skipped silently). The base image of your own app image is detected
automatically when possible (see find_base); otherwise list it with
docker.watch_images (globs matched against `docker image ls`), docker.extra_images
or docker.dockerfiles.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import shutil
import sys
from collections import namedtuple

from ..core import CRIT, WARN, Finding, HttpError, Skip

NAME = "docker"
DESC = "containers down/unhealthy or running untrusted images; image tags behind latest of the same major"
FREQUENT = True  # cheap and local: also runs on the frequent timer

HUB = "https://hub.docker.com/v2/repositories"
PS_FORMAT = ("{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t"
             '{{.Label "com.docker.compose.project.working_dir"}}\t{{.Label "com.docker.compose.service"}}')
TAG = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-(.+))?$")
HUB_HOSTS = (None, "docker.io", "index.docker.io", "registry-1.docker.io")

Ref = namedtuple("Ref", "registry repo tag")
Container = namedtuple("Container", "name image state status workdir service")

q = shlex.quote


def applicable(cfg):
    return shutil.which("docker") is not None


def parse_ref(ref):
    ref = ref.split("@", 1)[0]
    name, tag = ref, "latest"
    if ":" in ref.rsplit("/", 1)[-1]:
        name, tag = ref.rsplit(":", 1)
    parts = name.split("/")
    registry = None
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry = parts.pop(0)
    repo = "/".join(parts)
    if registry in HUB_HOSTS:
        registry = None
        if "/" not in repo:
            repo = "library/" + repo
    return Ref(registry, repo, tag)


def display(ref):
    repo = ref.repo[len("library/"):] if ref.repo.startswith("library/") else ref.repo
    return "%s:%s" % (repo, ref.tag)


def parse_ps(out):
    rows = []
    for line in out.splitlines():
        cols = line.split("\t")
        if len(cols) == 6:
            rows.append(Container(*cols))
    return rows


def parse_tag(tag):
    """'7.4.1-alpine' -> (version tuple, suffix); None if not a version tag."""
    m = TAG.match(tag)
    if not m:
        return None
    ver = tuple(int(x) for x in m.groups()[:3] if x is not None)
    return ver, m.group(4) or ""


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


def norm(name):
    return name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"


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


DEFAULT_ROOT = "/var/lib/docker"


def data_root(cfg):
    """Docker's data directory: [docker] data_root, else "data-root" of daemon.json, else /var/lib/docker."""
    root = cfg.get("docker", "data_root", "")
    if root:
        return str(root)
    try:
        with open("/etc/docker/daemon.json") as fh:
            return str(json.load(fh).get("data-root") or DEFAULT_ROOT)
    except (OSError, ValueError, AttributeError):
        return DEFAULT_ROOT


def pid_alive(pid, cid):
    """The process Docker recorded is still there and belongs to that container (the file says
    Running even after a power cut)."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        with open("/proc/%d/cgroup" % pid) as fh:
            return cid[:12] in fh.read()
    except FileNotFoundError:
        return False
    except OSError:
        return os.path.isdir("/proc/%d" % pid)  # cannot read its cgroup: the process existing is the best we know


def container_from_config(conf, alive=None):
    """One container from Docker's own config.v2.json, shaped like a `docker ps -a` row."""
    alive = alive or pid_alive
    st, cfg = conf.get("State") or {}, conf.get("Config") or {}
    labels = cfg.get("Labels") or {}
    name = str(conf.get("Name") or conf.get("ID", "")[:12]).lstrip("/")
    if st.get("Restarting"):
        state, status = "restarting", "Restarting (%s)" % st.get("ExitCode", 0)
    elif st.get("Running") and alive(st.get("Pid"), str(conf.get("ID", ""))):
        state = "paused" if st.get("Paused") else "running"
        health = (st.get("Health") or {}).get("Status")
        status = "Up since %s%s" % (st.get("StartedAt", "?"), " (unhealthy)" if health == "unhealthy" else "")
    elif st.get("StartedAt", "0001").startswith("0001"):
        state, status = "created", "Created"
    else:
        state, status = "exited", "Exited (%s) at %s" % (st.get("ExitCode", "?"), st.get("FinishedAt", "?"))
    return Container(name, str(cfg.get("Image", "")), state, status,
                     str(labels.get("com.docker.compose.project.working_dir", "")),
                     str(labels.get("com.docker.compose.service", "")))


def read_containers(root, alive=None):
    """Containers from /var/lib/docker/containers/*/config.v2.json: no socket needed, only read access.
    Docker's internal format, so unknown or half-written files are skipped, never fatal."""
    base = os.path.join(root, "containers")
    try:
        ids = sorted(os.listdir(base))
    except OSError as exc:
        raise Skip("docker socket not accessible and %s cannot be read (%s); run with sudo, or as a user in "
                   "the docker group, or give the account read access (restricted install)" % (base, exc.strerror))
    containers = []
    for cid in ids:
        try:
            with open(os.path.join(base, cid, "config.v2.json")) as fh:
                containers.append(container_from_config(json.load(fh), alive))
        except (OSError, ValueError, AttributeError, TypeError):
            continue
    return containers


def images(ctx, containers):
    """Image tags behind the registry: asks Docker Hub, so not on a frequent run."""
    return [] if ctx.mode == "frequent" else check_images(ctx, containers)


def run(ctx):
    rc, _, err = ctx.run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if rc != 0 and "permission denied" in err.lower():  # not a down daemon: we are just not allowed in
        containers = read_containers(data_root(ctx.cfg))
        print("centinela: docker: no socket access, reading container files (image rebuilds are not checked)",
              file=sys.stderr)
        return check_containers(ctx, containers) + check_trusted(ctx, containers) + images(ctx, containers)
    if rc != 0:
        return [Finding(NAME, "daemon", CRIT, "docker daemon is not reachable",
                        "systemctl status docker --no-pager")]
    _, out, _ = ctx.run(["docker", "ps", "-a", "--format", PS_FORMAT])
    containers = parse_ps(out)
    return check_containers(ctx, containers) + check_trusted(ctx, containers) + images(ctx, containers)
