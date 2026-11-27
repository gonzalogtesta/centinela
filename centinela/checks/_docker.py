"""What the docker checks share: reading containers (socket or Docker's own files) and image names.

Not a check itself (the leading underscore keeps it out of the module list)."""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from collections import namedtuple

from ..core import Skip


PS_FORMAT = ("{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t"
             '{{.Label "com.docker.compose.project.working_dir"}}\t{{.Label "com.docker.compose.service"}}')

TAG = re.compile(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-(.+))?$")

HUB_HOSTS = (None, "docker.io", "index.docker.io", "registry-1.docker.io")

Ref = namedtuple("Ref", "registry repo tag")

Container = namedtuple("Container", "name image state status workdir service")

q = shlex.quote

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

def norm(name):
    return name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"

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


class Unreachable(Exception):
    """The docker daemon does not answer (as opposed to: we may not use its socket)."""


def list_containers(ctx, who):
    """Every container, from the socket, or from Docker's files when the account may not use the socket.
    Raises Unreachable when the daemon is down. `who` names the check, for the note on stderr."""
    rc, _, err = ctx.run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    if rc != 0 and "permission denied" in err.lower():  # not a down daemon: we are just not allowed in
        containers = read_containers(data_root(ctx.cfg))
        print("centinela: %s: no socket access, reading container files" % who, file=sys.stderr)
        return containers
    if rc != 0:
        raise Unreachable()
    _, out, _ = ctx.run(["docker", "ps", "-a", "--format", PS_FORMAT])
    return parse_ps(out)
