"""Install modes for `centinela setup`: how much power Centinela runs with, what that costs, and doing it.

Three modes:
  full        root, in the bundled sandbox (read-only filesystem, no new privileges). Nothing is lost.
  restricted  its own account `centinela` with one capability, CAP_DAC_READ_SEARCH: it can read, never write.
  advanced    restricted, plus groups you choose (systemd-journal, adm, docker, your own) and, optionally,
              CAP_NET_ADMIN to read the firewall rules in force.

What each check needs without root is declared by the check itself (its NEEDS tuple), so the limits
shown here are computed from the checks on this machine, not written down by hand.
"""
from __future__ import annotations

import grp
import os
import re
import subprocess
import tempfile

MODES = ("full", "restricted", "advanced")
ACCOUNT = "centinela"
UNITS = ("centinela@", "centinela-failure@")  # the failure notice shares the state file, so it runs as the same account
DROPIN_NAME = "restricted.conf"

# Groups the wizard offers, with what each one gives away.
GROUPS = {
    "systemd-journal": "read the system journal and kernel log (oom check)",
    "adm": "read /var/log (also the journal on Debian)",
    "docker": "use the Docker socket. WARNING: root-equivalent on the host (anyone in it can mount / in a container)",
}
RANK = {"ok": 0, "unknown": 1, "reduced": 2, "lost": 3}


class Profile:
    def __init__(self, mode="full", net_admin=False, groups=()):
        self.mode = mode
        self.net_admin = net_admin and mode != "full"
        self.groups = tuple(g for g in dict.fromkeys(groups)) if mode == "advanced" else ()

    @property
    def root(self):
        return self.mode == "full"

    @property
    def caps(self):
        return () if self.root else ("CAP_DAC_READ_SEARCH",) + (("CAP_NET_ADMIN",) if self.net_admin else ())


def _token(profile, token):
    """-> (status, what is lost or reduced) for one need."""
    if profile.root:
        return "ok", ""
    if token == "files":
        return "ok", ""  # every restricted profile has CAP_DAC_READ_SEARCH
    if token == "journal":
        ok = {"systemd-journal", "adm"} & set(profile.groups)
        return ("ok", "") if ok else ("lost", "cannot read the kernel log (add the systemd-journal or adm group)")
    if token == "docker":
        if "docker" in profile.groups:
            return "ok", ""
        return "reduced", "reads Docker's files, not the socket: image rebuilds of the same tag are not checked"
    if token == "netadmin":
        if profile.net_admin:
            return "ok", ""
        return "reduced", "the ufw settings are checked, the rules in force in the kernel are not (needs CAP_NET_ADMIN)"
    if token == "procs":
        return "reduced", "process names of other accounts' listeners may be missing"
    if token == "root":
        return "lost", "needs root (for example needrestart -b)"
    if token == "custom":
        return "unknown", "runs your own commands; some may need root (see `centinela --coverage`)"
    return "unknown", token


def report(plan, profile):
    """plan: {name: (module, status)} from modules.plan -> [(name, status, note)] for the checks that run here."""
    rows = []
    for name, (mod, state) in plan.items():
        if state != "run":
            continue
        worst, notes = "ok", []
        for token in getattr(mod, "NEEDS", ()):
            status, note = _token(profile, token)
            if note:
                notes.append(note)
            if RANK[status] > RANK[worst]:
                worst = status
        rows.append((name, worst, "; ".join(notes)))
    return rows


def render_report(rows):
    label = {"ok": "works", "unknown": "unknown", "reduced": "reduced", "lost": "LOST"}
    return "\n".join("  %-9s %-8s %s" % (name, label[status], note) for name, status, note in rows)


def dropin(profile):
    """The systemd drop-in text for a restricted or advanced profile."""
    lines = ["# Written by `centinela setup` (%s install). Remove this file and run `systemctl daemon-reload` to go back to root." % profile.mode,
             "[Service]", "User=%s" % ACCOUNT, "Group=%s" % ACCOUNT,
             "CapabilityBoundingSet=%s" % " ".join(profile.caps), "AmbientCapabilities=%s" % " ".join(profile.caps),
             "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes"]
    if profile.groups:
        lines.append("SupplementaryGroups=%s" % " ".join(profile.groups))
    return "\n".join(lines) + "\n"


def properties(profile):
    """The same settings as systemd-run -p arguments, to try a run exactly as the service would."""
    props = ["User=%s" % ACCOUNT, "Group=%s" % ACCOUNT, "CapabilityBoundingSet=%s" % " ".join(profile.caps),
             "AmbientCapabilities=%s" % " ".join(profile.caps), "NoNewPrivileges=yes", "ProtectSystem=strict",
             "ProtectHome=yes", "PrivateTmp=yes"]
    if profile.groups:
        props.append("SupplementaryGroups=%s" % " ".join(profile.groups))
    return props


def valid_group(name):
    return bool(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name))


def group_exists(name):
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def sh(argv, timeout=120):
    """Run a command for the installer (the only place Centinela itself runs commands that change things)."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


class Installer:
    """Does what the wizard decided. `root` is a prefix for tests; `run` runs a command, `secret` asks hidden."""

    def __init__(self, root="/", run=sh, secret=None, say=print):
        self.root, self.run, self.secret, self.say = root, run, secret, say

    def path(self, p):
        return os.path.join(self.root, p.lstrip("/"))

    def write(self, path, text, mode=0o644):
        target = self.path(path)
        os.makedirs(os.path.dirname(target), mode=0o755 if mode != 0o600 else 0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(target), prefix=".centinela-")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
            os.chmod(tmp, mode)
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def account(self, sysusers_text):
        """Create the `centinela` account when it does not exist yet."""
        rc, _, _ = self.run(["getent", "passwd", ACCOUNT])
        if rc == 0:
            return True
        self.write("/etc/sysusers.d/centinela.conf", sysusers_text)
        rc, _, err = self.run(["systemd-sysusers"])
        if rc != 0:
            self.say("  could not create the account: %s" % err.strip()[:200])
        return rc == 0

    def install_dropins(self, profile):
        for unit in UNITS:
            self.write("/etc/systemd/system/%s.service.d/%s" % (unit, DROPIN_NAME), dropin(profile))
        return self.run(["systemctl", "daemon-reload"])[0] == 0

    def remove_dropins(self):
        removed = False
        for unit in UNITS:
            path = self.path("/etc/systemd/system/%s.service.d/%s" % (unit, DROPIN_NAME))
            if os.path.exists(path):
                os.unlink(path)
                removed = True
        if removed:
            self.run(["systemctl", "daemon-reload"])
        return removed

    def state_dir(self, path):
        """The state directory, owned by the account (a root-owned one would lock the service out of its own state)."""
        return self.run(["install", "-d", "-o", ACCOUNT, "-g", ACCOUNT, "-m", "700", self.path(path)])[0] == 0

    def secrets(self, env_path, names):
        """Ask (hidden) for each missing variable and add it to the secrets file: directory 700, file 600.

        Existing lines are kept as they are. A value is never printed, logged or put in an error message.
        Returns the names that were added."""
        target = self.path(env_path)
        try:
            with open(target) as fh:
                text = fh.read()
        except FileNotFoundError:
            text = ""
        have = {l.split("=", 1)[0].replace("export ", "").strip() for l in text.splitlines()
                if "=" in l and not l.lstrip().startswith("#")}
        added = []
        for name in names:
            if name in have:
                continue
            value = (self.secret("  %s (hidden, Enter to skip): " % name) or "").strip()
            if value:
                text += ("\n" if text and not text.endswith("\n") else "") + "%s=%s\n" % (name, value)
                added.append(name)
        if added:
            self.write(env_path, text, 0o600)
        return added


def limits_table(mods):
    """Markdown table of every check against the three modes, generated from the checks' own NEEDS.
    The README embeds it; a test keeps the two in step."""
    plan = {n: (m, "run") for n, m in sorted(mods.items())}
    profiles = (Profile("restricted"), Profile("advanced", True, ["systemd-journal", "docker"]))
    cols = [{n: (s, note) for n, s, note in report(plan, p)} for p in profiles]
    shown = {"ok": "works", "unknown": "depends", "reduced": "reduced", "lost": "lost"}
    lines = ["| Check | Full | Restricted | Advanced (journal + docker + firewall) | What Restricted loses |", "|---|---|---|---|---|"]
    for name in plan:
        lines.append("| `%s` | works | %s | %s | %s |" % (name, shown[cols[0][name][0]], shown[cols[1][name][0]], cols[0][name][1] or "nothing"))
    return "\n".join(lines)
