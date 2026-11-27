"""`centinela setup`: look around (read-only), let you pick, write one drop-in config file.

This is the only part of the tool that writes anything, and only the drop-in
<config dir>/centinela.d/10-wizard.toml, after showing it and asking. The monitoring
runs never write config.

For each thing found (docker images, running services, listening ports) you choose:
  [x] monitor / trust it     [ ] don't care (allowed, not monitored)     NEW = not seen last time
and per category whether the list is frozen: anything that appears later and is in
neither group is reported.
"""
from __future__ import annotations

import argparse
import datetime
import fnmatch
import getpass
import json
import os
import pkgutil
import re
import shutil
import socket
import subprocess
import sys
import textwrap

from . import identity, install, migrate, modules, notify
from .checks import docker, ports, services
from .core import Config, Ctx

DEFAULT_CONFIG = "/etc/centinela/centinela.toml"
DROPIN = "10-wizard.toml"
RUNNING = ("running", "restarting")

INTRO = """\
centinela setup
-------------------
I will look at this server (read-only) and show what I find: which checks apply, the docker
images that are running, the services that are running and the ports that are listening.
For each list you choose what to monitor and what you do not care about, and whether to
freeze it, so that anything new that appears later is reported as "unexpected".

Nothing is changed on the system. At the end I show the config I would write, and only
after you confirm I write one file: {path}
Your own {main} is never touched; settings in centinela.d/ override it.
"""


def banner_text(color=False, columns=80, utf8=True):
    """The banner: the braille-art sentinel on UTF-8 terminals, a plain ASCII title otherwise.

    Returns "" when the terminal is too narrow for it.
    """
    name = "banner.txt" if utf8 else "banner_ascii.txt"
    art = textwrap.dedent(pkgutil.get_data("centinela", "data/" + name).decode("utf-8")).rstrip("\n").split("\n")
    if max(len(line) for line in art) + 2 > columns:
        return ""
    text = "\n".join(("  " + line) if line else "" for line in art)
    return "\033[32m%s\033[0m" % text if color else text


def fmt(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[]" if not value else "[\n" + "".join("  %s,\n" % fmt(v) for v in value) + "]"
    return json.dumps(value)


def key(name):
    return name if re.fullmatch(r"[A-Za-z0-9_-]+", name) else json.dumps(name)


def dump_toml(data):
    """Sections of flat values; a dict value becomes a sub-table ([docker.images])."""
    lines = []
    for section, table in data.items():
        lines.append("[%s]" % section)
        lines += ["%s = %s" % (key(k), fmt(v)) for k, v in table.items() if not isinstance(v, dict)]
        lines.append("")
        for k, sub in table.items():
            if isinstance(sub, dict) and sub:
                lines.append("[%s.%s]" % (section, key(k)))
                lines += ["%s = %s" % (key(sk), fmt(sv)) for sk, sv in sub.items()]
                lines.append("")
    return "\n".join(lines)


def matches(patterns, name):
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


class Wizard:
    def __init__(self, ctx, ask=input, say=print, assume_yes=False, banner=""):
        self.ctx, self.cfg = ctx, ctx.cfg
        self._ask, self.say, self.assume_yes, self.banner = ask, say, assume_yes, banner
        self.out = {}
        self.required = []  # services 1.0 silently required and the user chose to keep

    # --- prompts -------------------------------------------------------
    def ask(self, prompt, default=""):
        if self.assume_yes:
            return default
        try:
            return self._ask(prompt).strip() or default
        except EOFError:
            return default

    def confirm(self, prompt, default):
        answer = self.ask("%s [%s] " % (prompt, "Y/n" if default else "y/N")).lower()
        return default if not answer else answer in ("y", "yes")

    def pick(self, items, checked):
        """items: [(key, label, is_new)]. Toggle by number until Enter."""
        checked = set(checked)
        while True:
            for n, (ident, label, new) in enumerate(items, 1):
                self.say("  %3d [%s] %s%s" % (n, "x" if ident in checked else " ", label, "   <- NEW" if new else ""))
            answer = self.ask("Toggle numbers (e.g. 2 5-7), a = all, n = none, Enter = continue: ").lower()
            if not answer:
                return checked
            if answer in ("a", "n"):
                checked = {k for k, _, _ in items} if answer == "a" else set()
                continue
            for part in answer.replace(",", " ").split():
                lo, _, hi = part.partition("-")
                if lo.isdigit() and (not hi or hi.isdigit()):
                    for n in range(int(lo), int(hi or lo) + 1):
                        if 1 <= n <= len(items):
                            checked ^= {items[n - 1][0]}
                else:
                    self.say("  (ignoring %r)" % part)

    def review(self, rows, prior_monitor, prior_ignore, first):
        """rows: {key: label}. Returns (monitored, ignored, kept_ignored) sorted lists.

        Entries from the previous setup that no longer exist show as '(not present now)':
        keep them ticked or untick to drop them. Old 'ignored' leftovers are carried over.
        """
        stale = sorted(k for k in prior_monitor if k not in rows)
        items, checked = [], set()
        for key in sorted(rows):
            new = not first and key not in prior_monitor and key not in prior_ignore
            items.append((key, rows[key], new))
            if first or key in prior_monitor or new:
                checked.add(key)
        for key in stale:
            items.append((key, "%s   (not present now)" % key, False))
            checked.add(key)
        if not items:
            return [], [], sorted(prior_ignore)
        checked = self.pick(items, checked)
        monitored = sorted(checked)
        ignored = sorted(k for k in rows if k not in checked)
        carried = sorted(k for k in prior_ignore if k not in rows and k not in ignored)
        return monitored, ignored, carried

    def freeze_question(self, what, default):
        return self.confirm("Freeze this list? Report anything new that shows up later (%s)" % what, default)

    # --- steps ---------------------------------------------------------
    def step_migrate(self):
        """An existing config may have relied on what 1.0 did silently: say so before asking anything."""
        if not self.cfg.sources:
            return
        analysis = migrate.Analysis(self.cfg)
        lines = analysis.lines()
        if not lines:
            return
        self.say("\n== 0. What changed since 1.0 ==\nYour config predates 1.1 and relied on these defaults:")
        for line in lines:
            self.say("  - " + textwrap.fill(line, 96, subsequent_indent="    "))
        self.say("  (full report: centinela migrate)")
        for unit in analysis.pins.get("required", []):
            rc, _, _ = self.ctx.run(["systemctl", "is-active", unit])
            if self.confirm("1.0 treated %s as REQUIRED (a critical finding whenever it is not running). Keep that?" % unit,
                            rc == 0):
                self.required.append(unit)
        if analysis.pins.get("watch"):
            self.say("  Step 5 lists the running services; the ones 1.0 watched for you are ticked when they run.")

    def step_modules(self):
        self.say("\n== 1. Checks ==\nThese checks apply to this server. Untick the ones you do not want.")
        plan = modules.plan(self.cfg, modules.discover(self.cfg))
        shown = [(n, "%-9s %s" % (n, getattr(m, "DESC", ""))) for n, (m, status) in plan.items() if status != "n/a"]
        skipped = [n for n, (_, status) in plan.items() if status == "n/a" and n != "ports"]  # ports: set up in step 6
        if skipped:
            self.say("  Not applicable here, skipped automatically: %s" % ", ".join(skipped))
        prior_off = set(self.cfg.list("general", "disable"))
        names = [n for n, _ in shown]
        checked = self.pick([(n, label, False) for n, label in shown], {n for n in names if n not in prior_off})
        self.out.setdefault("general", {})["disable"] = sorted({n for n in names if n not in checked} | (prior_off - set(names)))

    def step_identity(self):
        self.say("\n== 2. Naming this server ==\nThe first line of every message says which server it is.")
        current = self.cfg.get("general", "host_name") or socket.gethostname()
        name = self.ask("Name for this server [%s]: " % current, current)
        if name != socket.gethostname() or self.cfg.has("general", "host_name"):
            self.out.setdefault("general", {})["host_name"] = name
        prior = set(self.cfg.list("notify", "show", "host"))
        items = [("ip", "local IP address (%s)" % (identity.local_ip() or "unknown"), False),
                 ("public_ip", "public IP address (asks api.ipify.org on every message)", False),
                 ("os", "OS version (%s)" % (identity.os_name() or "unknown"), False)]
        self.say("  Also show in the message header:")
        chosen = self.pick(items, {k for k, _, _ in items if k in prior})
        self.out.setdefault("notify", {})["show"] = ["host"] + [k for k, _, _ in items if k in chosen]

    def step_telegram(self):
        self.say("\n== 3. Notifications ==")
        path = self.cfg.get("notify", "env_file", "/etc/sec/notify.env")
        available = notify.channels(self.cfg)
        channels = [c for c in self.cfg.list("notify", "channels", "telegram") if c in available]
        keys = set()
        try:
            with open(path) as fh:
                keys = {l.split("=", 1)[0].replace("export ", "").strip() for l in fh if "=" in l and not l.lstrip().startswith("#")}
            state = "found"
        except FileNotFoundError:
            state = "missing"
        except PermissionError:
            state = "not readable (run setup with sudo to check it)"
        self.say("  Channels: %s (set [notify] channels to change; available: %s)"
                 % (", ".join(channels) or "none", ", ".join(available)))
        self.say("  Secrets file %s: %s" % (path, state))
        needed = notify.required(available, channels)
        if state == "found":
            for key in needed:
                self.say("    %-19s %s" % (key, "set" if key in keys else "MISSING"))
        if needed and (state == "missing" or (state == "found" and not set(needed) <= keys)):
            self.say("  Create it (directory 700, file 600, root) with %s lines.\n"
                     "  I never ask for or write secrets. Then check with: sudo centinela --test"
                     % " and ".join(v + "=" for v in needed))

    def step_docker(self):
        rc, out, _ = self.ctx.run(["docker", "ps", "--format", docker.PS_FORMAT])
        if rc != 0:
            return
        images = sorted({c.image for c in docker.parse_ps(out) if c.state in RUNNING and not c.image.startswith("sha256:")})
        self.say("\n== 4. Docker images ==\n"
                 "Running containers use these images. [x] = trusted and monitored (checked for updates).\n"
                 "[ ] = you do not care (allowed, never reported). With the list frozen, a container from\n"
                 "any other image is reported as CRITICAL.")
        table_prior = docker.image_rules(self.cfg)
        trusted = self.cfg.list("docker", "trusted_images") + ["%s:%s" % (repo, r) for repo, rs in table_prior.items() for r in rs]
        ignored = self.cfg.list("docker", "ignore_images")
        first = not trusted and not ignored and not self.cfg.has("docker", "ignore_images")
        wild = self.confirm("Use * for version numbers, e.g. redis:7.4 -> redis:7.* (good for images that rotate)?", True)

        def pattern(image):
            for p in trusted + ignored:  # keep what you wrote by hand
                if any(fnmatch.fnmatchcase(f, p) for f in docker.image_forms(image)):
                    return p
            return docker.generalize(image) if wild else image.split("@", 1)[0]

        rows, running = {}, {}
        for image in images:
            p = pattern(image)
            rows[p] = rows.get(p, "%-28s covers:" % p) + " " + image
            repo, tag = docker.split_image(image)
            running.setdefault(repo, []).append(tag)
        mon, ign, carried = self.review(rows, set(trusted), set(ignored), first)

        table, leftover = {}, []
        for pat in mon:  # "repo:rule" becomes a [docker.images] entry; anything else stays a plain glob
            repo, sep, rule = pat.rpartition(":")
            if sep and "/" not in rule and not any(ch in repo for ch in "*?["):
                table.setdefault(docker.norm_repo(repo), []).append(rule)
            else:
                leftover.append(pat)
        if table:
            self.edit_rules(table, running)
        freeze = self.freeze_question("unexpected image", self.cfg.bool("docker", "freeze_images", True))
        self.out["docker"] = {"trusted_images": leftover, "ignore_images": sorted(set(ign) | set(carried)),
                              "freeze_images": freeze,
                              "images": {r: (v[0] if len(v) == 1 else v) for r, v in sorted(table.items())}}

    def edit_rules(self, table, running):
        """Show the allowed tags per image and let the user change them: redis=7.4, myapp=1.*, redis=fixed."""
        self.say("  Allowed versions per image. An exact tag is FIXED (no newer-version warnings); * and ? match ranges.")
        for repo in sorted(table):
            self.say("    %-28s %-14s running: %s" % (repo, ", ".join(table[repo]), ", ".join(sorted(running.get(repo, []))) or "-"))
        self.say("  Examples:  redis=7.4   myapp=1.*   worker=*   redis=fixed  (fixed = the version running now)")
        answer = self.ask("Change a rule? name=rule, several separated by spaces (Enter = keep): ")
        for part in answer.split():
            name, _, rule = part.partition("=")
            hits = [r for r in table if r == docker.norm_repo(name) or r.endswith("/" + docker.norm_repo(name))]
            if len(hits) != 1 or not rule:
                self.say("  (ignoring %r: %s)" % (part, "no rule given" if not rule else "unknown or ambiguous image name"))
                continue
            repo = hits[0]
            if rule == "fixed":
                tags = sorted(set(running.get(repo, [])))
                if not tags:
                    self.say("  (cannot fix %s: nothing of it is running right now)" % repo)
                    continue
                table[repo] = tags
            else:
                table[repo] = [r for r in rule.split(",") if r]

    def step_services(self):
        rc, out, _ = self.ctx.run(["systemctl", "list-units", "--type=service", "--state=running",
                                   "--no-legend", "--plain", "--no-pager"])
        if rc != 0:
            return
        units = sorted(set(services.parse_running(out)))
        rows, instances = {}, set()
        for unit in units:
            if "@" in unit:  # getty@tty1.service -> getty@*.service
                instances.add(unit.split("@")[0] + "@*.service")
            else:
                rows[unit] = unit
        self.say("\n== 5. Running services ==\n"
                 "[x] = must stay running (reported if it stops). [ ] = you do not care. With the list frozen,\n"
                 "a service that starts running and is in neither group is reported.")
        if instances:
            self.say("  Instances are never monitored one by one and are allowed: %s" % ", ".join(sorted(instances)))
        watch = [services.unit_name(n) for n in self.cfg.list("services", "watch")]
        known = [services.unit_name(n) for n in self.cfg.list("services", "known")]
        first = not self.cfg.has("services", "known")
        mon, ign, carried = self.review(rows, set(watch), {k for k in known if "@" not in k}, first)
        freeze = self.freeze_question("unexpected service", self.cfg.bool("services", "freeze", False))
        self.out["services"] = {"watch": mon, "known": sorted(set(ign) | set(carried) | instances), "freeze": freeze}
        if self.required:
            self.out["services"]["required"] = list(self.required)

    def step_ports(self):
        try:
            listeners = ports.listing(self.ctx)
        except Exception:
            return
        rows = {ports.entry(l): "%-18s %-14s %s" % (ports.entry(l), "loopback only" if l.scope == "local" else "all interfaces",
                                                  l.process or "") for l in listeners}
        self.say("\n== 6. Listening ports ==\n"
                 "[x] = expected: must keep listening, and must not become more exposed than shown.\n"
                 "[ ] = you do not care. With the list frozen, a new listener is reported (CRITICAL if it\n"
                 "is open on all interfaces).")
        expected, known = self.cfg.list("ports", "expected"), self.cfg.list("ports", "known")
        first = not self.cfg.has("ports", "expected") and not self.cfg.has("ports", "known")
        mon, ign, carried = self.review(rows, set(expected), set(known), first)
        freeze = self.freeze_question("unexpected listener", self.cfg.bool("ports", "freeze", True))
        self.out["ports"] = {"expected": mon, "known": sorted(set(ign) | set(carried)), "freeze": freeze}

    # --- install modes -------------------------------------------------
    MODE_TEXT = (
        ("full", "Full        runs as root inside the bundled read-only sandbox. Every check works."),
        ("restricted", "Restricted  its own account `centinela` with one capability (read any file, write none)."),
        ("advanced", "Advanced    restricted, plus groups you choose (journal, adm, docker...) and, if you want, firewall access."),
    )

    def choose_profile(self, current):
        self.say("\n== 7. How much power should Centinela have? ==")
        for _, line in self.MODE_TEXT:
            self.say("  " + line)
        default = {"full": "1", "restricted": "2", "advanced": "3"}[current]
        answer = self.ask("Mode [1-3, Enter = %s]: " % default, default)
        mode = {"1": "full", "2": "restricted", "3": "advanced"}.get(answer, current)
        net_admin, groups = False, []
        if mode != "full":
            net_admin = self.confirm("Let it read the firewall rules in force (CAP_NET_ADMIN)? The account could then also "
                                     "change rules, so the answer is no unless you want the firewall check to see them", False)
        if mode == "advanced":
            offered = [g for g in install.GROUPS if install.group_exists(g)]
            items = [(g, "%-16s %s" % (g, install.GROUPS[g]), False) for g in offered]
            if items:
                self.say("  Groups to add to the account. Each one widens what it can see:")
                groups = sorted(self.pick(items, set()))
            for custom in self.ask("Any other group? names separated by spaces (Enter = none): ").split():
                if install.valid_group(custom) and install.group_exists(custom):
                    groups.append(custom)
                else:
                    self.say("  (ignoring %r: no such group)" % custom)
            if "docker" in groups and self.ask("The docker group is root-equivalent on this host. Type YES to keep it: ") != "YES":
                groups.remove("docker")
                self.say("  docker group not added.")
        return install.Profile(mode, net_admin, groups)

    def step_install(self, config_path, installer=None, run=install.sh, exe=None):
        """Choose the mode, show what it costs, install it, add the secrets, try it, offer the timers."""
        installer = installer or install.Installer(run=run, secret=getpass.getpass, say=self.say)
        if not sys.platform.startswith("linux") or not os.path.isdir(installer.path("/run/systemd/system")):
            self.say("\nInstall modes need Linux with systemd (this is %s). Nothing was installed; see the README, "
                     "\"Restricted install\", for this platform." % sys.platform)
            return
        if os.geteuid() != 0 and installer.root == "/":
            self.say("\nRun `sudo centinela setup` to also choose how much power Centinela has and install it.")
            return
        exe = exe or shutil.which("centinela") or os.path.abspath(sys.argv[0])
        current = ("advanced" if "SupplementaryGroups" in self.read(installer, "centinela@") else "restricted") \
            if self.read(installer, "centinela@") else "full"
        profile = self.choose_profile(current)
        plan = modules.plan(self.cfg, modules.discover(self.cfg))
        self.say("\nWhat it means for the checks that apply here:\n" + install.render_report(install.report(plan, profile)))
        if profile.mode == "full":
            if current != "full" and self.confirm("Remove the restricted drop-ins so it runs as root again?", True):
                installer.remove_dropins()
                self.say("  Removed. It runs as root, sandboxed.")
        else:
            self.say("\nThis writes %s for the services %s and creates the account `%s` if it is missing."
                     % (install.DROPIN_NAME, ", ".join(u + ".service" for u in install.UNITS), install.ACCOUNT))
            if not self.confirm("Install it?", True):
                return
            sysusers = pkgutil.get_data("centinela", "data/centinela-restricted.sysusers").decode()
            if not installer.account(sysusers) or not installer.install_dropins(profile):
                self.say("  Could not finish the install; nothing else was changed. See above.")
                return
            installer.state_dir(os.path.dirname(self.cfg.get("general", "state_file", "/var/lib/centinela/state.json")))
        self.step_secrets(installer)
        self.step_verify(profile, config_path, exe, run)
        self.step_firewall_approve(profile, plan, config_path, exe, run)
        self.step_timers(run)

    def read(self, installer, unit):
        try:
            with open(installer.path("/etc/systemd/system/%s.service.d/%s" % (unit, install.DROPIN_NAME))) as fh:
                return fh.read()
        except OSError:
            return ""

    def step_secrets(self, installer):
        path = self.cfg.get("notify", "env_file", "/etc/sec/notify.env")
        available = notify.channels(self.cfg)
        names = notify.required(available, [c for c in self.cfg.list("notify", "channels", "telegram") if c in available])
        if self.assume_yes or not names:
            return
        if self.confirm("\nEnter the notification secrets now? They are typed hidden and stored only in %s "
                        "(root, mode 600)" % path, True):
            added = installer.secrets(path, names)
            self.say("  Added: %s" % (", ".join(added) if added else "nothing (already there, or skipped)"))

    def verify_command(self, profile, config_path, exe):
        base = [exe, "--coverage", "--config", config_path]
        if profile.root:
            return base
        wrapper = ["systemd-run", "--collect", "--wait", "--pipe", "--quiet"]
        for prop in install.properties(profile):
            wrapper += ["-p", prop]
        return wrapper + ["-p", "StateDirectory=centinela"] + ["--"] + base

    def step_verify(self, profile, config_path, exe, run):
        self.say("\n== Trying it ==\nRunning every check once as the service would run, to see which can do their work:")
        rc, out, err = run(self.verify_command(profile, config_path, exe), 300)
        self.say(out.rstrip() or ("  (no output: %s)" % " ".join(err.split())[:200]))
        if rc != 0:
            self.say("  Some checks could not run. That is what the digest's last line will say too; add what they need "
                     "(re-run setup in Advanced mode) or turn them off.")
        if self.confirm("Send a test message to every channel now?", True):
            rc, out, err = run([exe, "--test", "--config", config_path], 120)
            self.say("  Sent." if rc == 0 else "  Not sent: %s" % " ".join((err or out).split())[-300:])

    def step_firewall_approve(self, profile, plan, config_path, exe, run):
        if plan.get("firewall", (None, "n/a"))[1] != "run" or not (profile.root or profile.net_admin):
            return
        if self.confirm("\nApprove the firewall rules in force now, so a change is reported later? Review them first "
                        "with `centinela firewall show`", False):
            rc, out, err = run([exe, "firewall", "approve", "--config", config_path], 60)
            self.say("  " + " ".join((out if rc == 0 else err or out).split()))

    def step_timers(self, run):
        if self.confirm("\nStart the daily and weekly timers now?", True):
            rc, _, err = run(["systemctl", "enable", "--now", "centinela-daily.timer", "centinela-weekly.timer"], 60)
            self.say("  Timers enabled." if rc == 0 else "  Could not enable them: %s" % " ".join(err.split())[:200])
            if rc == 0 and self.confirm("Also the optional frequent timer (critical problems within about 15 minutes)?", False):
                run(["systemctl", "enable", "--now", "centinela-frequent.timer"], 60)

    # --- output --------------------------------------------------------
    def render(self):
        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        header = ("# Generated by `centinela setup` on %s. Re-run setup to change it; hand edits here are\n"
                  "# overwritten. Put your own overrides in centinela.toml or a later file such as centinela.d/20-local.toml.\n\n" % stamp)
        return header + dump_toml(self.out)

    def run(self):
        if self.banner:
            self.say(self.banner + "\n")
        self.say(INTRO.format(path="centinela.d/" + DROPIN, main="centinela.toml"))
        for step in (self.step_migrate, self.step_modules, self.step_identity, self.step_telegram, self.step_docker,
                     self.step_services, self.step_ports):
            step()
        return self.render()


def main(argv, ask=input, say=print):
    ap = argparse.ArgumentParser(prog="centinela setup", description="Interactive setup wizard.")
    ap.add_argument("--config", default=os.environ.get("CENTINELA_CONF", DEFAULT_CONFIG))
    ap.add_argument("--output", help="file to write (default: centinela.d/%s next to --config)" % DROPIN)
    ap.add_argument("--dry-run", action="store_true", help="show the generated config, write nothing")
    ap.add_argument("--no-banner", action="store_true", help="do not print the ASCII-art banner")
    ap.add_argument("--yes", action="store_true", help="no questions: accept the defaults (everything found, lists as suggested)")
    args = ap.parse_args(argv)
    try:
        cfg = Config.load(args.config)
    except (ValueError, OSError) as exc:
        print("centinela: cannot read config: %s" % exc, file=sys.stderr)
        return 2
    target = args.output or os.path.join(os.path.dirname(os.path.abspath(args.config)), "centinela.d", DROPIN)
    interactive = sys.stdout.isatty() and not args.yes and not args.no_banner
    color = interactive and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
    utf8 = "utf" in (getattr(sys.stdout, "encoding", None) or "").lower()
    banner = banner_text(color, shutil.get_terminal_size((80, 24)).columns, utf8) if interactive else ""
    wizard = Wizard(Ctx(cfg), ask, say, args.yes, banner)
    text = wizard.run()
    say("\n== Result ==\n%s" % text)
    if args.dry_run:
        say("(dry run: nothing written)")
        return 0
    if not wizard.confirm("Write this to %s?" % target, True):
        say("Nothing written.")
        return 0
    try:
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        tmp = target + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except PermissionError:
        print("centinela: cannot write %s; run it with sudo" % target, file=sys.stderr)
        return 2
    say("Written: %s" % target)
    if args.output:  # writing somewhere else: not a real install, so nothing outside that file is touched
        return 0
    if args.yes:
        say("Next:\n  centinela --dry-run          see what would be sent now\n"
            "  sudo centinela setup         to choose how much power it has, add the secrets and start the timers")
        return 0
    wizard.step_install(args.config)
    return 0
