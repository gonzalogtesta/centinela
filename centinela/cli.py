"""Command-line entry point. Exit codes: 0 ok/sent, 1 delivery failed, 2 usage/config."""
from __future__ import annotations

import argparse
import os
import pkgutil
import re
import sys
import time
from contextlib import nullcontext

from . import __version__, digest, heartbeat, identity, modules, notify
from .core import CRIT, WARN, Blocked, Config, Ctx, Finding, Skip
from .state import State, locked

DEFAULT_CONFIG = "/etc/centinela/centinela.toml"
DEFAULT_ENV = "/etc/sec/notify.env"
DEFAULT_STATE = "/var/lib/centinela/state.json"

# `--print NAME` writes a bundled file to stdout so the single-file install needs nothing else.
PRINTABLE = {
    "config": "centinela.toml.example",
    "service": "centinela@.service",
    "failure-service": "centinela-failure@.service",
    "weekly-timer": "centinela-weekly.timer",
    "daily-timer": "centinela-daily.timer",
    "example-check": "tcp_port.py",
    "restricted": "centinela-restricted.conf",
    "restricted-macos": "centinela-restricted.sb",
    "restricted-user": "centinela-restricted.sysusers",
}


def log(msg):
    print("centinela: " + msg, file=sys.stderr)


def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="centinela",
        description="Read-only server health digest; messages Telegram only when something needs action.",
    )
    ap.add_argument("--mode", choices=("weekly", "daily"), default="weekly",
                    help="weekly: all findings; daily: critical only (default: weekly)")
    ap.add_argument("--critical-only", action="store_true", help="same as --mode daily")
    ap.add_argument("--dry-run", action="store_true", help="print the message instead of sending; never writes state")
    ap.add_argument("--no-dedupe", action="store_true", help="ignore the 7-day dedupe (useful with --dry-run)")
    ap.add_argument("--only", help="comma-separated module names to run, ignoring enable/disable")
    ap.add_argument("--list-modules", action="store_true", help="show modules and whether they run on this host")
    ap.add_argument("--test", action="store_true",
                    help="send (or with --dry-run, print) a demo digest to verify Telegram; touches no state")
    ap.add_argument("--status", action="store_true",
                    help="when the daily and weekly runs last completed; exit 1 if one is overdue (changes nothing)")
    ap.add_argument("--failed", metavar="MODE", help="tell the channels that a scheduled run failed (used by "
                    "the systemd OnFailure= unit; at most one message per failure in the dedupe window)")
    ap.add_argument("--version", action="version", version="centinela " + __version__)
    ap.add_argument("--print", dest="print_name", choices=sorted(PRINTABLE),
                    help="write a bundled file (example config, systemd unit/timer, example check) to stdout")
    ap.add_argument("--config", default=os.environ.get("CENTINELA_CONF", DEFAULT_CONFIG))
    ap.add_argument("--env-file", help="notification secrets file (default: [notify] env_file or %s)" % DEFAULT_ENV)
    ap.add_argument("--state", help="state file (default: [general] state_file or %s)" % DEFAULT_STATE)
    return ap.parse_args(argv)


def load_config(path):
    cfg = Config.load(path)
    if not cfg.sources:
        log("no config at %s, using defaults" % path)
    return cfg


def run_modules(plan_, ctx):
    findings, evaluated = [], set()
    for name, (mod, status) in plan_.items():
        if status != "run":
            continue
        try:
            findings.extend(mod.run(ctx))
            evaluated.add(name)
        except Blocked as exc:  # not a quiet skip: a check that cannot run must not look healthy
            log("%s: %s" % (name, exc))
            findings.append(Finding(name, "blocked", WARN, "check '%s' ran a command the safety guard %s; review it, or "
                                    "set [general] allow_dangerous_commands = true" % (name, exc),
                                    "centinela --only %s --dry-run" % name))
        except Skip as exc:
            log("%s skipped: %s" % (name, exc))
        except Exception as exc:  # a crashing check is itself worth knowing about
            log("%s crashed: %r" % (name, exc))
            findings.append(Finding(name, "error", WARN, "check '%s' crashed: %s" % (name, type(exc).__name__),
                                    "centinela --only %s --dry-run" % name))
    return findings, evaluated


def failure_findings(mode):
    """The one finding for a failed scheduled run; the mode comes from a unit name, so it is checked."""
    mode = mode if re.fullmatch(r"[a-z0-9_-]{1,20}", mode) else "unknown"
    return [Finding("centinela", "failed-" + mode, CRIT, "the scheduled %s run of centinela failed; checks did not run" % mode,
                    "journalctl -u centinela@%s -n 40 --no-pager" % mode)]


def demo_findings():
    return [
        Finding("demo", "crit", CRIT, "demo critical finding (test message, nothing is wrong)", "echo critical"),
        Finding("demo", "warn", WARN, "demo warning finding", "echo warning"),
    ]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "setup":
        from . import setup  # the only part that can write, and only its own drop-in file
        return setup.main(argv[1:])
    if argv and argv[0] == "firewall":
        from . import rules  # reads the live ruleset; `approve` saves it next to the state file
        return rules.main(argv[1:])
    if argv and argv[0] == "migrate":
        from . import migrate  # reports; --write adds one drop-in file
        return migrate.main(argv[1:])
    args = parse_args(argv)
    if args.failed and (args.test or args.only):
        log("--failed cannot be combined with --test or --only")
        return 2
    if args.print_name:
        sys.stdout.write(pkgutil.get_data("centinela", "data/" + PRINTABLE[args.print_name]).decode())
        return 0
    critical_only = args.critical_only or args.mode == "daily"
    try:
        cfg = load_config(args.config)
    except Exception as exc:
        log("cannot read config %s: %s" % (args.config, exc))
        return 2
    dedupe_days = cfg.int("general", "dedupe_days", 7)
    max_per_module = cfg.int("general", "max_per_module", 8)
    state_path = args.state or cfg.get("general", "state_file", DEFAULT_STATE)
    channels = cfg.list("notify", "channels", "telegram")
    unknown = [c for c in channels if c not in notify.CHANNELS]
    if unknown or not channels:
        log("unknown [notify] channel %s (use %s)" % (", ".join(map(repr, unknown)) or "(none)", ", ".join(notify.CHANNELS)))
        return 2

    if args.status:
        lines, ok = heartbeat.status_lines(cfg, State.load(state_path).runs, time.time())
        print("\n".join(lines))
        return 0 if ok else 1

    mods = modules.discover(cfg)
    only = set(args.only.split(",")) if args.only else None
    if only and only - set(mods):
        log("unknown module(s): %s" % ", ".join(sorted(only - set(mods))))
        return 2
    plan_ = modules.plan(cfg, mods, only)

    if args.list_modules:
        for name, (mod, status) in plan_.items():
            print("%-10s %-9s %s" % (name, status, getattr(mod, "DESC", "")))
        return 0

    if args.failed:
        findings, evaluated = failure_findings(args.failed), set()
        critical_only = False
    elif args.test:
        findings, evaluated = demo_findings(), set()
    else:
        if os.geteuid() != 0 and sys.platform.startswith("linux"):
            log("not running as root: docker, certbot, ufw and other checks may be skipped or incomplete (use sudo)")
        ctx = Ctx(cfg)
        ctx.state_dir = os.path.dirname(state_path) or "."
        findings, evaluated = run_modules(plan_, ctx)
        if not evaluated:
            log("no check ran on this machine (see --list-modules); silence does not mean healthy")
        evaluated.add("centinela")  # a run that got this far clears an earlier failure notice, so the next one is sent at once

    levels = {CRIT} if critical_only else {CRIT, WARN}
    findings = digest.cap_module([f for f in findings if f.level in levels], max_per_module)

    def deliver(to_send):
        host = identity.describe(cfg, Ctx(cfg).http_get)
        messages = digest.format_messages(host, to_send)
        if args.dry_run:
            print("\n\n".join(messages))
            return
        required = [v for name in channels for v in notify.CHANNELS[name].required]
        notify.load_env_file(args.env_file or cfg.get("notify", "env_file", DEFAULT_ENV), required)
        notify.deliver(channels, messages, cfg)

    run_name = "daily" if critical_only else "weekly"
    checks_ran = len(evaluated - {"centinela"}) > 0  # a run in which nothing could be checked is not proof of health
    env_file = args.env_file or cfg.get("notify", "env_file", DEFAULT_ENV)

    def alive(quiet, mode, ran):
        """After a completed run: the optional "still alive" line, then the outside service's ping."""
        every = cfg.get("heartbeat", "message", "off")
        if quiet and (every == "every" or (every == "weekly" and mode == "weekly")):
            text = heartbeat.alive_text(identity.describe(cfg, Ctx(cfg).http_get), mode, ran)
            if args.dry_run:
                print(text)
            else:
                notify.load_env_file(env_file, [v for name in channels for v in notify.CHANNELS[name].required])
                notify.deliver(channels, [text], cfg)
        if not args.dry_run:
            problem = heartbeat.ping(cfg, identity.describe(cfg), env_file)
            if problem:
                log("warning: %s" % problem)

    def notify_failure():
        """One message per failure: the dedupe state is used when it can be, but a broken state file must not
        be the reason the notice is lost."""
        delivered = False
        try:
            with (nullcontext() if args.dry_run else locked(state_path)):
                state = State.load(state_path)
                now = time.time()
                to_send, _ = (findings, []) if args.no_dedupe else digest.select(findings, state.sent, now, dedupe_days)
                if to_send:
                    deliver(to_send)
                    delivered = True
                    if not args.dry_run:
                        state.sent.update({f.key: now for f in to_send})
                        state.save()
        except (OSError, ValueError) as exc:
            log("state error (%s): %s" % (state_path, exc))
            if not delivered:
                deliver(findings)
        return 0

    try:
        if args.failed:
            return notify_failure()
        if args.test:
            deliver(findings)
            return 0
        # The lock keeps the daily and weekly timers from racing on the state file.
        with (nullcontext() if args.dry_run else locked(state_path)):
            state = State.load(state_path)
            now = time.time()
            findings = findings + heartbeat.stale_findings(cfg, state.runs, now, run_name)
            if args.no_dedupe:
                to_send, suppressed = findings, []
            else:
                to_send, suppressed = digest.select(findings, state.sent, now, dedupe_days)
            if to_send:
                deliver(to_send)
            elif args.dry_run:
                log("nothing to report (%d suppressed by dedupe, %d module(s) evaluated)"
                    % (len(suppressed), len(evaluated)))
            if not args.dry_run:
                state.sent = digest.prune(state.sent, {f.key for f in findings}, evaluated, levels, now)
                state.sent.update({f.key: now for f in to_send})
                if checks_ran:
                    state.runs[run_name] = now
                state.save()
        if checks_ran:
            alive(not to_send, run_name, len(evaluated) - 1)
    except notify.NotifyError as exc:
        log("delivery failed: %s" % exc)
        return 1
    except OSError as exc:
        log("state error (%s): %s" % (state_path, exc))
        return 2
    return 0
