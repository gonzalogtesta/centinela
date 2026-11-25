"""Proof of life: has Centinela itself been running, and can an outside service tell when it stops?

Three small things, all optional except the first:
  - every completed run is recorded in the state file, and each run checks that the *other* schedule
    (daily / weekly) is still completing, so a disabled timer is reported instead of looking like health;
  - `centinela --status` prints those times and exits 1 when one is overdue, for any external probe;
  - HEARTBEAT_URL (in the secrets file) is pinged after every completed run, for a dead-man's-switch
    service that alerts when the pings stop; [heartbeat] message sends a "still alive" line to your channels.
"""
from __future__ import annotations

import os
import time

from . import notify
from .core import CRIT, Finding

MODES = ("daily", "weekly")
SLACK = {"daily": ("stale_daily_hours", 48, 3600), "weekly": ("stale_weekly_days", 10, 86400)}


def limit(cfg, mode):
    key, default, unit = SLACK[mode]
    return max(1, cfg.int("heartbeat", key, default)) * unit


def watched(cfg):
    return [m for m in cfg.list("heartbeat", "watch", list(MODES)) if m in MODES]


def ago(seconds):
    if seconds < 7200:
        return "%d min ago" % max(1, seconds // 60)
    if seconds < 2 * 86400:
        return "%d h ago" % (seconds // 3600)
    return "%d days ago" % (seconds // 86400)


def overdue(cfg, runs, now, modes=None):
    """{mode: seconds since its last completed run} for watched modes that ran before and are now late.
    A mode that never ran is not late: nothing says it was ever meant to."""
    late = {}
    for mode in modes if modes is not None else watched(cfg):
        last = runs.get(mode)
        if last is not None and now - last > limit(cfg, mode):
            late[mode] = int(now - last)
    return late


def stale_findings(cfg, runs, now, this_mode):
    """Late runs of the other schedule: the daily run notices a dead weekly timer and the other way round."""
    others = [m for m in watched(cfg) if m != this_mode]
    return [Finding("centinela", "stale-" + mode, CRIT,
                    "the %s run of centinela last completed %s; its timer may be off" % (mode, ago(secs)),
                    "systemctl list-timers 'centinela*' --all")
            for mode, secs in sorted(overdue(cfg, runs, now, others).items())]


def status_lines(cfg, runs, now):
    """-> (lines, ok) for `centinela --status`."""
    lines, ok = [], True
    for mode in MODES:
        last = runs.get(mode)
        if last is None:
            lines.append("%-7s never completed on this machine" % mode)
            continue
        late = mode in overdue(cfg, runs, now)
        ok = ok and not late
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(last))
        lines.append("%-7s last completed %s (%s)%s" % (mode, stamp, ago(int(now - last)), "  OVERDUE" if late else ""))
    return lines, ok


def ping(cfg, host, env_file):
    """Tell the dead-man's-switch URL that a run completed. Best effort: returns an error text, or "" if fine
    or not configured. The URL is a secret (it carries the token), so it only comes from the environment."""
    try:
        notify.load_env_file(env_file, ("HEARTBEAT_URL",))
        url = os.environ.get("HEARTBEAT_URL", "")
        if not url:
            return ""
        notify._post("heartbeat", notify._secure_url("heartbeat", url), ("%s: centinela ok" % host).encode(),
                     {"Content-Type": "text/plain; charset=utf-8"}, attempts=2)
    except notify.NotifyError as exc:
        return str(exc)
    return ""


def alive_text(host, mode, evaluated):
    return "%s: centinela is alive (%s run completed, %d check(s) ran, nothing needs action)" % (host, mode, evaluated)
