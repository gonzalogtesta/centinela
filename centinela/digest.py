"""Pure functions: cap, dedupe, prune and format findings."""
from __future__ import annotations

from .core import CRIT, WARN, Finding

# A weekly timer drifts by minutes; without slack a finding sent last Monday
# would be suppressed this Monday because 6d23h59m < 7d.
TOLERANCE = 12 * 3600


def split_key(key):
    module, rest = key.split(":", 1)
    return module, rest.rsplit(":", 1)[-1]


def sort_findings(findings):
    return sorted(findings, key=lambda f: (f.level != CRIT, f.module, f.id.startswith("more-"), f.id))  # '+N more' last


def kind(finding):
    """'down-redis' -> 'down': the sort of problem, so one noisy kind cannot bury another."""
    return finding.id.split("-", 1)[0].split(":", 1)[0]


def cap_module(findings, limit):
    """Collapse the tail of a noisy module into one '+N more' line, per module and kind of finding."""
    groups = {}
    for f in sort_findings(findings):
        groups.setdefault((f.module, kind(f)), []).append(f)
    out = []
    for (module, k), items in groups.items():
        if len(items) <= limit:
            out.extend(items)
            continue
        keep, rest = items[: limit - 1], items[limit - 1:]
        level = CRIT if any(f.level == CRIT for f in rest) else WARN
        out.extend(keep)
        out.append(Finding(
            module, "more-" + k, level,
            "%s (%s): +%d more findings" % (module, k, len(rest)),
            "centinela --only %s --dry-run --no-dedupe" % module,
        ))
    return sort_findings(out)


def select(findings, sent, now, dedupe_days):
    """Split findings into (to_send, suppressed) using the sent-at map."""
    window = max(0.0, dedupe_days * 86400 - TOLERANCE)
    to_send, suppressed = [], []
    for f in findings:
        last = sent.get(f.key)
        (suppressed if last is not None and now - last < window else to_send).append(f)
    return to_send, suppressed


def prune(sent, current_keys, evaluated, levels, now):
    """Forget resolved findings so a recurrence is reported immediately.

    Only keys whose module actually ran this time, and whose level was in
    scope (a critical-only run must not forget WARN entries), are forgotten.
    """
    from .state import PRUNE_AFTER
    kept = {}
    for key, ts in sent.items():
        module, level = split_key(key)
        resolved = module in evaluated and level in levels and key not in current_keys
        if not resolved and now - ts < PRUNE_AFTER:
            kept[key] = ts
    return kept


def coverage_note(skipped, limit=60):
    """'2 checks could not run: firewall (needs root), docker (permission denied)', or '' when all ran."""
    if not skipped:
        return ""
    parts = []
    for name, reason in skipped:
        reason = " ".join(str(reason).split())
        parts.append("%s (%s)" % (name, reason if len(reason) <= limit else reason[: limit - 3] + "..."))
    return "%d check%s could not run: %s" % (len(skipped), "" if len(skipped) == 1 else "s", ", ".join(parts))


def format_messages(host, findings, limit=3800, note=""):
    """Plain text, one line per finding; split on line boundaries for Telegram."""
    crit = sum(1 for f in findings if f.level == CRIT)
    head = "%s: %d need action" % (host, len(findings))
    if crit:
        head += " (%d critical)" % crit
    messages, cur = [], head
    for f in sort_findings(findings):
        line = f.line()
        if len(line) > limit - 20:
            line = line[: limit - 23] + "..."
        if len(cur) + 1 + len(line) > limit:
            messages.append(cur)
            cur = "%s (cont.)" % host
        cur += "\n" + line
    if note:
        note = note if len(note) <= limit - 20 else note[: limit - 23] + "..."
        if len(cur) + 1 + len(note) > limit:
            messages.append(cur)
            cur = "%s (cont.)" % host
        cur += "\n" + note
    messages.append(cur)
    return messages
