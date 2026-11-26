"""Your own expectations: run a command and say what its result must look like."""
from __future__ import annotations

import re
import shlex

from ..core import CRIT, WARN, Blocked, Finding, Skip

NAME = "expect"
DESC = "commands from [expect.*] must give the output you expect"
FREQUENT = True  # cheap and local: also runs on the frequent timer

MATCHERS = ("line", "equals", "contains", "not_contains", "regex")


def rules(cfg):
    table = cfg.data.get("expect")
    return {k: v for k, v in sorted(table.items()) if isinstance(v, dict)} if isinstance(table, dict) else {}


def applicable(cfg):
    return bool(rules(cfg))


def verdict(rule, out):
    """None when the output is as expected, else why not (a regex that does not compile included)."""
    text = out.strip()
    if "line" in rule and str(rule["line"]).strip() not in [l.strip() for l in text.splitlines()]:
        return "output does not have the line %r" % str(rule["line"])
    if "equals" in rule and text != str(rule["equals"]).strip():
        return "output is not exactly %r" % str(rule["equals"])
    if "contains" in rule and str(rule["contains"]) not in text:
        return "output does not contain %r" % str(rule["contains"])
    if "not_contains" in rule and str(rule["not_contains"]) in text:
        return "output contains %r" % str(rule["not_contains"])
    if "regex" in rule:
        try:
            if not re.search(str(rule["regex"]), text, re.M):
                return "output does not match %r" % str(rule["regex"])
        except re.error:
            return "the regex %r is not valid" % str(rule["regex"])
    return None


def check_rule(ctx, name, rule):
    level = CRIT if str(rule.get("level", "warn")).lower() == "crit" else WARN
    label = str(rule.get("text") or name)

    def finding(why, cmd):
        return [Finding(NAME, name, level, "%s: %s" % (label, why), str(rule.get("fix") or cmd))]

    run = rule.get("run")
    argv = shlex.split(run) if isinstance(run, str) else [str(a) for a in run] if isinstance(run, list) else []
    if not argv:
        return [Finding(NAME, name, WARN, "[expect.%s] needs a 'run' command" % name, "")]
    unknown = [k for k in rule if k not in MATCHERS + ("run", "exit", "level", "text", "fix", "timeout", "allow_dangerous")]
    if unknown:
        return [Finding(NAME, name, WARN, "[expect.%s] unknown setting %s (use %s)"
                        % (name, ", ".join(map(repr, unknown)), ", ".join(MATCHERS)), "")]
    cmd = shlex.join(argv)
    try:
        timeout = int(rule.get("timeout", 30))
        code, out, _ = ctx.run(argv, timeout=timeout, unsafe=rule.get("allow_dangerous") is True)
    except Blocked as exc:
        return [Finding(NAME, name, WARN, "[expect.%s] %s. If you are sure, set allow_dangerous = true on the rule" % (name, exc), "")]
    except Skip:
        return finding("%s did not finish in time" % argv[0], cmd)
    except ValueError:
        return [Finding(NAME, name, WARN, "[expect.%s] timeout must be a number" % name, "")]
    if code == 127:
        return finding("cannot run %s (not installed, or not allowed)" % argv[0], cmd)
    try:
        want_exit = int(rule.get("exit", 0))
    except (TypeError, ValueError):
        return [Finding(NAME, name, WARN, "[expect.%s] exit must be a number" % name, "")]
    if code != want_exit:
        return finding("exit code is %d, expected %d" % (code, want_exit), cmd)
    why = verdict(rule, out)
    return finding(why, cmd) if why else []


def run(ctx):
    findings = []
    for name, rule in rules(ctx.cfg).items():
        findings += check_rule(ctx, name, rule)
    return findings
