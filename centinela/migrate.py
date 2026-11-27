"""`centinela migrate`: what changed since 1.0 that an existing config may have relied on.

Reports by default and writes nothing. With --write it adds one drop-in file next to the
config (centinela.d/05-keep-1.0-services.toml) that pins the old service defaults; the main
config file is never touched, and an existing drop-in is never overwritten.
"""
from __future__ import annotations

import argparse
import ast
import glob
import json
import os
import sys

from . import safety
from .core import Config

# What 1.0 assumed when these keys were missing from the config.
OLD_SERVICE_DEFAULTS = {"required": ["fail2ban"], "watch": ["nginx", "docker", "ssh"]}
DROPIN = "05-keep-1.0-services.toml"
NAMES_DROPIN = "06-module-names.toml"

# 1.1 split two checks in two; a config that names the old one now means both halves.
RENAMED = {"firewall": ("ufw", "fwrules"), "docker": ("docker", "docker-images")}


def services_module_enabled(cfg):
    if "services" in cfg.list("general", "disable"):
        return False
    enable = cfg.list("general", "enable", "auto")
    return enable == ["auto"] or "services" in enable


def old_service_defaults_in_use(cfg):
    """The service settings 1.0 filled in silently because the config did not give them."""
    if not services_module_enabled(cfg):
        return {}
    return {key: value for key, value in OLD_SERVICE_DEFAULTS.items() if not cfg.has("services", key)}


def literal_argv(node):
    """The string items at the start of a command list written in the source, e.g. ["rm", "-rf", x] -> ["rm", "-rf"]."""
    while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        node = node.left
    if not isinstance(node, (ast.List, ast.Tuple)):
        return None
    argv = []
    for item in node.elts:
        if not (isinstance(item, ast.Constant) and isinstance(item.value, str)):
            break
        argv.append(item.value)
    return argv or None


def scan_checks(directory):
    """-> (refused, unchecked): commands in your own checks that the safety guard would refuse, and how many
    ctx.run calls could not be read from the source (built at run time). subprocess calls are not looked at."""
    refused, unchecked = [], 0
    for path in sorted(glob.glob(os.path.join(directory, "*.py"))):
        try:
            with open(path) as fh:
                tree = ast.parse(fh.read(), path)
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run" and node.args):
                continue
            argv = literal_argv(node.args[0])
            if argv is None:
                unchecked += 1
                continue
            try:
                safety.verify(argv)
            except safety.Unsafe as exc:
                refused.append((os.path.basename(path), node.lineno, " ".join(argv), str(exc)))
    return refused, unchecked


def is_old(name, mods=None):
    """An old check name, unless a check of that name exists (your own `firewall` drop-in)."""
    return name in RENAMED and name not in (set(mods or ()) - {"docker"})


def translate(names, mods=None):
    """A list of check names with each old name replaced by the checks it became (order kept, no repeats)."""
    out = []
    for name in names:
        for new in (RENAMED[name] if is_old(name, mods) else (name,)):
            if new not in out:
                out.append(new)
    return out


def translate_routes(table, mods=None):
    """Route table plus the routes the new names need ("firewall:crit" -> "ufw:crit" and "fwrules:crit").
    An entry you already wrote for a new name is kept as it is. Old keys stay (harmless, nothing asks for them)."""
    out = dict(table)
    for key, value in table.items():
        base, _, level = str(key).partition(":")
        if is_old(base, mods):
            for target in RENAMED[base]:
                out.setdefault(target + (":" + level if level else ""), value)
    return out


def renames(cfg, mods=None):
    """-> {"enable": [...], "disable": [...], "routes": {...}} holding only what must change to say the same
    thing with the 1.1 names. `mods` (the modules found) keeps your own check called `firewall` out of it."""
    out = {}
    for key in ("enable", "disable"):
        names = cfg.list("general", key, "auto" if key == "enable" else "")
        fixed = translate(names, mods)
        if fixed != list(names):
            out[key] = fixed
    table = {str(k): v for k, v in cfg.table("notify", "routes").items()}
    added = {k: v for k, v in translate_routes(table, mods).items() if k not in table}
    if added:
        out["routes"] = added
    return out


def renamed_lines(found):
    """One sentence per kind of rename, for the wizard and for the finding."""
    out = []
    for key in ("enable", "disable"):
        if key in found:
            out.append("[general] %s names a check that 1.1 split in two (%s); it should read %s."
                       % (key, ", ".join("%s = %s" % (o, " + ".join(n)) for o, n in RENAMED.items()), json.dumps(found[key])))
    if "routes" in found:
        out.append("[notify.routes] has routes for %s; 1.1 needs one per new check (%s)."
                   % ("firewall or docker", ", ".join(found["routes"])))
    return out


def names_dropin_text(found):
    lines = ["# Written by `centinela migrate`: the 1.1 names of the checks your config already mentioned.",
             "# `firewall` is now ufw + fwrules, and `docker` also has docker-images."]
    if "enable" in found or "disable" in found:
        lines.append("[general]")
        lines += ["%s = %s" % (key, json.dumps(found[key])) for key in ("enable", "disable") if key in found]
    if "routes" in found:
        lines.append("[notify.routes]")
        lines += ["%s = %s" % (json.dumps(key), json.dumps(value)) for key, value in sorted(found["routes"].items())]
    return "\n".join(lines) + "\n"


def stale_findings(cfg, mods):
    """A warning when the config still uses an old name: it silently stopped meaning what it said."""
    from .core import WARN, Finding
    found = renames(cfg, mods)
    if not found:
        return []
    return [Finding("centinela", "config-names", WARN, " ".join(renamed_lines(found)),
                    "centinela migrate --write   # then: centinela --list-modules")]


class Analysis:
    """What a 1.0 config relied on that 1.1 changed."""

    def __init__(self, cfg):
        self.pins = old_service_defaults_in_use(cfg)
        self.refused, self.unchecked = scan_checks(cfg.get("general", "extra_dir", "/etc/centinela/checks.d"))
        self.disk = "disk" not in cfg.list("general", "disable")
        self.renames = renames(cfg)

    def lines(self):
        """Short wording for the setup wizard."""
        out = []
        if self.pins:
            out.append("Services: 1.0 used %s without your config saying so; 1.1 does not." % ", ".join(
                "%s = %s" % (k, json.dumps(v)) for k, v in self.pins.items()))
        for name, line, command, why in self.refused:
            out.append("Your check %s:%d runs `%s`, which the safety guard now refuses (%s)." % (name, line, command, why))
        if self.unchecked:
            out.append("%d command(s) in your own checks are built at run time; a refused one is reported when the check runs."
                       % self.unchecked)
        out += renamed_lines(self.renames)
        if self.disk:
            out.append("Disk: a warning now also needs 20 GB or less free (10 GB for critical); 1.0 alerted on the percentage alone.")
        return out


def dropin_text(pins):
    lines = ["# Written by `centinela migrate`: the service settings 1.0 used when your config did not give them.",
             "# Edit or delete this file once you have chosen your own services (`centinela setup`).", "[services]"]
    lines += ["%s = %s" % (key, json.dumps(value)) for key, value in sorted(pins.items())]
    return "\n".join(lines) + "\n"


def main(argv):
    ap = argparse.ArgumentParser(prog="centinela migrate", description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=os.environ.get("CENTINELA_CONF", "/etc/centinela/centinela.toml"))
    ap.add_argument("--write", action="store_true",
                    help="write the drop-ins that keep the 1.0 service defaults and use the 1.1 check names (otherwise only report)")
    args = ap.parse_args(argv)
    try:
        cfg = Config.load(args.config)
    except ValueError as exc:
        print("centinela: cannot read config: %s" % exc, file=sys.stderr)
        return 2
    print("Config: %s%s" % (args.config, "" if cfg.sources else " (not found: built-in defaults)"))

    analysis = Analysis(cfg)
    pins = analysis.pins
    print("\n1. Services are now off until you list them")
    if pins:
        print("   1.0 filled these in for you, and 1.1 no longer does:")
        for key, value in pins.items():
            print("     [services] %s = %s" % (key, json.dumps(value)))
        print("   Choose your own with `sudo centinela setup` (recommended), or keep exactly the old behaviour\n"
              "   with `sudo centinela migrate --write`.")
    else:
        print("   Nothing to do: your config already names its services (or the module is disabled).")

    refused, unchecked = analysis.refused, analysis.unchecked
    print("\n2. Your own checks and the safety guard")
    if refused:
        print("   These commands would now be refused, and the check would report a warning:")
        for name, line, command, why in refused:
            print("     %s:%d  %s  (%s)" % (name, line, command, why))
        print("   Change the check, or set [general] allow_dangerous_commands = true if you have reviewed them.")
    else:
        print("   No refused command found in the checks that could be read.")
    if unchecked:
        print("   %d ctx.run call(s) build their command at run time and could not be checked; a refused one is reported "
              "when the check runs." % unchecked)

    if analysis.disk:
        print("\n3. Disk alerts also need little free space")
        print("   1.0 reported any disk at 80% (warning) or 90% (critical). 1.1 also needs 20 GB or less (warning) or\n"
              "   10 GB or less (critical) to be free. To keep the old behaviour:  [disk] warn_free_gb = 0, crit_free_gb = 0")

    print("\n4. Two checks were split in two")
    if analysis.renames:
        for line in renamed_lines(analysis.renames):
            print("   " + line)
    else:
        print("   Nothing to do: your config does not name `firewall` or `docker` in enable, disable or routes.")
    print("   firewall = ufw (is it active) + fwrules (the rules match what you approved);\n"
          "   docker = docker (containers) + docker-images (tags behind Docker Hub). Settings keep their sections.\n"
          "   Findings of these checks have new ids, so each one that is still true is reported once more.")

    if not args.write:
        return 0
    todo = [(DROPIN, dropin_text(pins)) if pins else None,
            (NAMES_DROPIN, names_dropin_text(analysis.renames)) if analysis.renames else None]
    todo = [t for t in todo if t]
    if not todo:
        print("\nNothing to write.")
        return 0
    status = 0
    for name, text in todo:
        target = os.path.join(os.path.dirname(args.config) or ".", "centinela.d", name)
        if os.path.exists(target):
            print("\n%s already exists; not overwriting it." % target, file=sys.stderr)
            status = 2
            continue
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "x") as fh:
                fh.write(text)
        except OSError as exc:
            print("\ncannot write %s: %s (use sudo?)" % (target, exc), file=sys.stderr)
            return 2
        print("\nWrote %s. Check it with `centinela --list-modules`." % target)
    return status
