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


def dropin_text(pins):
    lines = ["# Written by `centinela migrate`: the service settings 1.0 used when your config did not give them.",
             "# Edit or delete this file once you have chosen your own services (`centinela setup`).", "[services]"]
    lines += ["%s = %s" % (key, json.dumps(value)) for key, value in sorted(pins.items())]
    return "\n".join(lines) + "\n"


def main(argv):
    ap = argparse.ArgumentParser(prog="centinela migrate", description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=os.environ.get("CENTINELA_CONF", "/etc/centinela/centinela.toml"))
    ap.add_argument("--write", action="store_true",
                    help="write the drop-in that keeps the 1.0 service defaults (otherwise only report)")
    args = ap.parse_args(argv)
    try:
        cfg = Config.load(args.config)
    except ValueError as exc:
        print("centinela: cannot read config: %s" % exc, file=sys.stderr)
        return 2
    print("Config: %s%s" % (args.config, "" if cfg.sources else " (not found: built-in defaults)"))

    pins = old_service_defaults_in_use(cfg)
    print("\n1. Services are now off until you list them")
    if pins:
        print("   1.0 filled these in for you, and 1.1 no longer does:")
        for key, value in pins.items():
            print("     [services] %s = %s" % (key, json.dumps(value)))
        print("   Choose your own with `sudo centinela setup` (recommended), or keep exactly the old behaviour\n"
              "   with `sudo centinela migrate --write`.")
    else:
        print("   Nothing to do: your config already names its services (or the module is disabled).")

    refused, unchecked = scan_checks(cfg.get("general", "extra_dir", "/etc/centinela/checks.d"))
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

    if not args.write:
        return 0
    if not pins:
        print("\nNothing to write.")
        return 0
    target = os.path.join(os.path.dirname(args.config) or ".", "centinela.d", DROPIN)
    if os.path.exists(target):
        print("\n%s already exists; not overwriting it." % target, file=sys.stderr)
        return 2
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "x") as fh:
            fh.write(dropin_text(pins))
    except OSError as exc:
        print("\ncannot write %s: %s (use sudo?)" % (target, exc), file=sys.stderr)
        return 2
    print("\nWrote %s. Check it with `centinela --list-modules`." % target)
    return 0
