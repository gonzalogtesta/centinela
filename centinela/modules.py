"""Discover check modules: built-ins in centinela/checks, extras from a drop-in dir.

A module is a .py file exposing:
    NAME: str                         # id used in enable/disable lists
    DESC: str                         # one line, shown by --list-modules
    applicable(cfg) -> bool           # optional; False = silently not for this host
    run(ctx) -> list[Finding]
"""
from __future__ import annotations

import importlib
import importlib.util
import os
import pkgutil
import sys

from . import checks


def _builtin():
    for info in pkgutil.iter_modules(checks.__path__):
        if not info.name.startswith("_"):
            yield importlib.import_module("%s.%s" % (checks.__name__, info.name))


def _extra(directory):
    """Load *.py from directory. It runs as root, so it must not be writable by others."""
    if not os.path.isdir(directory):
        return
    problems = []
    for path in (directory, *[os.path.join(directory, n) for n in os.listdir(directory) if n.endswith(".py")]):
        st = os.stat(path)
        if st.st_mode & 0o022 or (os.geteuid() == 0 and st.st_uid != 0):
            problems.append(path)
    if problems:
        print("centinela: refusing extra checks, unsafe ownership/permissions: %s"
              % ", ".join(problems), file=sys.stderr)
        return
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".py") or name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location("centinela_extra_" + name[:-3], os.path.join(directory, name))
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:  # a broken drop-in must not take the digest down
            print("centinela: cannot load %s: %r" % (name, exc), file=sys.stderr)
            continue
        yield mod


def discover(cfg):
    mods = {}
    for mod in _builtin():
        mods[mod.NAME] = mod
    for mod in _extra(cfg.get("general", "extra_dir", "/etc/centinela/checks.d")):
        mods[mod.NAME] = mod  # a drop-in with the same NAME replaces the built-in
    return mods


def plan(cfg, mods, only=None):
    """Return {name: (module, status)} where status is 'run', 'disabled' or 'n/a'."""
    enabled = cfg.list("general", "enable", "auto")
    disabled = set(cfg.list("general", "disable"))
    out = {}
    for name in sorted(mods):
        mod = mods[name]
        if only is not None:
            status = "run" if name in only else "disabled"
        elif name in disabled or (enabled != ["auto"] and name not in enabled):
            status = "disabled"
        else:
            status = "run"
        if status == "run" and not getattr(mod, "applicable", lambda c: True)(cfg):
            status = "n/a"
        out[name] = (mod, status)
    return out
