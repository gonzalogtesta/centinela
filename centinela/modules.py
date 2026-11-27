"""Discover check modules: built-ins in centinela/checks, extras from a drop-in dir.

A module is a .py file exposing:
    NAME: str                         # id used in enable/disable lists
    NEEDS: tuple                      # optional; what it needs without root: files, docker, netadmin, journal, procs, root, custom
    FREQUENT: bool                    # optional; True = cheap and local enough to run every few minutes
    CONTRACT: int                     # optional; interface version this module was written for (core.CONTRACT)
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
from .core import CONTRACT


def _builtin():
    for info in pkgutil.iter_modules(checks.__path__):
        if not info.name.startswith("_"):
            yield importlib.import_module("%s.%s" % (checks.__name__, info.name))


def _unsafe(paths):
    """Paths that others could write to, or that a non-root owner controls when running as root."""
    bad = []
    for path in paths:
        st = os.stat(path)
        if st.st_mode & 0o022 or (os.geteuid() == 0 and st.st_uid != 0):
            bad.append(path)
    return bad


def _load(path, label, validate=None):
    """Import one .py file; returns a valid module or None (reported on stderr, never fatal)."""
    spec = importlib.util.spec_from_file_location("centinela_extra_" + label, path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # a broken drop-in must not take the digest down
        print("centinela: cannot load %s: %r" % (path, exc), file=sys.stderr)
        return None
    problem = (validate or _invalid)(mod)
    if problem:
        print("centinela: ignoring %s: %s" % (path, problem), file=sys.stderr)
        return None
    return mod


def _invalid(mod):
    """Why a module cannot be used, or '' when it satisfies the contract."""
    if not isinstance(getattr(mod, "NAME", None), str) or not mod.NAME:
        return "no NAME"
    if not callable(getattr(mod, "run", None)):
        return "no run(ctx)"
    wanted = getattr(mod, "CONTRACT", CONTRACT)
    if not isinstance(wanted, int) or wanted > CONTRACT:
        return "needs module contract %r, this Centinela offers %d (upgrade Centinela)" % (wanted, CONTRACT)
    return ""


def load_dir(directory, validate=None):
    """Load *.py from directory. It runs as root, so it must not be writable by others.

    The directory is on sys.path while its files load, so a check can be split into
    helper modules or a package next to it (import mylib).
    """
    if not os.path.isdir(directory):
        return
    files = [os.path.join(directory, n) for n in sorted(os.listdir(directory))
             if n.endswith(".py") and not n.startswith("_")]
    problems = _unsafe([directory] + files)
    if problems:
        print("centinela: refusing extra checks, unsafe ownership/permissions: %s"
              % ", ".join(problems), file=sys.stderr)
        return
    sys.path.insert(0, directory)
    try:
        for path in files:
            mod = _load(path, os.path.basename(path)[:-3], validate)
            if mod:
                yield mod
    finally:
        sys.path.remove(directory)


def load_listed(paths, validate=None):
    """[general] modules = ["/opt/mychecks/redis.py"]: explicit files, same safety rules."""
    for path in paths:
        if not path.endswith(".py") or not os.path.isfile(path):
            print("centinela: [general] modules: %s is not a .py file" % path, file=sys.stderr)
            continue
        directory = os.path.dirname(os.path.abspath(path))
        if _unsafe([directory, path]):
            print("centinela: refusing %s, unsafe ownership/permissions" % path, file=sys.stderr)
            continue
        sys.path.insert(0, directory)
        try:
            mod = _load(path, "listed_" + os.path.basename(path)[:-3], validate)
        finally:
            sys.path.remove(directory)
        if mod:
            yield mod


def discover(cfg):
    mods = {}
    for mod in _builtin():
        mods[mod.NAME] = mod
    for mod in load_dir(cfg.get("general", "extra_dir", "/etc/centinela/checks.d")):
        mods[mod.NAME] = mod  # a drop-in with the same NAME replaces the built-in
    for mod in load_listed(cfg.list("general", "modules")):
        mods[mod.NAME] = mod
    return mods


def plan(cfg, mods, only=None, frequent=False):
    """Return {name: (module, status)}: status is 'run', 'disabled', 'n/a', or 'slow' (a frequent run only
    runs modules that declare FREQUENT = True: cheap, local, no network)."""
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
        elif status == "run" and frequent and not getattr(mod, "FREQUENT", False) and only is None:
            status = "slow"
        out[name] = (mod, status)
    return out
