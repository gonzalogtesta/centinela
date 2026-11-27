"""Which channels does a finding go to? Pure functions.

Order of precedence for a finding: [notify.routes] "<module>:<level>", "<module>", "level:<level>", "*",
then the module's own CHANNELS, then [notify] channels. A route only picks among channels the admin
has set up, so a module can never send findings to an address of its own. Notices about
Centinela itself (a failed run, a missed schedule) always use [notify] channels.
"""
from __future__ import annotations

from .core import WARN, Finding

SELF = "centinela"


def route_table(cfg):
    return {str(k): ([str(v) for v in val] if isinstance(val, list) else [str(val)])
            for k, val in cfg.table("notify", "routes").items()}


def wanted(module, cfg, mods, level=None):
    """The channel names configured or declared for a finding of `module` (and `level`), before checking they exist.

    Most specific first: "<module>:<level>", "<module>", "level:<level>", "*", the module's own CHANNELS."""
    routes = route_table(cfg)
    keys = (["%s:%s" % (module, level)] if level else []) + [module] + (["level:%s" % level] if level else []) + ["*"]
    for key in keys:
        if key in routes:
            return routes[key]
    declared = getattr(mods.get(module), "CHANNELS", None)
    return [str(c) for c in declared] if isinstance(declared, (list, tuple)) else []


def named(cfg, mods):
    """[(where, channel name)] for every channel a route or a module asks for."""
    out = [(("route %r" % key), name) for key, names in route_table(cfg).items() for name in names]
    for module, mod in mods.items():
        declared = getattr(mod, "CHANNELS", None)
        if isinstance(declared, (list, tuple)):
            out.extend(("check %s" % module, str(name)) for name in declared)
    return out


def all_names(cfg, mods, default):
    """Every channel in use anywhere, for --test and for loading their secrets."""
    return list(dict.fromkeys(list(default) + [name for _, name in named(cfg, mods)]))


def problems(findings, cfg, mods, available):
    """A finding for each unknown channel name that a route or a check asks for."""
    seen, out = set(), []
    used = {f.module for f in findings if f.module != SELF}
    for where, name in named(cfg, {m: mod for m, mod in mods.items() if m in used}):
        if name not in available and name not in seen:
            seen.add(name)
            out.append(Finding(SELF, "route-unknown-" + name, WARN,
                               "channel %r (asked for by %s) is not a known notifier, so those findings went to the "
                               "default channels. Known: %s" % (name, where, ", ".join(sorted(available))),
                               "grep -n -A8 'notify.routes' /etc/centinela/centinela.toml"))
    return out


def group(findings, cfg, mods, default, available):
    """{tuple(channels): [findings]} in first-seen order. Unknown names are dropped; none left = default."""
    default = tuple(default)
    groups = {}
    for f in findings:
        names = [] if f.module == SELF else wanted(f.module, cfg, mods, f.level)
        chosen = tuple(dict.fromkeys(n for n in names if n in available)) or default
        groups.setdefault(chosen, []).append(f)
    return groups
