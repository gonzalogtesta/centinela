"""Which channels does a finding go to? Pure functions.

Order of precedence for a module: [notify.routes] <module>, then [notify.routes] "*", then
the module's own CHANNELS, then [notify] channels. A route only picks among channels the admin
has set up, so a module can never send findings to an address of its own. Notices about
Centinela itself (a failed run, a missed schedule) always use [notify] channels.
"""
from __future__ import annotations

from .core import WARN, Finding

SELF = "centinela"


def route_table(cfg):
    return {str(k): ([str(v) for v in val] if isinstance(val, list) else [str(val)])
            for k, val in cfg.table("notify", "routes").items()}


def wanted(module, cfg, mods):
    """The channel names configured or declared for a module, before checking they exist."""
    routes = route_table(cfg)
    if module in routes:
        return routes[module]
    if "*" in routes:
        return routes["*"]
    declared = getattr(mods.get(module), "CHANNELS", None)
    return [str(c) for c in declared] if isinstance(declared, (list, tuple)) else []


def all_names(cfg, mods, default):
    """Every channel in use anywhere, for --test and for loading their secrets."""
    names = list(default)
    for module in set(route_table(cfg)) | set(mods):
        names.extend(wanted(module, cfg, mods) if module != "*" else route_table(cfg)["*"])
    return list(dict.fromkeys(names))


def problems(findings, cfg, mods, available):
    """A finding for each unknown channel name that a route or a module asks for."""
    seen, out = set(), []
    modules_ = {f.module for f in findings if f.module != SELF}
    for module in sorted(modules_):
        for name in wanted(module, cfg, mods):
            if name not in available and name not in seen:
                seen.add(name)
                out.append(Finding(SELF, "route-unknown-" + name, WARN,
                                   "channel %r (asked for by %s) is not a known notifier, so its findings went to the "
                                   "default channels. Known: %s" % (name, module, ", ".join(sorted(available))),
                                   "grep -n -A8 'notify.routes' /etc/centinela/centinela.toml"))
    return out


def group(findings, cfg, mods, default, available):
    """{tuple(channels): [findings]} in first-seen order. Unknown names are dropped; none left = default."""
    default = tuple(default)
    groups = {}
    for f in findings:
        names = [] if f.module == SELF else wanted(f.module, cfg, mods)
        chosen = tuple(dict.fromkeys(n for n in names if n in available)) or default
        groups.setdefault(chosen, []).append(f)
    return groups
