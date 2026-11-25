"""Shared types and plumbing: findings, config, command/HTTP helpers.

Everything here is read-only with respect to the host: checks may run
commands and fetch URLs, never change anything.
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
import subprocess
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import safety

CRIT = "crit"
WARN = "warn"
LABELS = {CRIT: "CRIT", WARN: "WARN"}
CONTRACT = 1  # version of the module interface; a module may declare CONTRACT = n to require it
USER_AGENT = "centinela/1.0 (read-only health digest)"


class Skip(Exception):
    """A check could not run right now (offline, tool missing, no root).

    Logged to stderr/journal, never sent to Telegram.
    """


class HttpError(Skip):
    def __init__(self, url, code):
        super().__init__("HTTP %s for %s" % (code, url))
        self.code = code


@dataclass(frozen=True)
class Finding:
    module: str
    id: str  # stable identifier within the module; drives dedupe
    level: str  # CRIT or WARN
    text: str
    cmd: str = ""

    @property
    def key(self):
        return "%s:%s:%s" % (self.module, self.id, self.level)

    def line(self):
        out = "[%s] %s" % (LABELS[self.level], " ".join(self.text.split()))
        if self.cmd:
            out += " | run: " + " ".join(self.cmd.split())
        return out


def short_hash(*parts):
    return hashlib.sha1("\0".join(parts).encode()).hexdigest()[:8]


def vtuple(version):
    """'1.26.2' -> (1, 26, 2). Non-numeric trailing parts are ignored."""
    return tuple(int(p) for p in re.findall(r"\d+", version.split("-")[0].split("~")[0]))


def _merge(base, extra):
    """Deep-merge TOML tables; scalars and lists in `extra` replace those in `base`."""
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


class Config:
    """Typed, read-only view of the TOML config: cfg.get/list/int/bool(section, key, default)."""

    def __init__(self, data=None, sources=()):
        self.data = data or {}
        self.sources = list(sources)

    @classmethod
    def load(cls, path):
        """`path` plus every centinela.d/*.toml next to it; later files (by name) override earlier ones."""
        files = [path] if os.path.exists(path) else []
        files += sorted(glob.glob(os.path.join(os.path.dirname(path) or ".", "centinela.d", "*.toml")))
        data = {}
        for name in files:
            try:
                with open(name, "rb") as fh:
                    _merge(data, tomllib.load(fh))
            except tomllib.TOMLDecodeError as exc:
                raise ValueError("%s: %s" % (name, exc))
        return cls(data, files)

    @classmethod
    def from_string(cls, text):
        return cls(tomllib.loads(text))

    def _raw(self, section, key, default):
        value = self.data.get(section, {})
        value = value.get(key, default) if isinstance(value, dict) else default
        return default if value is None else value

    def has(self, section, key):
        return key in (self.data.get(section) or {})

    def get(self, section, key, default=""):
        return str(self._raw(section, key, default)).strip()

    def list(self, section, key, default=""):
        """Accepts a TOML array or a comma/space separated string."""
        raw = self._raw(section, key, default)
        if isinstance(raw, list):
            return [str(x) for x in raw]
        return [x for x in re.split(r"[,\s]+", str(raw)) if x]

    def int(self, section, key, default):
        try:
            return int(self._raw(section, key, default))
        except (TypeError, ValueError):
            return default

    def bool(self, section, key, default):
        raw = self._raw(section, key, default)
        return raw if isinstance(raw, bool) else str(raw).lower() in ("1", "true", "yes", "on")

    def table(self, section, key):
        value = self._raw(section, key, {})
        return value if isinstance(value, dict) else {}


SECRET_PREFIXES = ("TELEGRAM_", "NTFY_", "WEBHOOK_", "HEARTBEAT_")  # more are added from each notifier's REQUIRED


def add_secret_prefixes(prefixes):
    global SECRET_PREFIXES
    SECRET_PREFIXES = tuple(dict.fromkeys(SECRET_PREFIXES + tuple(prefixes)))


def child_env():
    """Environment for commands we run: C locale, and without the notification credentials."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(SECRET_PREFIXES)}
    env.update(LC_ALL="C", LANG="C")
    return env


class Blocked(Skip):
    """A command was refused because it could change the machine (see safety.py)."""


class Ctx:
    """What a check module gets: its config plus read-only command/HTTP access."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.state_dir = None  # where Centinela keeps its own files; set by the command line, None in tests
        self.allow_dangerous = cfg.bool("general", "allow_dangerous_commands", False)

    def guard(self, argv, unsafe=False):
        """Refuse a command that could change the machine, unless the config allowed it."""
        if unsafe or self.allow_dangerous:
            return
        try:
            safety.verify(argv)
        except safety.Unsafe as exc:
            raise Blocked("refused: %s" % exc)

    def run(self, argv, timeout=60, unsafe=False):
        """Return (returncode, stdout, stderr); 127 when the binary is missing."""
        self.guard(argv, unsafe)
        env = child_env()
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, env=env
            )
        except (FileNotFoundError, PermissionError) as exc:
            return 127, "", str(exc)
        except subprocess.TimeoutExpired:
            raise Skip("%s timed out after %ss" % (argv[0], timeout))
        return proc.returncode, proc.stdout, proc.stderr

    def http_get(self, url, timeout=20):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(5_000_000).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            raise HttpError(url, exc.code)
        except (urllib.error.URLError, OSError) as exc:
            raise Skip("cannot fetch %s: %s" % (url, exc))
