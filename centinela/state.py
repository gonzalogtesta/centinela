"""Dedupe state: which finding keys were sent, and when."""
from __future__ import annotations

import fcntl
import json
import os
import sys
import time
from contextlib import contextmanager

PRUNE_AFTER = 90 * 86400


class State:
    def __init__(self, path):
        self.path = path
        self.sent = {}
        self.runs = {}  # mode -> when a run of it last completed

    @classmethod
    def load(cls, path):
        st = cls(path)
        try:
            with open(path) as fh:
                data = json.load(fh)
            st.sent = {k: float(v) for k, v in data.get("sent", {}).items()}
            st.runs = {k: float(v) for k, v in data.get("runs", {}).items()}
        except FileNotFoundError:
            pass
        except (ValueError, AttributeError, OSError) as exc:
            print("centinela: ignoring unreadable state %s: %s" % (path, exc), file=sys.stderr)
        return st

    def save(self):
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"sent": self.sent, "runs": self.runs}, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.path)


@contextmanager
def locked(state_path):
    """Serialise runs (daily and weekly timers can fire close together)."""
    os.makedirs(os.path.dirname(state_path) or ".", mode=0o700, exist_ok=True)
    fd = os.open(state_path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def now():
    return time.time()
