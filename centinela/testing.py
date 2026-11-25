"""Helpers for testing a check without a real machine.

    from centinela.testing import FakeCtx

    ctx = FakeCtx('[myapp]\\nlimit = 5\\n', cmds={"uptime": (0, "up 3 days")}, urls={"/health": "ok"})
    assert mymodule.run(ctx) == []

FakeCtx behaves like the real Ctx, including the safety guard, but never runs a command
or opens a connection.
"""
from .core import Config, Ctx, HttpError


class FakeCtx(Ctx):
    """run() matches the longest command-prefix in `cmds`; http_get matches URL substrings in `urls`."""

    def __init__(self, conf="", cmds=None, urls=None):
        super().__init__(Config.from_string(conf))
        self.cmds, self.urls = cmds or {}, urls or {}

    def run(self, argv, timeout=60, unsafe=False):
        self.guard(argv, unsafe)
        line = " ".join(argv)
        for prefix in sorted(self.cmds, key=len, reverse=True):
            if line.startswith(prefix):
                rc, out, *err = self.cmds[prefix]
                return rc, out, err[0] if err else ""
        return 127, "", "not faked: " + line

    def http_get(self, url, timeout=20):
        for part, body in self.urls.items():
            if part in url:
                if isinstance(body, Exception):
                    raise body
                return body
        raise HttpError(url, 404)


class FakeNotifier:
    """A stand-in channel for tests: records what it was asked to send, or fails on request.

        fake = FakeNotifier("pager")                # fake.NAME, fake.REQUIRED, fake.deliver as a notifier module
        fake = FakeNotifier("pager", fail="down")   # every delivery raises NotifyError("down")
        assert fake.sent == ["message text"]
    """

    def __init__(self, name="fake", fail=None, required=()):
        self.NAME, self.DESC, self.REQUIRED = name, "fake notifier", tuple(required)
        self.fail, self.sent = fail, []

    def deliver(self, text, cfg):
        from .notify import NotifyError
        if self.fail:
            raise NotifyError(self.fail)
        self.sent.append(text)
