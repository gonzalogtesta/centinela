"""Example check: a URL must answer, and optionally contain some text.

Install:  centinela --print example-http-status | sudo tee /etc/centinela/checks.d/http_status.py
Config:   [http_status]
          urls = ["http://127.0.0.1:8000/health"]
          must_contain = "ok"        # optional
"""
import shlex

from centinela.core import CRIT, Finding, HttpError, Skip, short_hash

NAME = "http_status"
DESC = "listed URLs answer (and contain the expected text)"


def applicable(cfg):
    return bool(cfg.list("http_status", "urls"))


def run(ctx):
    needle = ctx.cfg.get("http_status", "must_contain")
    findings = []
    for url in ctx.cfg.list("http_status", "urls"):
        cmd = "curl -sS -m 10 -i %s" % shlex.quote(url)
        try:
            body = ctx.http_get(url, timeout=10)
        except HttpError as exc:
            findings.append(Finding(NAME, "status-" + short_hash(url), CRIT,
                                    "%s answered HTTP %s" % (url, exc.code), cmd))
            continue
        except Skip:  # connection refused, DNS, timeout: for this check that is the finding
            findings.append(Finding(NAME, "down-" + short_hash(url), CRIT, "%s does not answer" % url, cmd))
            continue
        if needle and needle not in body:
            findings.append(Finding(NAME, "text-" + short_hash(url), CRIT,
                                    "%s answers but does not contain %r" % (url, needle), cmd))
    return findings
