"""Notification delivery (stdlib only): Telegram, ntfy, a generic webhook.

Secrets never appear in errors, and never in a URL we print. Channels that take a secret in
a header (ntfy, webhook) refuse plain http and refuse to follow redirects, so the header
is never sent anywhere else.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import namedtuple
from urllib.parse import urlsplit

API = "https://api.telegram.org"


class NotifyError(Exception):
    pass


def load_env_file(path, required=("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")):
    """Fill os.environ from a KEY=VALUE file; the real environment wins.

    Under systemd the vars are already set (EnvironmentFile=), so the file is
    only read when running by hand, e.g. `sudo centinela --test`.
    """
    if all(os.environ.get(name) for name in required):
        return
    try:
        mode = os.stat(path).st_mode
        with open(path) as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return
    except PermissionError:
        raise NotifyError("cannot read %s (run as root, or with sudo)" % path)
    if mode & 0o077:
        print("centinela: warning: %s is accessible by others (mode %o); run: sudo chmod 600 %s"
              % (path, mode & 0o777, path), file=sys.stderr)
    for raw in lines:
        line = re.sub(r"^export\s+", "", raw.strip())
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def credentials():
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat:
        raise NotifyError("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set (see /etc/sec/notify.env)")
    return token, chat


def send(token, chat_id, text, api=API, attempts=3):
    url = "%s/bot%s/sendMessage" % (api, token)
    body = urllib.parse.urlencode(
        {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"}
    ).encode()
    last = ""
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, data=body)
            with urllib.request.urlopen(req, timeout=15) as resp:
                if json.load(resp).get("ok"):
                    return
                last = "telegram replied ok=false"
        except urllib.error.HTTPError as exc:
            last = "telegram HTTP %s" % exc.code
            try:  # Telegram explains itself, e.g. "Forbidden: bot can't send messages to bots"
                detail = str(json.load(exc).get("description", ""))
            except Exception:
                detail = ""
            if detail:
                last += ": " + detail
            if exc.code in (400, 401, 403, 404):  # bad token/chat: retrying will not help
                break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = "telegram request failed: %s" % type(exc).__name__
        if attempt + 1 < attempts:
            time.sleep(2 * (attempt + 1))
    raise NotifyError(last)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry our Authorization header to whatever host it points at."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _open(req):
    return _OPENER.open(req, timeout=15)


def _need(*names):
    values = [os.environ.get(name, "") for name in names]
    if not all(values):
        raise NotifyError("%s not set (see /etc/sec/notify.env)" % " / ".join(names))
    return values


def _secure_url(name, url):
    """https only (loopback excepted, for local relays): the secret travels in this request."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"):
        return url
    raise NotifyError("%s: the URL must be https://" % name)


def _post(name, url, body, headers, attempts=3):
    last = ""
    for attempt in range(attempts):
        try:
            _open(urllib.request.Request(url, data=body, headers=headers))
            return
        except urllib.error.HTTPError as exc:
            last = "%s HTTP %s" % (name, exc.code)
            if exc.code in (301, 302, 303, 307, 308):
                last += " (redirects are not followed)"
            if exc.code in (301, 302, 303, 307, 308, 400, 401, 403, 404, 413):
                break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = "%s request failed: %s" % (name, type(exc).__name__)
        if attempt + 1 < attempts:
            time.sleep(2 * (attempt + 1))
    raise NotifyError(last)


def _bearer(var):
    token = os.environ.get(var, "")
    return {"Authorization": "Bearer " + token} if token else {}


def _telegram(text, cfg):
    token, chat = credentials()
    send(token, chat, text)


def _ntfy(text, cfg):
    (url,) = _need("NTFY_URL")
    headers = {"Content-Type": "text/plain; charset=utf-8", **_bearer("NTFY_TOKEN")}
    _post("ntfy", _secure_url("ntfy", url), text.encode(), headers)


def _webhook(text, cfg):
    (url,) = _need("WEBHOOK_URL")
    field = str(cfg.table("notify", "webhook").get("field", "text")) if cfg else "text"
    headers = {"Content-Type": "application/json", **_bearer("WEBHOOK_TOKEN")}
    _post("webhook", _secure_url("webhook", url), json.dumps({field: text}).encode(), headers)


Channel = namedtuple("Channel", "required deliver")
CHANNELS = {
    "telegram": Channel(("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"), _telegram),
    "ntfy": Channel(("NTFY_URL",), _ntfy),
    "webhook": Channel(("WEBHOOK_URL",), _webhook),
}


def deliver(names, messages, cfg=None):
    """Send every message to every channel. One failing channel does not stop the others;
    it is an error only when none of them got the messages."""
    failures, delivered = [], 0
    for name in names:
        try:
            for text in messages:
                CHANNELS[name].deliver(text, cfg)
            delivered += 1
        except NotifyError as exc:
            failures.append(str(exc) if name in str(exc) else "%s: %s" % (name, exc))
    if not delivered:
        raise NotifyError("; ".join(failures))
    for failure in failures:
        print("centinela: warning: %s (delivered through the other channel(s))" % failure, file=sys.stderr)
