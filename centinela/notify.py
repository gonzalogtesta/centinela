"""Telegram delivery (stdlib only). The bot token never appears in errors."""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.telegram.org"


class NotifyError(Exception):
    pass


def load_env_file(path):
    """Fill os.environ from a KEY=VALUE file; the real environment wins.

    Under systemd the vars are already set (EnvironmentFile=), so the file is
    only read when running by hand, e.g. `sudo centinela --test`.
    """
    if os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
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
