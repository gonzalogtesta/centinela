"""Generic JSON webhook (Slack, Discord, Mattermost, your own service)."""
import json

from .. import notify

NAME = "webhook"
DESC = "JSON webhook (WEBHOOK_URL, optional WEBHOOK_TOKEN; [notify.webhook] field)"
REQUIRED = ("WEBHOOK_URL",)


def deliver(text, cfg):
    (url,) = notify.need("WEBHOOK_URL")
    field = str(cfg.table("notify", "webhook").get("field", "text")) if cfg else "text"
    headers = {"Content-Type": "application/json", **notify.bearer("WEBHOOK_TOKEN")}
    notify._post("webhook", notify._secure_url("webhook", url), json.dumps({field: text}).encode(), headers)
