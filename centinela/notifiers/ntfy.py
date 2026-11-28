"""ntfy.sh (or a self-hosted ntfy) topic."""
from .. import notify

NAME = "ntfy"
DESC = "ntfy topic (NTFY_URL, optional NTFY_TOKEN)"
REQUIRED = ("NTFY_URL",)


def deliver(text, cfg):
    (url,) = notify.need("NTFY_URL")
    headers = {"Content-Type": "text/plain; charset=utf-8", **notify.bearer("NTFY_TOKEN")}
    notify._post("ntfy", notify._secure_url("ntfy", url), text.encode(), headers)
