"""Notification channels. One file per channel, found the same way as checks.

A notifier is a .py file exposing:
    NAME: str                      # the name used in [notify] channels and [notify.routes]
    DESC: str                      # one line
    REQUIRED: tuple[str, ...]      # environment variables it needs (from the secrets file)
    CONTRACT: int                  # optional; interface version, see core.CONTRACT
    deliver(text, cfg)             # send one message; raise notify.NotifyError on failure

Secrets live in the secrets file, never in the config: a notifier only reads its REQUIRED
variables. Variables that start like a notifier's REQUIRED names are hidden from every command
a check runs. Helpers that keep a secret safe (notify.secure_url, notify.post, notify.bearer)
are in centinela.notify.
"""
