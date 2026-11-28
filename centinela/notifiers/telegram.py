"""Telegram bot message."""
from .. import notify

NAME = "telegram"
DESC = "Telegram bot (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)"
REQUIRED = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")


def deliver(text, cfg):
    token, chat = notify.credentials()
    notify.send(token, chat, text)
