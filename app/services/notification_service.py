"""
Notification delivery service. Sends alert messages via email (SMTP),
Telegram bot API, and/or Slack incoming webhooks, based on configuration.
All sends are best-effort: failures are logged and returned in the result
rather than raised, so one broken channel never blocks the others.
"""
from __future__ import annotations

import smtplib
from email.mime.text import MIMEText

import requests

from app.config import settings
from app.utils.logger import logger


def send_email(to_address: str, subject: str, body: str) -> tuple[bool, str | None]:
    if not settings.email_alerts_enabled:
        return False, "email_alerts_disabled"
    if not settings.smtp_user or not settings.smtp_password:
        return False, "smtp_not_configured"

    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = to_address

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.smtp_from, [to_address], message.as_string())
        return True, None
    except Exception as exc:
        logger.error("Email send failed: %s", exc)
        return False, str(exc)


def send_telegram(message: str) -> tuple[bool, str | None]:
    if not settings.telegram_alerts_enabled:
        return False, "telegram_alerts_disabled"
    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        return False, "telegram_not_configured"

    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    try:
        response = requests.post(
            url, json={"chat_id": settings.telegram_chat_id, "text": message}, timeout=10
        )
        response.raise_for_status()
        return True, None
    except requests.RequestException as exc:
        logger.error("Telegram send failed: %s", exc)
        return False, str(exc)


def send_slack(message: str) -> tuple[bool, str | None]:
    if not settings.slack_alerts_enabled:
        return False, "slack_alerts_disabled"
    if not settings.slack_webhook_url:
        return False, "slack_not_configured"

    try:
        response = requests.post(settings.slack_webhook_url, json={"text": message}, timeout=10)
        response.raise_for_status()
        return True, None
    except requests.RequestException as exc:
        logger.error("Slack send failed: %s", exc)
        return False, str(exc)


def dispatch_alert_notifications(alert_title: str, alert_message: str, user_email: str | None = None) -> dict:
    """Send the alert across all enabled channels; return per-channel results."""
    full_message = f"[ThreatShield] {alert_title}\n{alert_message}"
    results = {}

    if user_email:
        ok, error = send_email(user_email, f"[ThreatShield Alert] {alert_title}", full_message)
        results["email"] = {"sent": ok, "error": error}

    ok, error = send_telegram(full_message)
    results["telegram"] = {"sent": ok, "error": error}

    ok, error = send_slack(full_message)
    results["slack"] = {"sent": ok, "error": error}

    return results
