"""
Notifications: tell people when AIDA needs them, without anyone watching the dashboard.

Channels (configure in .env; any combination, or none):
  AIDA_NOTIFY_WEBHOOK_URLS   comma-separated incoming-webhook URLs (Slack, Microsoft Teams, Discord, ...)
  AIDA_SMTP_HOST / AIDA_SMTP_PORT (587) / AIDA_SMTP_USER / AIDA_SMTP_PASSWORD / AIDA_SMTP_FROM
  AIDA_NOTIFY_EMAIL_TO       comma-separated recipients
  AIDA_DASHBOARD_URL         link included in every message (default http://localhost:8501)
  AIDA_NOTIFY_EVENTS         which events to send (default: approval_needed,auto_ticket,fix_failed,escalated)

Sending happens in the background and never blocks or fails a ticket.
"""
import asyncio
import json
import os
import smtplib
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

DEFAULT_EVENTS = "approval_needed,auto_ticket,fix_failed,escalated"
TITLES = {
    "approval_needed": "Approval needed",
    "auto_ticket": "Problem detected",
    "fix_failed": "Fix failed",
    "escalated": "Needs a human",
    "test": "Test notification",
}

# Recent delivery results, newest last (shown on the dashboard)
history: list[dict] = []


def _enabled_events() -> set[str]:
    return {e.strip() for e in os.getenv("AIDA_NOTIFY_EVENTS", DEFAULT_EVENTS).split(",") if e.strip()} | {"test"}


def _webhooks() -> list[str]:
    return [u.strip() for u in os.getenv("AIDA_NOTIFY_WEBHOOK_URLS", "").split(",") if u.strip()]


def _email_recipients() -> list[str]:
    return [a.strip() for a in os.getenv("AIDA_NOTIFY_EMAIL_TO", "").split(",") if a.strip()]


def configured_channels() -> dict:
    return {"webhooks": len(_webhooks()), "email": bool(os.getenv("AIDA_SMTP_HOST") and _email_recipients()),
            "events": sorted(_enabled_events() - {"test"})}


def format_message(event: str, summary: str, thread_id: str | None = None) -> tuple[str, str]:
    dashboard = os.getenv("AIDA_DASHBOARD_URL", "http://localhost:8501")
    title = f"AIDA: {TITLES.get(event, event)}"
    ticket = f" (ticket {thread_id[:8]})" if thread_id else ""
    body = f"{summary}{ticket}\nOpen the dashboard: {dashboard}"
    return title, body


def _send_webhook(url: str, title: str, body: str) -> None:
    text = f"*{title}*\n{body}"
    # "text" is read by Slack and Teams incoming webhooks, "content" by Discord
    data = json.dumps({"text": text, "content": text}).encode()
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status >= 300:
            raise RuntimeError(f"HTTP {response.status}")


def _send_email(title: str, body: str) -> None:
    message = EmailMessage()
    message["Subject"] = title
    message["From"] = os.getenv("AIDA_SMTP_FROM") or os.getenv("AIDA_SMTP_USER") or "aida@localhost"
    message["To"] = ", ".join(_email_recipients())
    message.set_content(body)
    with smtplib.SMTP(os.environ["AIDA_SMTP_HOST"], int(os.getenv("AIDA_SMTP_PORT", "587")), timeout=15) as smtp:
        smtp.ehlo()
        if smtp.has_extn("starttls"):
            smtp.starttls()
            smtp.ehlo()
        if os.getenv("AIDA_SMTP_USER"):
            smtp.login(os.environ["AIDA_SMTP_USER"], os.getenv("AIDA_SMTP_PASSWORD", ""))
        smtp.send_message(message)


def send_now(event: str, summary: str, thread_id: str | None = None) -> list[dict]:
    """Deliver to every configured channel. Returns one result per channel (never raises)."""
    if event not in _enabled_events():
        return []
    title, body = format_message(event, summary, thread_id)
    results = []
    for url in _webhooks():
        channel = "webhook " + url.split("//", 1)[-1].split("/", 1)[0]  # host only; the path holds the secret
        try:
            _send_webhook(url, title, body)
            results.append({"channel": channel, "ok": True, "error": None})
        except Exception as e:
            results.append({"channel": channel, "ok": False, "error": str(e)[:200]})
    if os.getenv("AIDA_SMTP_HOST") and _email_recipients():
        try:
            _send_email(title, body)
            results.append({"channel": "email", "ok": True, "error": None})
        except Exception as e:
            results.append({"channel": "email", "ok": False, "error": str(e)[:200]})
    for r in results:
        history.append({**r, "event": event, "thread_id": thread_id,
                        "at": datetime.now(timezone.utc).isoformat()})
        if not r["ok"]:
            print(f"[Notify] {r['channel']} failed: {r['error']}")
    del history[:-50]
    return results


_background: set[asyncio.Task] = set()


def send_in_background(event: str, summary: str, thread_id: str | None = None) -> None:
    """Fire-and-forget from async code; the network call runs in a worker thread."""
    if event not in _enabled_events() or not (_webhooks() or os.getenv("AIDA_SMTP_HOST")):
        return
    task = asyncio.create_task(asyncio.to_thread(send_now, event, summary, thread_id))
    _background.add(task)
    task.add_done_callback(_background.discard)


async def drain() -> None:
    """Wait for pending notifications (used at shutdown and in tests)."""
    if _background:
        await asyncio.gather(*list(_background), return_exceptions=True)
