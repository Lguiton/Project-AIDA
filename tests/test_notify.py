"""Notifications to webhooks (Slack/Teams/Discord) and email."""
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src import monitor, notify

pytestmark = pytest.mark.usefixtures("test_db")


@pytest.fixture
def webhook(monkeypatch):
    """A local stand-in for a Slack/Teams webhook that records what it receives."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/services/T000/SECRET-PATH"
    monkeypatch.setenv("AIDA_NOTIFY_WEBHOOK_URLS", url)
    notify.history.clear()
    yield received
    server.shutdown()


def test_approval_request_sends_a_notification(api_client, webhook):
    with api_client() as client:
        ticket = client.post("/api/tickets", json={"issue": "please flush my dns"}).json()
        client.portal.call(notify.drain)
        status = client.get("/api/notify/status").json()

    assert len(webhook) == 1
    text = webhook[0]["text"]
    assert "Approval needed" in text and "flush_dns_cache" in text and ticket["thread_id"][:8] in text
    assert webhook[0]["content"] == text  # Discord field
    # The webhook's secret path is never shown on the dashboard
    assert status["recent"][0]["ok"] and "SECRET-PATH" not in json.dumps(status)


def test_monitoring_alert_sends_a_notification(api_client, webhook, monkeypatch):
    # Unique key: other tests may already have an open ticket for "disk:/"
    alert = monitor.Alert(key=f"disk:/notify-{uuid.uuid4().hex[:6]}", check="disk",
                          issue=f"{monitor.AUTO_PREFIX} The disk at / is 99% full.")
    monkeypatch.setattr(monitor, "collect_alerts", lambda: [alert])
    with api_client() as client:
        client.post("/api/monitor/run")
        client.portal.call(notify.drain)
    assert any("Problem detected" in m["text"] and "99% full" in m["text"] for m in webhook)


def test_events_can_be_filtered(api_client, webhook, monkeypatch):
    monkeypatch.setenv("AIDA_NOTIFY_EVENTS", "fix_failed")
    with api_client() as client:
        client.post("/api/tickets", json={"issue": "please flush my dns"})
        client.portal.call(notify.drain)
    assert webhook == []


def test_email_notifications(monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            sent.append(("connect", host, port))
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def ehlo(self): pass
        def has_extn(self, name): return True
        def starttls(self): sent.append(("starttls",))
        def login(self, user, password): sent.append(("login", user))
        def send_message(self, message): sent.append(("send", message["To"], message["Subject"]))

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    monkeypatch.delenv("AIDA_NOTIFY_WEBHOOK_URLS", raising=False)
    monkeypatch.setenv("AIDA_SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("AIDA_SMTP_USER", "aida@example.com")
    monkeypatch.setenv("AIDA_NOTIFY_EMAIL_TO", "ops@example.com, boss@example.com")
    results = notify.send_now("approval_needed", "AIDA wants to run restart_service", "abcdef1234")
    assert results == [{"channel": "email", "ok": True, "error": None}]
    assert ("starttls",) in sent and ("login", "aida@example.com") in sent
    assert ("send", "ops@example.com, boss@example.com", "AIDA: Approval needed") in sent


def test_test_button_without_channels(api_client, monkeypatch):
    monkeypatch.delenv("AIDA_NOTIFY_WEBHOOK_URLS", raising=False)
    monkeypatch.delenv("AIDA_SMTP_HOST", raising=False)
    with api_client() as client:
        response = client.post("/api/notify/test")
    assert response.status_code == 400 and "No notification channels" in response.text


def test_broken_webhook_never_breaks_a_ticket(api_client, monkeypatch):
    monkeypatch.setenv("AIDA_NOTIFY_WEBHOOK_URLS", "http://127.0.0.1:9/unreachable")
    with api_client() as client:
        ticket = client.post("/api/tickets", json={"issue": "please flush my dns"})
        client.portal.call(notify.drain)
    assert ticket.status_code == 200
    assert notify.history[-1]["ok"] is False
