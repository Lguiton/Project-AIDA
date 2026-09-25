"""Connected products: signed error intake, grouping, health checks, closing tickets."""
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src import monitor, notify, products
from tests.conftest import make_user


def signed(secret: str, report: dict, product_id: str = "eivanta-analytics", ts: int | None = None):
    body = json.dumps(report).encode()
    timestamp = str(ts or int(time.time()))
    signature = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return body, {"Content-Type": "application/json", "X-AIDA-Product": product_id,
                  "X-AIDA-Timestamp": timestamp, "X-AIDA-Signature": signature}


def sample_report(signature="abc123", tenant="CLI-001", error_type="KeyError"):
    return {
        "product": "eivanta-analytics", "environment": "local", "error_type": error_type,
        "message": "'revenue'", "method": "GET", "route": "/api/v1/finance/mrr", "status": 500,
        "request_id": f"req-{time.time_ns()}", "tenant_id": tenant, "signature": signature,  # unique, like real reports
        "frames": [{"file": "backend/db_manager.py", "line": 812, "function": "get_mrr",
                    "code": "row['revenue']", "in_app": True}],
    }


# ---- unit ----------------------------------------------------------------------

def test_signature_verification_rejects_bad_old_and_replayed_reports():
    products._seen_signatures.clear()
    body, headers = signed("s3cret", sample_report())
    ts, sig = headers["X-AIDA-Timestamp"], headers["X-AIDA-Signature"]
    assert products.verify("s3cret", ts, sig, body) is None
    assert products.verify("s3cret", ts, sig, body) == "duplicate report (replay)"
    assert products.verify("wrong", ts, sig, body) == "invalid signature"
    old_body, old = signed("s3cret", sample_report(), ts=int(time.time()) - 3600)
    assert "too old" in products.verify("s3cret", old["X-AIDA-Timestamp"], old["X-AIDA-Signature"], old_body)
    assert products.verify("s3cret", "not-a-time", sig, body).startswith("missing or invalid")


def test_issue_text_carries_the_diagnosis_inputs_only():
    text = products.issue_text({"name": "Eivanta Analytics", "environment": "local"}, sample_report())
    assert text.startswith("[Error reported by Eivanta Analytics (local)] Unhandled KeyError on GET /api/v1/finance/mrr")
    assert "Tenant: CLI-001" in text and "backend/db_manager.py:812 in get_mrr" in text


@pytest.fixture
def health_server():
    """A local stand-in for a product's /api/v1/status endpoint; set .reply before calling it."""
    state = {"status": 200, "body": {"overall_status": "operational"}}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(state["status"])
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(state["body"]).encode())

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield state, f"http://127.0.0.1:{server.server_port}/api/v1/status"
    server.shutdown()


def test_health_check_reads_eivanta_status(health_server):
    state, url = health_server
    assert products.check_health(url) is None
    state["body"] = {"overall_status": "maintenance", "database_reachable": True}
    assert products.check_health(url) is None  # declared maintenance is not an outage
    state["body"] = {"overall_status": "degraded", "database_reachable": False}
    assert products.check_health(url) == "product reports 'degraded' (database unreachable)"
    state["status"] = 503
    assert products.check_health(url) == "health check returned HTTP 503"
    state["status"] = 404
    assert products.check_health(url).startswith("health check returned HTTP 404: nothing answers at that address")
    assert products.check_health("http://127.0.0.1:9/api/v1/status").startswith("health check failed")


# ---- API -----------------------------------------------------------------------

pytestmark_db = pytest.mark.usefixtures("test_db")


def add_eivanta(client, health_url=None) -> str:
    response = client.post("/api/products", json={"id": "eivanta-analytics", "name": "Eivanta Analytics",
                                                  "environment": "local", "health_url": health_url})
    if response.status_code == 409:
        return client.post("/api/products/eivanta-analytics", json={"rotate_secret": True, "paused": False}).json()["intake_secret"]
    assert response.status_code == 200, response.text
    return response.json()["intake_secret"]


def post_report(client, secret, report, **kw):
    body, headers = signed(secret, report, **kw)
    return client.post("/intake/errors", content=body, headers=headers)


@pytest.mark.usefixtures("test_db")
def test_only_admins_connect_products_and_secrets_are_never_listed(api_client):
    with api_client() as client:
        approver = make_user(client, "pat", "approver")
        assert client.post("/api/products", json={"id": "x-prod", "name": "X"}, headers=approver).status_code == 403
        assert client.post("/api/products", json={"id": "Bad Id!", "name": "X"}).status_code == 400
        secret = add_eivanta(client)
        listed = client.get("/api/products", headers=approver).json()
    assert len(secret) >= 32
    assert "intake_secret" not in json.dumps(listed) and secret not in json.dumps(listed)


@pytest.mark.usefixtures("test_db")
def test_error_report_opens_one_diagnosed_ticket_and_groups_repeats(api_client):
    products._seen_signatures.clear()
    with api_client() as client:
        secret = add_eivanta(client)
        first = post_report(client, secret, sample_report(signature="grp1", tenant="CLI-001"))
        assert first.status_code == 202 and first.json()["status"] == "accepted"
        second = post_report(client, secret, sample_report(signature="grp1", tenant="CLI-002"))
        client.portal.call(notify.drain)
        third = post_report(client, secret, sample_report(signature="grp1", tenant="CLI-001"))
        tickets = [t for t in client.get("/api/tickets").json() if t["alert_key"] == first.json()["alert_key"]]
        audit = client.get("/api/audit", params={"thread_id": tickets[0]["thread_id"]}).json()

    assert second.json()["status"] == "grouped" and third.json()["occurrences"] == 3
    assert len(tickets) == 1
    ticket = tickets[0]
    assert ticket["source"] == "product" and ticket["current_specialist"] == "app_errors"
    assert ticket["status"] == "diagnosed" and ticket["learned"] is False
    assert ticket["occurrences"] == 3 and ticket["tenants"] == ["CLI-001", "CLI-002"]
    assert audit[-1]["actor"] == "product:eivanta-analytics"


@pytest.mark.usefixtures("test_db")
def test_intake_rejects_forged_unknown_paused_malformed_and_oversized(api_client):
    products._seen_signatures.clear()
    with api_client() as client:
        secret = add_eivanta(client)
        assert post_report(client, "wrong-secret", sample_report(signature="f1")).status_code == 401
        assert post_report(client, secret, sample_report(signature="f2"), product_id="nope").status_code == 401
        body, headers = signed(secret, sample_report(signature="f3"))
        assert client.post("/intake/errors", content=body, headers=headers).status_code == 202
        assert client.post("/intake/errors", content=body, headers=headers).status_code == 401  # replay
        other = sample_report(signature="f4"); other["product"] = "someone-else"
        assert post_report(client, secret, other).status_code == 400
        assert post_report(client, secret, {"product": "eivanta-analytics", "pad": "x" * 70000}).status_code == 413
        client.post("/api/products/eivanta-analytics", json={"paused": True})
        assert post_report(client, secret, sample_report(signature="f5")).status_code == 423
        client.post("/api/products/eivanta-analytics", json={"paused": False})
        client.portal.call(notify.drain)
        # The intake endpoint is not reachable with the dashboard's API key alone either
        assert client.post("/intake/errors", json=sample_report()).status_code == 401


@pytest.mark.usefixtures("test_db")
def test_resolved_errors_reopen_when_they_come_back_but_dismissed_ones_stay_quiet(api_client):
    products._seen_signatures.clear()
    with api_client() as client:
        secret = add_eivanta(client)
        post_report(client, secret, sample_report(signature="loop1"))
        client.portal.call(notify.drain)
        first = [t for t in client.get("/api/tickets").json() if t["alert_key"] == "error:eivanta-analytics:loop1"][0]

        requester = make_user(client, "quinn", "requester")
        assert client.post(f"/api/tickets/{first['thread_id']}/close", json={"resolution": "resolved"},
                           headers=requester).status_code == 403
        closed = client.post(f"/api/tickets/{first['thread_id']}/close", json={"resolution": "resolved", "note": "fixed in abc123"}).json()
        assert closed["status"] == "resolved" and closed["learned"] is True

        again = post_report(client, secret, sample_report(signature="loop1"))
        assert again.status_code == 202  # the bug came back: a new ticket
        client.portal.call(notify.drain)
        second = [t for t in client.get("/api/tickets").json() if t["alert_key"] == "error:eivanta-analytics:loop1"
                  and t["thread_id"] != first["thread_id"]][0]
        client.post(f"/api/tickets/{second['thread_id']}/close", json={"resolution": "dismissed"})
        quiet = post_report(client, secret, sample_report(signature="loop1"))
        assert quiet.json()["status"] == "grouped"
        audit = client.get("/api/audit", params={"thread_id": first["thread_id"]}).json()
    assert any(e["action"] == "ticket.closed" and e["details"]["note"] == "fixed in abc123" for e in audit)


@pytest.mark.usefixtures("test_db")
def test_unhealthy_product_opens_a_ticket(api_client, health_server, monkeypatch):
    state, url = health_server
    state["body"] = {"overall_status": "degraded", "database_reachable": False}
    monkeypatch.setattr(monitor, "collect_alerts", lambda: [])
    with api_client() as client:
        add_eivanta(client)
        client.post("/api/products/eivanta-analytics", json={"health_url": url})
        result = client.post("/api/monitor/run").json()
        opened = [o for o in result["opened"] if o["alert_key"] == "health:eivanta-analytics"]
        ticket = client.get(f"/api/tickets/{opened[0]['thread_id']}").json()
        client.post("/api/products/eivanta-analytics", json={"paused": True})
        paused_run = client.post("/api/monitor/run").json()
    assert ticket["current_specialist"] == "app_errors" and ticket["source"] == "monitor"
    assert "database unreachable" in ticket["issue"]
    assert not any(a["key"] == "health:eivanta-analytics" for a in paused_run["alerts"])
