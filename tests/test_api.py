"""End-to-end API tests: real FastAPI app, real MCP server, real Postgres (aida_test), fake AI model."""
import os
import time

import pytest

pytestmark = pytest.mark.usefixtures("test_db")


def create(client, issue):
    response = client.post("/api/tickets", json={"issue": issue})
    assert response.status_code == 200, response.text
    return response.json()


def test_api_requires_key(api_client):
    with api_client(api_key=None) as client:
        assert client.get("/api/tickets").status_code == 401
    with api_client(api_key="wrong-key") as client:
        assert client.get("/api/metrics").status_code == 401
        assert client.post("/api/tickets", json={"issue": "x"}).status_code == 401
    with api_client() as client:
        assert client.get("/api/tickets").status_code == 200


def test_deny_closes_ticket_without_running_tool(api_client):
    with api_client() as client:
        ticket = create(client, "please flush my dns")
        assert ticket["requires_approval"] is True
        assert "flush_dns_cache" in ticket["last_message"]

        denied = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": False}).json()
        assert denied["status"] == "denied"
        assert denied["requires_approval"] is False
        assert "was not run" in denied["last_message"]
        assert denied["learned"] is False

        # A denied ticket can no longer be approved
        again = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": True})
        assert again.status_code == 400


def test_pending_approval_survives_restart_then_approve_runs_tool(api_client, temp_dir_for_tools):
    old = temp_dir_for_tools / "stale.tmp"
    old.write_text("old")
    week_ago = time.time() - 7 * 86400
    os.utime(old, (week_ago, week_ago))

    # Safety: the tool server must be pointed at the test folder, never the real temp directory
    import main
    assert main.tool_server_env().get("AIDA_TEMP_DIR") == str(temp_dir_for_tools)

    with api_client() as client:
        ticket = create(client, "clear my temp files")
        assert ticket["requires_approval"] is True
    assert old.exists()  # nothing runs before approval

    # "Restart" the backend: a brand-new app start reads the ticket back from Postgres
    with api_client() as client:
        listed = {t["thread_id"]: t for t in client.get("/api/tickets").json()}
        assert listed[ticket["thread_id"]]["requires_approval"] is True

        approved = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": True}).json()
        assert approved["status"] == "resolved"
        assert "deleted 1 file(s)" in approved["last_message"]
    assert not old.exists()


def test_resolved_tickets_are_learned_once(api_client):
    with api_client() as client:
        before = client.get("/api/metrics").json()

        resolved = create(client, "my computer is slow")
        assert resolved["status"] == "resolved"
        assert resolved["learned"] is True

        # Reading the ticket again must not add it a second time
        client.get(f"/api/tickets/{resolved['thread_id']}")

        knowledge = create(client, "BSOD after driver update")
        assert knowledge["current_specialist"] == "knowledge"
        assert knowledge["learned"] is False  # answers from the KB are not re-learned

        after = client.get("/api/metrics").json()
        assert after["kb_records"] == before["kb_records"] + 1
        assert after["tickets_learned"] == before["tickets_learned"] + 1


def test_metrics_report_live_numbers(api_client):
    with api_client() as client:
        create(client, "please flush my dns")
        metrics = client.get("/api/metrics").json()
    assert metrics["agent_count"] == 6
    assert set(metrics["agents"]) == {"knowledge", "network", "os_diag", "remediate", "security", "triage"}
    assert metrics["pending_approvals"] >= 1
    assert metrics["kb_online"] is True


def test_tool_server_gets_settings_but_not_secrets(monkeypatch):
    import main
    monkeypatch.setenv("AIDA_TEMP_DIR", "/some/where")
    env = main.tool_server_env()
    assert env["AIDA_TEMP_DIR"] == "/some/where"
    assert "AIDA_API_KEY" not in env and "OPENAI_API_KEY" not in env and "AIDA_UI_PASSWORD" not in env
    assert "PATH" in env


def test_refused_remediation_is_failed_not_resolved_or_learned(api_client):
    with api_client() as client:
        ticket = create(client, "restart the service please")
        result = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": True}).json()
    assert result["status"] == "failed"
    assert "REFUSED" in result["last_message"]
    assert result["learned"] is False


def test_remediation_without_a_tool_is_needs_info_and_not_learned(api_client):
    with api_client() as client:
        ticket = create(client, "please do some vague fix")
    assert ticket["current_specialist"] == "remediate"
    assert ticket["status"] == "needs_info"
    assert ticket["learned"] is False


def test_forget_removes_ticket_from_knowledge_base_for_good(api_client):
    with api_client() as client:
        ticket = create(client, "my computer is slow")
        assert ticket["learned"] is True
        before = client.get("/api/metrics").json()["kb_records"]

        forgot = client.post(f"/api/tickets/{ticket['thread_id']}/forget")
        assert forgot.status_code == 200
        assert client.get("/api/metrics").json()["kb_records"] == before - 1

        # Reading the ticket again must not re-learn it
        again = client.get(f"/api/tickets/{ticket['thread_id']}").json()
        assert again["learned"] is False and again["forgotten"] is True
        assert client.get("/api/metrics").json()["kb_records"] == before - 1

        assert client.post("/api/tickets/not-a-ticket/forget").status_code == 404


def test_startup_repairs_tickets_learned_without_a_fix(api_client):
    """Tickets learned by older versions (a question marked resolved) are cleaned up when the API starts."""
    from langchain_core.messages import AIMessage, HumanMessage

    import main
    from src.kb.learn import learn_from_ticket

    with api_client() as client:
        # Recreate the old bad state: a remediation question stored as resolved and learned
        thread_id = "legacy-question-ticket"
        config = {"configurable": {"thread_id": thread_id}}
        client.portal.call(main.aida_graph.aupdate_state, config, {
            "messages": [HumanMessage(content="Clear my temp files"),
                         AIMessage(content="How many days old should the files be?")],
            "current_specialist": "remediate", "ticket_status": "resolved",
        }, "remediate")
        client.portal.call(learn_from_ticket, thread_id, "Clear my temp files", "remediate",
                           "How many days old should the files be?")

        async def mark_learned():
            async with main.db_pool.connection() as conn:
                await conn.execute(
                    "INSERT INTO aida_tickets (thread_id, issue, status, current_specialist, learned) "
                    "VALUES (%s, 'Clear my temp files', 'resolved', 'remediate', TRUE) "
                    "ON CONFLICT (thread_id) DO UPDATE SET learned = TRUE, forgotten = FALSE, status = 'resolved'",
                    (thread_id,))
        client.portal.call(mark_learned)
        before = client.get("/api/metrics").json()["kb_records"]

    # Restart: the repair runs at startup
    with api_client() as client:
        after = client.get("/api/metrics").json()["kb_records"]
        ticket = client.get(f"/api/tickets/{thread_id}").json()
    assert after == before - 1
    assert ticket["status"] == "needs_info"
    assert ticket["learned"] is False and ticket["forgotten"] is True


def test_security_reports_are_not_learned(api_client):
    with api_client() as client:
        report = create(client, "run a security health check")
    assert report["current_specialist"] == "security"
    assert "SECURITY SCORE" in report["last_message"]
    assert report["status"] == "resolved" and report["learned"] is False
