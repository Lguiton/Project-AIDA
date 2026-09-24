"""Tamper-evident audit log: every action is recorded, the chain verifies, and edits are detected."""
import psycopg
import pytest

pytestmark = pytest.mark.usefixtures("test_db")


def create(client, issue):
    response = client.post("/api/tickets", json={"issue": issue}, headers={"X-AIDA-Actor": "alice"})
    assert response.status_code == 200, response.text
    return response.json()


def test_actions_are_recorded_with_who_did_them(api_client):
    with api_client() as client:
        ticket = create(client, "please flush my dns")
        client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": False},
                    headers={"X-AIDA-Actor": "bob"})
        entries = client.get("/api/audit", params={"thread_id": ticket["thread_id"]}).json()

    actions = [(e["actor"], e["action"]) for e in reversed(entries)]
    assert actions == [
        ("alice", "ticket.created"),
        ("agent:remediate", "remediation.requested"),
        ("bob", "remediation.denied"),
    ]
    assert entries[0]["details"]["tools"][0]["name"] == "flush_dns_cache"  # newest first


def test_executed_fix_records_the_tool_result(api_client):
    with api_client() as client:
        ticket = create(client, "clear my temp files")
        client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": True})
        entries = client.get("/api/audit", params={"thread_id": ticket["thread_id"]}).json()
    executed = next(e for e in entries if e["action"] == "remediation.executed")
    assert executed["details"]["results"][0]["tool"] == "clear_temp_files"
    assert "SUCCESS" in executed["details"]["results"][0]["result"]
    assert any(e["action"] == "remediation.approved" for e in entries)


def test_chain_verifies_and_blocks_changes(api_client, test_db):
    with api_client() as client:
        create(client, "my computer is slow")
        assert client.get("/api/audit/verify").json()["ok"] is True

    with psycopg.connect(test_db, autocommit=True) as conn:
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("UPDATE aida_audit SET actor = 'mallory'")
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("DELETE FROM aida_audit")
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("TRUNCATE aida_audit")


def test_tampering_is_detected(api_client, test_db):
    with api_client() as client:
        create(client, "my computer is slow")
        create(client, "which ports are open")

    # Simulate an attacker with database admin rights who bypasses the trigger and edits history
    with psycopg.connect(test_db, autocommit=True) as conn:
        conn.execute("ALTER TABLE aida_audit DISABLE TRIGGER aida_audit_no_change")
        try:
            target = conn.execute("SELECT min(id) FROM aida_audit").fetchone()[0]
            conn.execute("UPDATE aida_audit SET actor = 'mallory' WHERE id = %s", (target,))
        finally:
            conn.execute("ALTER TABLE aida_audit ENABLE TRIGGER aida_audit_no_change")

    with api_client() as client:
        result = client.get("/api/audit/verify").json()
    assert result["ok"] is False
    assert result["first_bad_id"] == target

    # Leave a clean log for other tests
    with psycopg.connect(test_db, autocommit=True) as conn:
        conn.execute("DROP TABLE aida_audit")
