"""Runbook approvals, attack monitoring, reports, compliance evidence and scheduled maintenance."""
from collections import Counter
from datetime import datetime, timezone

import pytest

from src import monitor, scheduler
from tests.conftest import make_user

pytestmark = pytest.mark.usefixtures("test_db")


def test_runbook_needs_one_approval_and_shows_steps(api_client):
    with api_client() as client:
        ticket = client.post("/api/tickets", json={"issue": "please free up disk space"}).json()
        runbooks = client.get("/api/runbooks").json()
        denied = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": False}).json()
    assert ticket["requires_approval"] and "run_runbook" in ticket["last_message"] and "disk_cleanup" in ticket["last_message"]
    assert runbooks["disk_cleanup"]["steps"][1] == "clear_temp_files"
    assert denied["status"] == "denied"


def test_attack_detection_opens_a_block_ip_ticket(api_client, monkeypatch):
    counts = Counter({"203.0.113.9": 42, "198.51.100.4": 3})
    alerts = monitor.check_failed_logins(threshold=20, hours=1, counter=lambda h: counts)
    assert [a.key for a in alerts] == ["attack:203.0.113.9"]
    monkeypatch.setattr(monitor, "collect_alerts", lambda: alerts)
    with api_client() as client:
        opened = client.post("/api/monitor/run").json()["opened"]
        ticket = client.get(f"/api/tickets/{opened[0]['thread_id']}").json()
    assert ticket["current_specialist"] == "remediate" and ticket["requires_approval"]
    assert "block_ip" in ticket["last_message"] and "203.0.113.9" in ticket["last_message"]


def test_reports_summarise_activity(api_client):
    with api_client() as client:
        client.post("/api/tickets", json={"issue": "my computer is slow"})
        pending = client.post("/api/tickets", json={"issue": "please flush my dns"}).json()
        client.post(f"/api/tickets/{pending['thread_id']}/approve", json={"approved": False})
        report = client.get("/api/reports/summary", params={"days": 30}).json()
        requester = make_user(client, "rory", "requester")
        assert client.get("/api/reports/summary", headers=requester).status_code == 403
    assert report["total"] >= 2 and report["resolved"] >= 1
    assert report["hands_free_resolved"] >= 1 and report["denials"] >= 1
    assert report["median_approval_wait_minutes"] is not None
    assert report["estimated_hours_saved"] == round(report["resolved"] * 15 / 60, 1)
    assert sum(r["n"] for r in report["by_day"]) == report["total"]


def test_compliance_report_is_an_evidence_document(api_client):
    with api_client() as client:
        result = client.get("/api/reports/compliance").json()
        audit = client.get("/api/audit").json()
    md = result["markdown"]
    assert "# AIDA Compliance Evidence Report" in md and "§164.312(b)" in md
    assert "not a HIPAA certification" in md and "SECURITY SCORE" in md
    assert result["audit"]["ok"] is True
    assert audit[0]["action"] == "report.compliance"


# ---- scheduling -----------------------------------------------------------

def test_next_run_times(monkeypatch):
    monkeypatch.setenv("AIDA_TIMEZONE", "America/Los_Angeles")
    wed_noon_utc = datetime(2026, 9, 23, 19, 0, tzinfo=timezone.utc)  # Wed 12:00 PDT
    daily = {"frequency": "daily", "weekday": None, "at_time": "02:00"}
    weekly = {"frequency": "weekly", "weekday": 6, "at_time": "02:00"}  # Sunday
    assert scheduler.next_run_after(daily, wed_noon_utc) == datetime(2026, 9, 24, 9, 0, tzinfo=timezone.utc)
    assert scheduler.next_run_after(weekly, wed_noon_utc) == datetime(2026, 9, 27, 9, 0, tzinfo=timezone.utc)
    later = {"frequency": "daily", "weekday": None, "at_time": "13:30"}
    assert scheduler.next_run_after(later, wed_noon_utc) == datetime(2026, 9, 23, 20, 30, tzinfo=timezone.utc)


def test_schedule_validation_and_permissions(api_client):
    with api_client() as client:
        approver = make_user(client, "sam", "approver")
        assert client.post("/api/schedules", json={"name": "x", "runbook": "disk_cleanup"}, headers=approver).status_code == 403
        assert client.post("/api/schedules", json={"name": "x", "runbook": "rm_rf"}).status_code == 400
        assert client.post("/api/schedules", json={"name": "x", "runbook": "disk_cleanup", "at_time": "25:00"}).status_code == 400
        assert client.post("/api/schedules", json={"name": "x", "runbook": "disk_cleanup", "weekday": "funday"}).status_code == 400
        ok = client.post("/api/schedules", json={"name": "Weekly cleanup", "runbook": "disk_cleanup",
                                                 "frequency": "weekly", "weekday": "sunday", "at_time": "02:00"})
        assert ok.status_code == 200
        assert client.post("/api/schedules", json={"name": "Weekly cleanup", "runbook": "disk_cleanup"}).status_code == 409
        listed = client.get("/api/schedules", headers=approver).json()
    assert listed[0]["description"] == "every Sunday at 02:00" and listed[0]["next_run_at"]


def test_scheduled_run_is_ticketed_audited_and_notifies_on_failure(api_client, monkeypatch):
    import main
    from src import notify

    async def fake_runbook(name):
        return f"FAILED: runbook {name} stopped at step 3 of 5.\nStep 3 rotate_logs: FAILED: permission denied"

    sent = []
    monkeypatch.setattr(main, "run_runbook_now", fake_runbook)
    monkeypatch.setattr(notify, "send_in_background", lambda event, summary, thread_id=None: sent.append((event, summary)))
    with api_client() as client:
        schedule = client.post("/api/schedules", json={"name": "Nightly", "runbook": "disk_cleanup",
                                                       "frequency": "daily", "at_time": "03:00"}).json()
        result = client.post(f"/api/schedules/{schedule['id']}/run").json()
        tickets = {t["thread_id"]: t for t in client.get("/api/tickets").json()}
        audit = client.get("/api/audit", params={"thread_id": result["thread_id"]}).json()
        listed = client.get("/api/schedules").json()
    assert result["status"] == "failed"
    ticket = tickets[result["thread_id"]]
    assert ticket["source"] == "schedule" and ticket["status"] == "failed"
    assert audit[0]["actor"] == "schedule:Nightly" and audit[0]["details"]["approved_by"] == "api"
    assert sent and sent[0][0] == "fix_failed"
    assert [s for s in listed if s["name"] == "Nightly"][0]["last_status"] == "failed"


def test_due_schedules(monkeypatch):
    monkeypatch.setenv("AIDA_TIMEZONE", "UTC")
    created = datetime(2026, 9, 20, 0, 0, tzinfo=timezone.utc)
    sched = {"enabled": True, "frequency": "daily", "weekday": None, "at_time": "02:00",
             "last_run_at": None, "created_at": created}
    assert not scheduler.due(sched, datetime(2026, 9, 20, 1, 59, tzinfo=timezone.utc))
    assert scheduler.due(sched, datetime(2026, 9, 20, 2, 0, tzinfo=timezone.utc))
    sched["last_run_at"] = datetime(2026, 9, 20, 2, 0, 5, tzinfo=timezone.utc)
    assert not scheduler.due(sched, datetime(2026, 9, 20, 23, 0, tzinfo=timezone.utc))
    sched["enabled"] = False
    assert not scheduler.due(sched, datetime(2026, 9, 25, tzinfo=timezone.utc))
