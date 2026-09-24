"""Proactive monitoring: checks detect problems and open (deduplicated) tickets."""
import subprocess
from types import SimpleNamespace

import pytest

from src import monitor


# ---- individual checks --------------------------------------------------------

def test_disk_check_alerts_only_above_threshold(monkeypatch):
    usage = SimpleNamespace(total=100 * 1024**3, used=95 * 1024**3, free=5 * 1024**3)
    monkeypatch.setattr(monitor.shutil, "disk_usage", lambda path: usage)
    alerts = monitor.check_disks(["/"], threshold_pct=90)
    assert [a.key for a in alerts] == ["disk:/"]
    assert "95% full" in alerts[0].issue
    assert monitor.check_disks(["/"], threshold_pct=96) == []


def test_memory_check(tmp_path):
    meminfo = tmp_path / "meminfo"
    meminfo.write_text("MemTotal: 16000000 kB\nMemFree: 100000 kB\nMemAvailable: 800000 kB\n")
    assert [a.key for a in monitor.check_memory(10, str(meminfo))] == ["memory"]
    assert monitor.check_memory(4, str(meminfo)) == []


def test_load_check():
    assert monitor.check_load(2.0, loadavg=(9, 9, 9), cpus=4)[0].key == "load"
    assert monitor.check_load(2.0, loadavg=(1, 1, 1), cpus=4) == []


def test_failed_services_check():
    fake = lambda *a, **k: SimpleNamespace(stdout="nginx.service loaded failed failed Web server\nfoo.mount loaded failed failed x\n")
    alerts = monitor.check_failed_services(runner=fake)
    assert [a.key for a in alerts] == ["service:nginx"]


def test_certificate_check():
    days = {"good.example": 90, "soon.example": 5, "dead.example": -2}
    alerts = monitor.check_certificates(list(days), days=14, days_left=lambda host, port: days[host])
    by_key = {a.key: a.issue for a in alerts}
    assert set(by_key) == {"cert:soon.example:443", "cert:dead.example:443"}
    assert "EXPIRED" in by_key["cert:dead.example:443"]


# ---- opening tickets --------------------------------------------------------

@pytest.mark.usefixtures("test_db")
def test_monitoring_opens_one_ticket_per_problem(api_client, monkeypatch):
    alert = monitor.Alert(key="disk:/", check="disk",
                          issue=f"{monitor.AUTO_PREFIX} The disk at / is 97% full (1.0 GB free of 50.0 GB).")
    monkeypatch.setattr(monitor, "collect_alerts", lambda: [alert])

    with api_client() as client:
        first = client.post("/api/monitor/run").json()
        assert len(first["opened"]) == 1
        thread_id = first["opened"][0]["thread_id"]

        ticket = client.get(f"/api/tickets/{thread_id}").json()
        assert ticket["source"] == "monitor" and ticket["alert_key"] == "disk:/"
        assert ticket["current_specialist"] == "os_diag"

        # Same problem again: recorded but no duplicate ticket
        second = client.post("/api/monitor/run").json()
        assert second["opened"] == [] and second["suppressed"] == ["disk:/"]

        status = client.get("/api/monitor/status").json()
        assert status["alerts"][0]["key"] == "disk:/"

        audit = client.get("/api/audit", params={"thread_id": thread_id}).json()
        oldest = audit[-1]  # newest first
        assert oldest["actor"] == "monitor" and oldest["action"] == "ticket.created"
