"""Windows side of the PC (Phase 8): a fake powershell.exe stands in for Windows, so nothing real is touched."""
import json
import sys

import pytest

import mcp_server
from src import monitor, windows


def fake_powershell(tmp_path, monkeypatch, responses: dict):
    """responses: {text found in the script: (stdout, exit code)}. Every decoded script is logged."""
    (tmp_path / "responses.json").write_text(json.dumps(responses))
    log = tmp_path / "scripts.log"
    exe = tmp_path / "powershell.exe"
    exe.write_text(f"""#!{sys.executable}
import base64, json, sys
args = sys.argv[1:]
script = base64.b64decode(args[args.index("-EncodedCommand") + 1]).decode("utf-16-le")
open({str(log)!r}, "a").write(script + "\\n=====\\n")
for needle, (out, code) in json.load(open({str(tmp_path / "responses.json")!r})).items():
    if needle in script:
        print(out)
        sys.exit(code)
sys.exit(0)
""")
    exe.chmod(0o755)
    monkeypatch.setenv("AIDA_POWERSHELL", str(exe))
    return log


def snap(**overrides):
    base = {
        "computer": "DESKTOP-TEST", "os": "Microsoft Windows 11 Home (build 26100)", "uptime_hours": 30.5,
        "mem_total_mb": 16000, "mem_free_mb": 6000,
        "disks": [{"drive": "C:", "size_gb": 475.0, "free_gb": 120.0}],
        "services": [{"name": "WinDefend", "display": "Microsoft Defender Antivirus Service", "status": "Running", "start": "Automatic"}],
        "defender": {"mode": "Normal", "antivirus": True, "realtime": True, "signature_age_days": 0, "quick_scan_age_days": 2},
        "antivirus_products": ["Windows Defender"],
        "firewall": [{"profile": "Domain", "enabled": True}, {"profile": "Private", "enabled": True}, {"profile": "Public", "enabled": True}],
        "pending_reboot": False, "is_admin": False,
    }
    base.update(overrides)
    return base


def keys(s):
    return [k for k, _, _ in windows.problems(s, disk_pct=90, mem_pct=10)]


# ---- what counts as a problem -----------------------------------------------------

def test_healthy_windows_has_no_problems():
    assert keys(snap()) == []


def test_each_problem_is_detected():
    bad = snap(
        mem_free_mb=800,
        disks=[{"drive": "C:", "size_gb": 100.0, "free_gb": 4.0}, {"drive": "D:", "size_gb": 100.0, "free_gb": 50.0}],
        services=[{"name": "Spooler", "display": "Print Spooler", "status": "Stopped", "start": "Automatic"},
                  {"name": "wuauserv", "display": "Windows Update", "status": "Stopped", "start": "Manual"}],
        defender={"mode": "Normal", "antivirus": True, "realtime": False, "signature_age_days": 9, "quick_scan_age_days": 2},
        firewall=[{"profile": "Public", "enabled": False}, {"profile": "Private", "enabled": True}],
    )
    assert keys(bad) == ["win-disk:C:", "win-memory", "win-service:Spooler", "win-defender:realtime",
                         "win-defender:signatures", "win-firewall:Public"]


def test_antivirus_rules():
    # Another antivirus is in charge: Defender being passive is expected, not an alarm
    passive = snap(defender={"mode": "Passive", "antivirus": False, "realtime": False, "signature_age_days": 30},
                   antivirus_products=["Windows Defender", "Norton 360"])
    assert keys(passive) == []
    # Nothing protecting the PC
    none = snap(defender={"mode": "Normal", "antivirus": False, "realtime": False, "signature_age_days": 0},
                antivirus_products=[])
    assert keys(none) == ["win-defender:none"]
    # Status could not be read: unknown is not reported as "no antivirus"
    assert keys(snap(defender=None, antivirus_products=[])) == []


# ---- monitoring ---------------------------------------------------------------------

def test_monitor_opens_windows_alerts():
    bad = snap(firewall=[{"profile": "Public", "enabled": False}])
    alerts = monitor.check_windows(snapshot=lambda: bad)
    assert [a.key for a in alerts] == ["win-firewall:Public"]
    assert alerts[0].issue.startswith(monitor.AUTO_PREFIX + " [Windows]")


def test_monitor_skips_windows_when_off_or_unreachable(monkeypatch, tmp_path):
    monkeypatch.setenv("AIDA_MONITOR_WINDOWS", "off")
    assert monitor.check_windows() == []
    monkeypatch.setenv("AIDA_MONITOR_WINDOWS", "auto")
    monkeypatch.setenv("AIDA_POWERSHELL", str(tmp_path / "missing.exe"))
    assert monitor.check_windows() == []
    # A Windows failure never breaks monitoring
    def broken():
        raise RuntimeError("WMI is broken")
    assert monitor.check_windows(snapshot=broken) == []


def test_snapshot_through_fake_powershell(tmp_path, monkeypatch):
    log = fake_powershell(tmp_path, monkeypatch, {"Win32_OperatingSystem": (
        "WARNING: something noisy\n" + json.dumps(snap(disks={"drive": "C:", "size_gb": 100.0, "free_gb": 5.0},
                                                       firewall=None)), 0)})
    monkeypatch.setenv("AIDA_MONITOR_WINDOWS", "on")
    monkeypatch.setenv("AIDA_WINDOWS_SERVICES", "Spooler, bad'name, WinDefend")
    alerts = monitor.check_windows()
    assert [a.key for a in alerts] == ["win-disk:C:"]  # one-item array and null handled
    script = log.read_text()
    assert "@('Spooler','WinDefend')" in script and "bad'name" not in script  # invalid names never reach PowerShell


# ---- tools --------------------------------------------------------------------------

def test_windows_health_report(tmp_path, monkeypatch):
    fake_powershell(tmp_path, monkeypatch, {"Win32_OperatingSystem": (json.dumps(snap(pending_reboot=True)), 0)})
    report = mcp_server.windows_health()
    assert "DESKTOP-TEST" in report and "PROBLEMS FOUND: none" in report
    assert "Drive C:" in report and "real-time protection on" in report and "Restart pending (updates): YES" in report


def test_tools_explain_when_windows_is_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("AIDA_POWERSHELL", str(tmp_path / "missing.exe"))
    assert "Windows is not reachable" in mcp_server.windows_health()
    assert mcp_server.windows_defender_scan().startswith("FAILED")


def test_service_names_are_validated():
    assert mcp_server.windows_service_status("Spooler'; Remove-Item C:\\ -Recurse").startswith("REFUSED")
    result = mcp_server.windows_restart_service("WinDefend")
    assert result.startswith("REFUSED") and "allowlist" in result


def test_restart_service_needs_admin(tmp_path, monkeypatch):
    fake_powershell(tmp_path, monkeypatch, {"Restart-Service": ("NOT_ADMIN", 0)})
    result = mcp_server.windows_restart_service("spooler")
    assert result.startswith("FAILED") and "Run as administrator" in result


def test_restart_service_success_and_refusal(tmp_path, monkeypatch):
    log = fake_powershell(tmp_path, monkeypatch, {"Restart-Service": ("STATUS:Running", 0)})
    assert mcp_server.windows_restart_service("Spooler").startswith("SUCCESS")
    assert "Restart-Service -Name 'Spooler'" in log.read_text()
    fake_powershell(tmp_path, monkeypatch, {"Restart-Service": ("ERROR:Access is denied.", 0)})
    assert mcp_server.windows_restart_service("Spooler") == "FAILED: Windows refused to restart Spooler: Access is denied."


def test_defender_scan_and_signatures(tmp_path, monkeypatch):
    log = fake_powershell(tmp_path, monkeypatch, {
        "-SignatureUpdate": (json.dumps({"code": 0, "output": "done", "age": 0, "version": "1.419.1"}), 0),
        "'-Scan'": ("STARTED", 0),
    })
    assert mcp_server.windows_defender_scan().startswith("SUCCESS: started")
    assert "version 1.419.1" in mcp_server.windows_update_signatures()
    assert "-ScanType','1'" in log.read_text()  # quick scan, never a full scan
    fake_powershell(tmp_path, monkeypatch, {"-SignatureUpdate": (json.dumps({"code": 2, "output": "line\nNo network"}), 0)})
    assert mcp_server.windows_update_signatures() == "FAILED: Defender definition update returned code 2: No network"


def test_clear_temp_reports_and_refuses(tmp_path, monkeypatch):
    log = fake_powershell(tmp_path, monkeypatch, {"GetTempPath": (
        json.dumps({"dir": "C:\\Users\\Guito\\AppData\\Local\\Temp\\", "deleted": 12, "mb": 340.5, "skipped": 2}), 0)})
    result = mcp_server.windows_clear_temp(0)
    assert result.startswith("SUCCESS: deleted 12") and "340.5 MB" in result and "skipped 2" in result
    assert "AddDays(-1)" in log.read_text()  # minimum age is 1 day
    fake_powershell(tmp_path, monkeypatch, {"GetTempPath": ("REFUSE:D:\\Temp\\", 0)})
    assert mcp_server.windows_clear_temp(7).startswith("REFUSED")


def test_event_errors_and_updates(tmp_path, monkeypatch):
    fake_powershell(tmp_path, monkeypatch, {
        "Get-WinEvent": (json.dumps({"total": 7, "groups": {"source": "disk", "id": 7, "log": "System", "level": "Error",
                                                              "count": 7, "last": "2026-09-24 08:00", "message": "bad block"}}), 0),
        "Microsoft.Update.Session": (json.dumps({"last_update": "KB5040442 on 2026-09-10", "pending_reboot": False,
                                                 "pending": {"title": "2026-09 Cumulative Update", "severity": "Critical", "security": True}}), 0),
    })
    events = mcp_server.windows_event_errors(24)
    assert "7x Error disk (event 7" in events and "bad block" in events
    updates = mcp_server.windows_update_status()
    assert "1 update(s) waiting" in updates and "[security, Critical]" in updates


def test_windows_runbooks_are_available():
    assert {"windows_cleanup", "windows_security_refresh"} <= set(mcp_server.RUNBOOKS)
    calls = []
    steps = {name: (lambda name=name: (lambda **kw: calls.append(name) or "SUCCESS: ok"))() for name in
             ("windows_update_signatures", "windows_defender_scan")}
    assert mcp_server.run_runbook_steps("windows_security_refresh", steps).startswith("SUCCESS")
    assert calls == ["windows_update_signatures", "windows_defender_scan"]


def test_windows_check_result_is_recorded_for_the_dashboard():
    monitor.check_windows(snapshot=lambda: snap(firewall=[{"profile": "Public", "enabled": False}]))
    assert monitor.windows_status["ok"] is True and monitor.windows_status["problems"] == 1
    assert monitor.windows_status["computer"] == "DESKTOP-TEST"

    def broken():
        raise RuntimeError("Get-CimInstance failed")
    monitor.check_windows(snapshot=broken)
    assert monitor.windows_status["ok"] is False and "Get-CimInstance failed" in monitor.windows_status["error"]
