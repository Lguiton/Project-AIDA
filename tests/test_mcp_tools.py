"""Unit tests for the diagnostic and remediation tools in mcp_server.py (safe: nothing on your system is changed)."""
import os
import subprocess
import sys
import time

import pytest

import mcp_server


@pytest.mark.parametrize("address,expected", [
    ("[::]", "all interfaces"),
    ("*", "all interfaces"),
    ("0.0.0.0", "all IPv4 interfaces"),
    ("127.0.0.53%lo", "localhost only"),
    ("[::1]", "localhost only"),
    ("192.168.1.5", "specific address 192.168.1.5"),
])
def test_bind_addresses_are_described_in_plain_words(address, expected):
    assert expected in mcp_server._describe_bind_address(address)


def test_top_processes_excludes_aida_and_measures_cpu():
    # A process whose command line mentions mcp_server.py must be hidden from the results
    decoy = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)", "mcp_server.py"])
    try:
        time.sleep(0.3)
        output = mcp_server.list_top_processes(limit=25)
    finally:
        decoy.kill()
    assert "CPU measured over 1s" in output
    assert str(decoy.pid) not in output
    assert "AIDA diagnostic process(es) excluded" in output


def test_restart_service_refuses_services_not_on_allowlist(monkeypatch):
    monkeypatch.setenv("AIDA_RESTARTABLE_SERVICES", "cron")
    result = mcp_server.restart_service("sshd")
    assert result.startswith("REFUSED")
    assert "Nothing was restarted" in result


def test_restart_service_rejects_injection_attempts(monkeypatch):
    monkeypatch.setenv("AIDA_RESTARTABLE_SERVICES", "cron")
    assert mcp_server.restart_service("cron; rm -rf /").startswith("REFUSED")


def test_check_service_status_rejects_bad_names():
    assert mcp_server.check_service_status("x; reboot").startswith("Invalid service name")


def test_clear_temp_files_only_deletes_old_files_owned_by_user(temp_dir_for_tools):
    old_file = temp_dir_for_tools / "old.log"
    new_file = temp_dir_for_tools / "new.log"
    nested = temp_dir_for_tools / "sub"
    nested.mkdir()
    old_nested = nested / "old.tmp"
    for f in (old_file, new_file, old_nested):
        f.write_text("x" * 2048)
    ten_days_ago = time.time() - 10 * 86400
    os.utime(old_file, (ten_days_ago, ten_days_ago))
    os.utime(old_nested, (ten_days_ago, ten_days_ago))
    # A symlink pointing outside the folder must never be followed or removed
    outside = temp_dir_for_tools.parent / "outside_keep.txt"
    outside.write_text("keep me")
    link = temp_dir_for_tools / "link"
    link.symlink_to(outside)

    result = mcp_server.clear_temp_files(older_than_days=7)

    assert "deleted 2 file(s)" in result
    assert not old_file.exists() and not old_nested.exists()
    assert new_file.exists()
    assert outside.exists() and link.is_symlink()


def test_flush_dns_reports_each_cache(monkeypatch, tmp_path):
    # Fake commands: resolvectl is denied (and sudo needs a password), Windows ipconfig succeeds
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scripts = {
        "resolvectl": 'echo "Access denied" >&2; exit 1',
        "sudo": 'echo "a password is required" >&2; exit 1',
        "ipconfig.exe": 'echo "Successfully flushed the DNS Resolver Cache."',
    }
    for name, body in scripts.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")

    result = mcp_server.flush_dns_cache()

    assert result.startswith("SUCCESS: flushed 1 of 2")
    assert "NOT FLUSHED: Linux resolver cache" in result
    assert "sudoers rule" in result
    assert "FLUSHED: Windows DNS client cache" in result


def test_sshd_settings_use_first_value_and_includes(tmp_path):
    conf_d = tmp_path / "sshd_config.d"
    conf_d.mkdir()
    (conf_d / "50-cloud.conf").write_text("PasswordAuthentication no\n")
    main = tmp_path / "sshd_config"
    main.write_text(f"Include {conf_d}/*.conf\n# comment\nPermitRootLogin yes\nPasswordAuthentication yes\n"
                    "Match User bob\n  PermitRootLogin no\n")
    settings = mcp_server._sshd_settings(str(main))
    assert settings["passwordauthentication"] == "no"   # first value wins (from the include)
    assert settings["permitrootlogin"] == "yes"          # Match block ignored


def test_security_score_and_report_format(monkeypatch):
    findings = [
        {"severity": "critical", "title": "a", "detail": "", "fix": "x"},
        {"severity": "medium", "title": "b", "detail": "", "fix": ""},
        {"severity": "info", "title": "c", "detail": "", "fix": ""},
    ]
    assert mcp_server.security_score(findings) == 100 - 30 - 7
    monkeypatch.setattr(mcp_server, "run_security_checks", lambda: findings)
    report = mcp_server.security_audit()
    assert report.startswith("SECURITY SCORE: 63/100 (2 issue(s) found)")
    assert report.index("[CRITICAL]") < report.index("[MEDIUM]") < report.index("[INFO]")


def test_security_checks_run_on_this_machine():
    findings = mcp_server.run_security_checks()
    assert findings and all(f["severity"] in mcp_server.SEVERITY_PENALTY for f in findings)


def test_failed_logins_are_counted_per_ip(monkeypatch):
    log = ("sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n"
           "sshd[2]: Invalid user admin from 203.0.113.9 port 22\n"
           "sshd[3]: Failed password for bob from 198.51.100.4 port 22 ssh2\n")
    monkeypatch.setattr(mcp_server, "_run_status", lambda *a, **k: (True, log))
    counts, source = mcp_server._failed_logins(24)
    assert counts == {"203.0.113.9": 2, "198.51.100.4": 1}
    report = mcp_server.list_failed_logins(24)
    assert "3 failed login attempt(s)" in report and "203.0.113.9: 2" in report
