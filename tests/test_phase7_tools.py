"""More fixes, firewall blocking, runbooks, vulnerability scan and compliance checks (no system changes)."""
import json
import os

import pytest

import mcp_server


def fake_bin(tmp_path, monkeypatch, scripts: dict):
    """Put fake commands first on PATH so tools never touch the real system."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in scripts.items():
        path = bin_dir / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return bin_dir


@pytest.mark.parametrize("address,reason", [
    ("not-an-ip", "not a valid IP"),
    ("127.0.0.1", "loopback"),
    ("::1", "loopback"),
    ("0.0.0.0", "loopback/unspecified"),
])
def test_block_ip_refuses_dangerous_targets(address, reason):
    result = mcp_server.block_ip(address)
    assert result.startswith("REFUSED") and reason in result


def test_block_ip_refuses_this_machines_own_address(monkeypatch):
    monkeypatch.setattr(mcp_server, "_this_hosts_addresses", lambda: {"192.0.2.10"})
    assert "own addresses" in mcp_server.block_ip("192.0.2.10")


def test_block_ip_uses_ufw_with_sudo(tmp_path, monkeypatch):
    log = tmp_path / "calls.log"
    fake_bin(tmp_path, monkeypatch, {
        "ufw": 'echo "ERROR: You need to be root" >&2; exit 1',
        "sudo": f'printf "%s\\n" "$*" >> {log}; exit 0',
    })
    monkeypatch.setattr(mcp_server, "_this_hosts_addresses", lambda: set())
    result = mcp_server.block_ip("203.0.113.9")
    assert result.startswith("SUCCESS") and "with sudo" in result
    assert log.read_text().strip() == "-n ufw insert 1 deny from 203.0.113.9"


def test_block_ip_explains_how_to_allow_it(tmp_path, monkeypatch):
    fake_bin(tmp_path, monkeypatch, {"ufw": "exit 1", "sudo": 'echo "a password is required" >&2; exit 1'})
    monkeypatch.setattr(mcp_server, "_this_hosts_addresses", lambda: set())
    result = mcp_server.block_ip("203.0.113.9")
    assert result.startswith("FAILED") and "NOPASSWD: /usr/sbin/ufw insert 1 deny from 203.0.113.9" in result


def test_restart_container_validates_names(tmp_path, monkeypatch):
    fake_bin(tmp_path, monkeypatch, {
        "docker": 'case "$1" in ps) echo "web\\ndb";; restart) echo "$2";; inspect) echo running;; esac',
    })
    assert mcp_server.restart_container("web; rm -rf /").startswith("REFUSED")
    assert "no container named 'cache'" in mcp_server.restart_container("cache")
    assert mcp_server.restart_container("web") == "SUCCESS: restarted container web; it is running."


def test_docker_prune_reports_reclaimed_space(tmp_path, monkeypatch):
    fake_bin(tmp_path, monkeypatch, {"docker": 'echo "Deleted Containers:\\nabc\\n\\nTotal reclaimed space: 1.2GB"'})
    assert mcp_server.docker_prune() == "SUCCESS: Docker cleanup finished. Reclaimed 1.2GB space."


def test_runbook_stops_at_first_failure():
    calls = []

    def step(name, result):
        def run(**kwargs):
            calls.append(name)
            return result
        return run

    functions = {
        "check_disk_usage": step("check", "Disk usage for /: 90% full"),
        "clear_temp_files": step("clear", "SUCCESS: deleted 3 file(s)"),
        "rotate_logs": step("rotate", "FAILED: could not rotate logs"),
        "docker_prune": step("prune", "SUCCESS"),
    }
    result = mcp_server.run_runbook_steps("disk_cleanup", functions)
    assert result.startswith("FAILED: runbook disk_cleanup stopped at step 3 of 5.")
    assert calls == ["check", "clear", "rotate"]  # docker_prune never ran
    assert mcp_server.run_runbook_steps("nope").startswith("REFUSED")


def test_runbook_tool_description_lists_runbooks():
    for name in mcp_server.RUNBOOKS:
        assert name in mcp_server.run_runbook.__doc__


def test_vulnerability_scan_parses_pip_audit(monkeypatch):
    report = {"dependencies": [
        {"name": "requests", "version": "2.0.0", "vulns": [{"id": "GHSA-xxxx", "fix_versions": ["2.32.0"]}]},
        {"name": "fastapi", "version": "0.141.1", "vulns": []},
    ]}

    def fake_run(cmd, timeout=10):
        if cmd[:2] == ["apt", "list"]:
            return True, "Listing...\nopenssl/noble-security 3.0.13 amd64 [upgradable from: 3.0.10]\nvim/noble 9.1 amd64"
        return True, json.dumps(report)

    monkeypatch.setattr(mcp_server, "_run_status", fake_run)
    result = mcp_server.scan_vulnerabilities()
    assert "1 with pending SECURITY updates: openssl" in result
    assert "requests 2.0.0: GHSA-xxxx (fixed in 2.32.0)" in result


def test_compliance_checks_are_mapped_to_citations():
    checks = mcp_server.run_compliance_checks()
    assert {c["status"] for c in checks} <= {"pass", "fail", "unknown"}
    citations = {c["citation"] for c in checks}
    assert {"164.312(a)(2)(iv)", "164.312(b)", "164.312(a)(2)(iii)", "164.308(a)(5)(ii)(D)"} <= citations
    text = mcp_server.compliance_check()
    assert "not a certification or legal advice" in text
    assert json.loads(mcp_server.compliance_check("json"))[0]["safeguard"]
