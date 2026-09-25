"""Phase 9: other machines over SSH. A fake `ssh` runs the "remote" tool server locally, so the whole path
(SSH command line -> MCP over stdio -> tool server) is exercised without a second computer."""
import os
import sys
from pathlib import Path

import psycopg
import pytest

from src import machines, monitor
from tests.conftest import TEST_DB_URI, make_user

REPO = Path(__file__).resolve().parent.parent
AGENT = f"{sys.executable} {REPO / 'mcp_server.py'}"


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    """`ssh ... -- host command...`: hosts starting with 'unreachable' fail like a machine that is off;
    anything else runs the command here. Every call is logged."""
    log = tmp_path / "ssh.log"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ssh = bin_dir / "ssh"
    ssh.write_text(f"""#!{sys.executable}
import os, sys
args = sys.argv[1:]
i = args.index("--")
host, command = args[i + 1], args[i + 2:]
with open({str(log)!r}, "a") as f:
    f.write(host + " " + " ".join(command) + "\\n")
if host.split("@")[-1].startswith("unreachable"):
    sys.stderr.write(f"ssh: connect to host {{host}} port 22: Connection refused\\n")
    sys.exit(255)
os.execvp(command[0], command)
""")
    ssh.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return log


@pytest.fixture
def clean_machines():
    """Machines live in the database and in module state: leave neither behind for other tests."""
    yield
    with psycopg.connect(TEST_DB_URI, autocommit=True) as conn:
        conn.execute("DELETE FROM aida_machines")
    machines.set_registry([])
    machines.status.clear()
    machines.forget_tools()


# ---- validation (nothing can be injected into the SSH command) ---------------------------

@pytest.mark.parametrize("target", ["-oProxyCommand=touch /tmp/x", "user@host;rm -rf ~", "user@-host", "a b", ""])
def test_bad_ssh_targets_are_refused(target):
    assert machines.validate(ssh_target=target) is not None


@pytest.mark.parametrize("command", ["python3 mcp_server.py; rm -rf ~", "$(reboot)", "-oX python", "a|b", "`id`", ""])
def test_bad_remote_commands_are_refused(command):
    assert machines.validate(remote_command=command) is not None


def test_good_values_and_ssh_command_shape():
    assert machines.validate("office-laptop", "guito@192.168.1.50", 22,
                             "env AIDA_RESTARTABLE_SERVICES=nginx,cron aida-agent/venv/bin/python aida-agent/mcp_server.py") is None
    assert machines.validate("local") is not None  # reserved for this computer
    args = machines.ssh_args({"ssh_port": 2222, "ssh_target": "ops@server", "remote_command": "python3 a.py"})
    assert args[args.index("--") + 1:] == ["ops@server", "python3", "a.py"]  # target can never be read as an option
    assert "BatchMode=yes" in args


def test_connection_errors_are_explained():
    assert "accept its host key" in machines.explain_failure(RuntimeError("Host key verification failed."))
    assert "aida_ed25519.pub" in machines.explain_failure(RuntimeError("Permission denied (publickey)."))
    assert "is it on" in machines.explain_failure(RuntimeError("connect to host x port 22: Connection refused"))


# ---- through the API ----------------------------------------------------------------------

def add(client, machine_id, target="ops@laptop", command=AGENT, name=None):
    response = client.post("/api/machines", json={"id": machine_id, "name": name or machine_id.title(),
                                                  "ssh_target": target, "remote_command": command})
    assert response.status_code == 200, response.text


def test_only_admins_manage_machines_and_requesters_see_no_ssh_details(api_client, fake_ssh, clean_machines):
    with api_client() as client:
        approver = make_user(client, "mach-approver", "approver")
        requester = make_user(client, "mach-requester", "requester")
        body = {"id": "laptop", "name": "Laptop", "ssh_target": "ops@laptop", "remote_command": AGENT}
        assert client.post("/api/machines", json=body, headers=approver).status_code == 403
        assert client.post("/api/machines", json={**body, "ssh_target": "-oProxyCommand=x"}).status_code == 400
        add(client, "laptop")
        assert client.post("/api/machines", json=body).status_code == 409
        seen = {m["id"]: m for m in client.get("/api/machines", headers=requester).json()}
        assert set(seen) == {"local", "laptop"} and "ssh_target" not in seen["laptop"]
        assert client.get("/api/machines").json()[1]["ssh_target"] == "ops@laptop"  # admin sees details
        audit = client.get("/api/audit", params={"limit": 20}).json()
        assert any(e["action"] == "machine.added" and e["details"]["machine"] == "laptop" for e in audit)


def test_test_connection(api_client, fake_ssh, clean_machines):
    with api_client() as client:
        add(client, "laptop")
        add(client, "gone", target="ops@unreachable-box")
        ok = client.post("/api/machines/laptop/test").json()
        assert ok["ok"] and ok["tools"] >= 30 and "OS:" in ok["system_info"] and ok["missing_tools"] == []
        bad = client.post("/api/machines/gone/test").json()
        assert not bad["ok"] and "is it on" in bad["error"]


def test_ticket_runs_its_tools_on_the_chosen_machine(api_client, fake_ssh, clean_machines):
    with api_client() as client:
        add(client, "laptop", name="Office laptop")
        ticket = client.post("/api/tickets", json={"issue": "my disk is nearly full", "machine": "laptop"}).json()
        assert ticket["machine"] == "laptop" and ticket["issue"].startswith("[On Office laptop] ")
        assert "Disk usage for /" in ticket["last_message"]
        assert "ops@laptop" in fake_ssh.read_text()  # the tool really went over "SSH"

        # A ticket for this computer never touches SSH
        calls_before = fake_ssh.read_text()
        local = client.post("/api/tickets", json={"issue": "my disk is nearly full"}).json()
        assert local["machine"] == "local" and fake_ssh.read_text() == calls_before

        listed = {t["thread_id"]: t for t in client.get("/api/tickets").json()}
        assert listed[ticket["thread_id"]]["machine"] == "laptop"

        client.post("/api/machines/laptop", json={"enabled": False})
        refused = client.post("/api/tickets", json={"issue": "slow", "machine": "laptop"})
        assert refused.status_code == 400


def test_approved_fix_runs_on_the_ticket_machine(api_client, fake_ssh, clean_machines):
    with api_client() as client:
        add(client, "server")
        ticket = client.post("/api/tickets", json={"issue": "please flush the dns cache", "machine": "server"}).json()
        assert ticket["requires_approval"]
        assert not fake_ssh.exists()  # nothing runs on the machine before approval
        done = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": True}).json()
        assert "flush" in done["last_message"].lower()
        assert "ops@laptop" in fake_ssh.read_text()  # the approved fix ran over SSH
        audit = client.get("/api/audit", params={"thread_id": ticket["thread_id"]}).json()
        approved = next(e for e in audit if e["action"] == "remediation.approved")
        assert approved["details"]["machine"] == "server"


def test_monitoring_checks_other_machines(api_client, fake_ssh, clean_machines, monkeypatch):
    monkeypatch.setattr(monitor, "collect_alerts", lambda: [])  # only the other machines matter here
    remote = ("env AIDA_MONITOR_DISK_PCT=0 AIDA_MONITOR_WINDOWS=off AIDA_MONITOR_FAILED_LOGINS=1000000 "
              f"AIDA_MONITOR_LOAD_FACTOR=100000 AIDA_MONITOR_MEM_PCT=0 {AGENT}")
    with api_client() as client:
        add(client, "laptop", command=remote, name="Laptop")
        add(client, "gone", target="ops@unreachable-box", name="Old server")
        result = client.post("/api/monitor/run").json()
        by_key = {a["key"]: a for a in result["alerts"]}
        disk = by_key["laptop/disk:/"]
        assert disk["machine"] == "laptop" and "[Laptop]" in disk["issue"]
        down = by_key["gone/unreachable"]
        assert down["machine"] is None and "could not be checked" in down["issue"]

        opened = {o["alert_key"]: o["thread_id"] for o in result["opened"]}
        assert client.get(f"/api/tickets/{opened['laptop/disk:/']}").json()["machine"] == "laptop"
        assert client.get(f"/api/tickets/{opened['gone/unreachable']}").json()["machine"] == "local"

        status = client.get("/api/monitor/status").json()
        machine_status = {m["id"]: m for m in status["machines"]}
        assert machine_status["laptop"]["ok"] and not machine_status["gone"]["ok"]

        # Same problems again: no duplicate tickets
        again = client.post("/api/monitor/run").json()
        assert again["opened"] == [] and {"laptop/disk:/", "gone/unreachable"} <= set(again["suppressed"])


def test_tools_refuse_unknown_machines():
    import asyncio

    class Tool:
        name, description, args_schema = "ping_host", "Ping", {"type": "object", "properties": {}}

        async def ainvoke(self, args):
            return "local result"

    wrapped = machines.wrap_tools([Tool()])[0]
    assert asyncio.run(wrapped.ainvoke({})) == "local result"
    token = machines.current_machine.set("nowhere")
    try:
        assert asyncio.run(wrapped.ainvoke({})).startswith("FAILED: machine 'nowhere' is not connected")
    finally:
        machines.current_machine.reset(token)


def test_aida_uses_its_own_ssh_key_when_present(tmp_path, monkeypatch):
    machine = {"ssh_port": 22, "ssh_target": "ops@pc", "remote_command": machines.DEFAULT_REMOTE_COMMAND}
    monkeypatch.setenv("AIDA_SSH_KEY", str(tmp_path / "missing_key"))
    assert "-i" not in machines.ssh_args(machine)  # no key yet: SSH's normal keys/agent
    key = tmp_path / "aida_ed25519"
    key.write_text("private key")
    monkeypatch.setenv("AIDA_SSH_KEY", str(key))
    args = machines.ssh_args(machine)
    assert args[args.index("-i") + 1] == str(key) and "IdentitiesOnly=yes" in args
    assert args.index("-i") < args.index("--")  # options always before the target
    assert machines.validate(remote_command=machines.DEFAULT_REMOTE_COMMAND) is None
