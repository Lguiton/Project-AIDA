"""
Multiple machines (Phase 9): one AIDA looks after other computers over SSH.

Each extra machine runs a copy of AIDA's tool server (mcp_server.py, "the agent"). AIDA starts it over SSH
for each tool call (MCP's stdio transport works over SSH), so the other machine needs no open ports, no
AIDA database and no AI key: only SSH access with a key, Python 3 and the `mcp` package.
scripts/install_agent.sh copies the agent there and sets it up.

How tickets reach the right machine: every ticket has a `machine` (default "local" = this computer).
While AIDA works on a ticket, the machine id is held in a context variable; the tools the agents see are
thin dispatchers that forward each call to that machine's tool server. Approvals, the audit log and
learning work exactly as before.

Security:
  - SSH runs in batch mode with your own keys: no passwords are stored in AIDA, and a host key that has
    not been accepted yet makes the connection fail instead of trusting it silently.
  - The SSH target and remote command are validated strictly (no leading "-", no shell characters), so
    they cannot inject SSH options or remote shell commands.
  - Only admins can add, change or test machines.
"""
import asyncio
import contextvars
import json
import os
import re
from datetime import datetime, timezone

LOCAL = "local"
current_machine: contextvars.ContextVar[str] = contextvars.ContextVar("aida_machine", default=LOCAL)

DEFAULT_REMOTE_COMMAND = "~/aida-agent/venv/bin/python ~/aida-agent/mcp_server.py"
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_TARGET = re.compile(r"^(?:[A-Za-z0-9._][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_./~][A-Za-z0-9_./~=,:+-]{0,255}$")

MACHINES_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS aida_machines (
        id             TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        ssh_target     TEXT NOT NULL,
        ssh_port       INT NOT NULL DEFAULT 22,
        remote_command TEXT NOT NULL,
        enabled        BOOLEAN NOT NULL DEFAULT TRUE,
        created_by     TEXT NOT NULL,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
)


def validate(machine_id: str | None = None, ssh_target: str | None = None, ssh_port: int | None = None,
             remote_command: str | None = None) -> str | None:
    """An error message, or None when every given field is acceptable."""
    if machine_id is not None and (machine_id == LOCAL or not _ID.match(machine_id)):
        return "Machine id: lowercase letters, digits and dashes (e.g. 'office-laptop'); 'local' is reserved."
    if ssh_target is not None and not _TARGET.match(ssh_target):
        return "SSH target must look like user@host or host (letters, digits, dots, dashes)."
    if ssh_port is not None and not (1 <= int(ssh_port) <= 65535):
        return "SSH port must be between 1 and 65535."
    if remote_command is not None:
        tokens = remote_command.split()
        if not tokens or len(tokens) > 12 or not all(_TOKEN.match(t) for t in tokens):
            return ("Remote command may only contain paths, program names and NAME=value settings separated by "
                    "spaces (no quotes or shell characters).")
    return None


def aida_ssh_key() -> str | None:
    """AIDA's own SSH key (no passphrase, so it can log in unattended): AIDA_SSH_KEY, or ~/.ssh/aida_ed25519.
    Create it with: ssh-keygen -t ed25519 -f ~/.ssh/aida_ed25519 -N "" -C aida"""
    path = os.path.expanduser(os.getenv("AIDA_SSH_KEY") or "~/.ssh/aida_ed25519")
    return path if os.path.isfile(path) else None


def ssh_args(machine: dict) -> list[str]:
    key = aida_ssh_key()
    return [
        "-p", str(int(machine["ssh_port"])),
        *(["-i", key, "-o", "IdentitiesOnly=yes"] if key else []),
        "-o", "BatchMode=yes",            # never prompt for a password or passphrase
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=15",
        "--", machine["ssh_target"], *machine["remote_command"].split(),
    ]


def _ssh_env() -> dict[str, str]:
    """SSH needs HOME and the SSH agent socket; AIDA's secrets are never passed on."""
    secret_markers = ("KEY", "PASSWORD", "SECRET", "TOKEN", "WEBHOOK", "SMTP", "DB_URI")
    return {k: v for k, v in os.environ.items() if not any(m in k.upper() for m in secret_markers)}


# ---- registry -------------------------------------------------------------------

async def ensure_schema(pool) -> None:
    async with pool.connection() as conn:
        for statement in MACHINES_SCHEMA_SQL:
            await conn.execute(statement)


async def list_machines(pool) -> list[dict]:
    async with pool.connection() as conn:
        return await (await conn.execute("SELECT * FROM aida_machines ORDER BY name")).fetchall()


async def get_machine(pool, machine_id: str) -> dict | None:
    async with pool.connection() as conn:
        return await (await conn.execute("SELECT * FROM aida_machines WHERE id = %s", (machine_id,))).fetchone()


async def add_machine(pool, machine_id, name, ssh_target, ssh_port, remote_command, created_by) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO aida_machines (id, name, ssh_target, ssh_port, remote_command, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (machine_id, name, ssh_target, int(ssh_port), " ".join(remote_command.split()), created_by),
        )


async def update_machine(pool, machine_id: str, **fields) -> None:
    allowed = {k: v for k, v in fields.items() if k in ("name", "ssh_target", "ssh_port", "remote_command", "enabled")
               and v is not None}
    if "remote_command" in allowed:
        allowed["remote_command"] = " ".join(allowed["remote_command"].split())
    if not allowed:
        return
    async with pool.connection() as conn:
        await conn.execute(
            f"UPDATE aida_machines SET {', '.join(f'{k} = %s' for k in allowed)} WHERE id = %s",
            (*allowed.values(), machine_id),
        )
    forget_tools(machine_id)


# ---- talking to a machine's tool server ----------------------------------------------

_tool_cache: dict[str, dict] = {}   # machine id -> {tool name: tool}


def forget_tools(machine_id: str | None = None) -> None:
    if machine_id is None:
        _tool_cache.clear()
    else:
        _tool_cache.pop(machine_id, None)


async def fetch_tools(machine: dict, timeout: float = 60) -> dict:
    """The machine's tools (cached). Raises when the machine cannot be reached."""
    if machine["id"] in _tool_cache:
        return _tool_cache[machine["id"]]
    from langchain_mcp_adapters.client import MultiServerMCPClient
    client = MultiServerMCPClient({machine["id"]: {
        "command": "ssh", "args": ssh_args(machine), "transport": "stdio", "env": _ssh_env(),
    }})
    try:
        tools = await asyncio.wait_for(client.get_tools(), timeout)
    except Exception as e:
        raise ConnectionError(await diagnose(machine, e)) from e
    _tool_cache[machine["id"]] = {t.name: t for t in tools}
    return _tool_cache[machine["id"]]


async def diagnose(machine: dict, error: BaseException) -> str:
    """The MCP client hides SSH's own error message, so log in once more (running only `true`) to learn why."""
    probe = [a for a in ssh_args(machine)[: ssh_args(machine).index("--") + 2]] + ["true"]
    try:
        process = await asyncio.create_subprocess_exec("ssh", *probe, stdout=asyncio.subprocess.DEVNULL,
                                                       stderr=asyncio.subprocess.PIPE, env=_ssh_env())
        _, stderr = await asyncio.wait_for(process.communicate(), 20)
    except FileNotFoundError:
        return "The ssh program is not installed on this computer (sudo apt install openssh-client)."
    except Exception as e:
        return explain_failure(e)
    if process.returncode == 0:
        return ("SSH login works, but the AIDA agent did not start there: check the remote command, or run "
                f"scripts/install_agent.sh {machine['ssh_target']} {machine['ssh_port']}.")
    return explain_failure(RuntimeError(stderr.decode(errors="replace").strip() or f"ssh exit code {process.returncode}"))


def explain_failure(error: BaseException) -> str:
    """Turn SSH/MCP start-up failures into a sentence an operator can act on."""
    parts, stack = [], [error]
    while stack:  # ExceptionGroups from the MCP client hide the real cause
        e = stack.pop()
        stack.extend(getattr(e, "exceptions", []) or [])
        text = str(e).strip()
        if text:
            parts.append(text)
    text = " ".join(parts) or type(error).__name__
    lowered = text.lower()
    if "host key verification failed" in lowered:
        hint = "SSH does not trust this machine yet: connect once by hand with ssh and accept its host key."
    elif "permission denied" in lowered:
        hint = ("SSH refused the login: AIDA's key (~/.ssh/aida_ed25519.pub) is not authorized on that machine "
                "(for a Windows PC, run scripts/setup_windows_pc.ps1 there).")
    elif "could not resolve" in lowered or "name or service not known" in lowered:
        hint = "The host name could not be found."
    elif "connection refused" in lowered or "timed out" in lowered or "no route" in lowered:
        hint = "The machine did not answer on its SSH port: is it on, and is SSH running?"
    elif "timeout" in type(error).__name__.lower():
        hint = "The machine did not answer in time."
    else:
        hint = "Unexpected error."
    return f"{hint} ({text[:300]})"


def tool_text(result) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        return "\n".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in result)
    return str(result)


_registry: dict[str, dict] = {}  # machine id -> row, refreshed by the API whenever machines change


def set_registry(rows: list[dict]) -> None:
    _registry.clear()
    _registry.update({r["id"]: dict(r) for r in rows})


def registry() -> dict[str, dict]:
    return dict(_registry)


def wrap_tools(local_tools: list) -> list:
    """Dispatcher tools with the same names, descriptions and arguments as this computer's tools."""
    from langchain_core.tools import StructuredTool

    def make(tool):
        async def dispatch(**kwargs):
            machine_id = current_machine.get()
            if machine_id == LOCAL:
                return tool_text(await tool.ainvoke(kwargs))
            machine = _registry.get(machine_id)
            if machine is None or not machine.get("enabled"):
                return f"FAILED: machine {machine_id!r} is not connected to AIDA (or is disabled); nothing was run."
            try:
                remote = await fetch_tools(machine)
            except ConnectionError as e:
                return f"FAILED: could not reach {machine['name']}: {e}"
            if tool.name not in remote:
                return (f"FAILED: {machine['name']} runs an older AIDA agent without {tool.name}; "
                        f"update it with scripts/install_agent.sh.")
            try:
                return tool_text(await remote[tool.name].ainvoke(kwargs))
            except Exception as e:
                forget_tools(machine_id)
                return f"FAILED: {tool.name} on {machine['name']} did not complete: {explain_failure(e)}"

        return StructuredTool(name=tool.name, description=tool.description, args_schema=tool.args_schema,
                              coroutine=dispatch)

    return [make(t) for t in local_tools]


# ---- monitoring other machines ---------------------------------------------------------

status: dict[str, dict] = {}  # machine id -> last check result, for the dashboard


async def check_machine(machine: dict, alert_cls, auto_prefix: str, timeout: float = 180) -> list:
    """Run the machine's own health checks over SSH; an unreachable machine is itself an alert."""
    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        tools = await fetch_tools(machine)
        if "monitor_snapshot" not in tools:
            raise ConnectionError("its AIDA agent is too old for monitoring; update it with scripts/install_agent.sh")
        data = json.loads(tool_text(await asyncio.wait_for(tools["monitor_snapshot"].ainvoke({}), timeout)))
    except Exception as e:
        forget_tools(machine["id"])
        reason = str(e) if isinstance(e, ConnectionError) else explain_failure(e)
        status[machine["id"]] = {"ok": False, "error": reason[:400], "alerts": 0, "checked_at": checked_at}
        return [alert_cls(
            key=f"{machine['id']}/unreachable", check="machine",
            issue=(f"{auto_prefix} The machine {machine['name']} ({machine['ssh_target']}) could not be checked: {reason} "
                   f"Check whether {machine['ssh_target'].split('@')[-1]} is reachable from here."),
            machine=None,  # investigated from this computer, since that machine cannot be reached
        )]
    alerts = []
    for raw in data.get("alerts", []):
        text = str(raw.get("issue", "")).replace(auto_prefix, "").strip()
        alerts.append(alert_cls(key=f"{machine['id']}/{raw.get('key')}", check=str(raw.get("check", "")),
                                issue=f"{auto_prefix} [{machine['name']}] {text}", machine=machine["id"]))
    status[machine["id"]] = {"ok": True, "error": None, "alerts": len(alerts), "checked_at": checked_at,
                             "host": data.get("host"), "windows": data.get("windows")}
    return alerts


async def monitor_all(alert_cls, auto_prefix: str) -> list:
    machines = [m for m in _registry.values() if m.get("enabled")]
    results = await asyncio.gather(*(check_machine(m, alert_cls, auto_prefix) for m in machines))
    return [a for group in results for a in group]
