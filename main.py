import asyncio
import hmac
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load .env before importing modules that read environment variables
load_dotenv()

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from src import audit, machines, monitor, notify, products, reports, scheduler, users, windows
from src.db import DB_URI, KB_COLLECTION, TICKETS_TABLE_SQL
from src.graph.graph import compile_aida_graph
from src.kb.learn import forget_ticket, learn_from_ticket, should_learn
from src.kb.store import close_vector_store

aida_graph = None
mcp_client = None
db_pool = None
monitor_task = None
monitor_lock = None
scheduler_task = None
aida_tools: dict = {}

# Graph nodes that are not AI agents (tool executors, routing sentinels, the human hand-off)
NON_AGENT_NODES = {"__start__", "__end__", "human_escalation"}


def tool_server_env() -> dict[str, str]:
    """Environment for the MCP tool server: everything except secrets."""
    secret_markers = ("KEY", "PASSWORD", "SECRET", "TOKEN", "WEBHOOK", "SMTP")
    shell_only = {"PS1", "PS2", "PROMPT_COMMAND"}  # interactive prompt settings; the MCP SDK warns about them
    return {name: value for name, value in os.environ.items()
            if name not in shell_only and not any(marker in name.upper() for marker in secret_markers)}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global aida_graph, mcp_client, db_pool, monitor_task, monitor_lock, scheduler_task, aida_tools

    # 1. Database: one pool shared by the LangGraph checkpointer and the tickets table
    print("\n[System] Connecting to Postgres...")
    db_pool = AsyncConnectionPool(
        DB_URI,
        max_size=10,
        open=False,
        kwargs={"autocommit": True, "prepare_threshold": 0, "row_factory": dict_row},
    )
    await db_pool.open()
    checkpointer = AsyncPostgresSaver(db_pool)
    await checkpointer.setup()  # creates LangGraph's checkpoint tables if missing
    async with db_pool.connection() as conn:
        for statement in TICKETS_TABLE_SQL:
            await conn.execute(statement)
    await audit.ensure_audit_schema(db_pool)
    await scheduler.ensure_schema(db_pool)
    await products.ensure_schema(db_pool)
    await machines.ensure_schema(db_pool)
    machines.set_registry(await machines.list_machines(db_pool))
    note = await users.ensure_users(db_pool)
    if note:
        print(f"[System] {note}")
    print("[System] Postgres ready (tickets persist across restarts).")

    # 2. MCP tools. sys.executable enforces the virtual environment's Python
    print("[System] Connecting to MCP Server...")
    mcp_client = MultiServerMCPClient({
        "aida_diagnostics": {
            "command": sys.executable,
            "args": ["mcp_server.py"],
            "transport": "stdio",
            # The MCP SDK otherwise starts the server with a minimal environment, which would drop
            # AIDA settings from .env (e.g. AIDA_RESTARTABLE_SERVICES). Secrets are not passed on.
            "env": tool_server_env(),
        }
    })
    local_tools = await mcp_client.get_tools()
    aida_tools = {t.name: t for t in local_tools}  # this computer's tools (scheduled maintenance, backups)
    print(f"[System] Fetched {len(local_tools)} tools via MCP: {[t.name for t in local_tools]}")
    # The agents get dispatchers: each call runs on the ticket's machine (this computer unless chosen otherwise)
    tools = machines.wrap_tools(local_tools)
    if machines.registry():
        print(f"[System] Other machines: {', '.join(m['name'] for m in machines.registry().values())}")

    # 3. Route tools to the correct agents
    def pick(*names):
        return [t for t in tools if t.name in names]

    net_tools = pick("ping_host", "resolve_dns", "get_adapter_status")
    rem_tools = pick("flush_dns_cache", "restart_service", "clear_temp_files", "rotate_logs", "docker_prune",
                     "restart_container", "block_ip", "unblock_ip", "install_security_updates", "run_runbook",
                     "windows_restart_service", "windows_defender_scan", "windows_update_signatures", "windows_clear_temp")
    os_tools = pick("get_system_info", "check_disk_usage", "list_top_processes", "check_service_status",
                    "windows_health", "windows_top_processes", "windows_event_errors", "windows_service_status")
    sec_tools = pick("list_listening_ports", "list_recent_logins", "security_audit", "list_failed_logins",
                     "scan_vulnerabilities", "compliance_check", "windows_health", "windows_update_status")

    # 4. Compile the graph with injected tools and the Postgres checkpointer
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    aida_graph = compile_aida_graph(llm, net_tools, rem_tools, os_tools, sec_tools, checkpointer=checkpointer)

    repaired = await repair_learned_tickets()
    if repaired:
        print(f"[System] Removed {repaired} ticket(s) from the knowledge base that were learned without a real fix.")

    # 5. Proactive monitoring: checks the machine on a schedule and opens its own tickets
    monitor_lock = asyncio.Lock()
    interval = float(os.getenv("AIDA_MONITOR_INTERVAL", "300") or 0)
    if interval > 0:
        monitor_task = asyncio.create_task(monitor.monitor_loop(
            db_pool, open_monitor_ticket, interval, monitor_lock, extra_collect=extra_alerts))
        print(f"[System] Monitoring every {interval:.0f}s (set AIDA_MONITOR_INTERVAL=0 to turn off).")

    # 6. Scheduled maintenance (runbooks approved in advance by an admin)
    scheduler_interval = float(os.getenv("AIDA_SCHEDULER_INTERVAL", "60") or 0)
    if scheduler_interval > 0:
        scheduler_task = asyncio.create_task(scheduler.scheduler_loop(
            db_pool, run_runbook_now, record_schedule_audit, notify_maintenance_failure, scheduler_interval))

    print("[System] Project AIDA API Ready.")

    yield

    if scheduler_task:
        scheduler_task.cancel()
        try:
            await scheduler_task
        except asyncio.CancelledError:
            pass
        scheduler_task = None

    if monitor_task:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass
        monitor_task = None

    print("\n[System] Shutting down MCP Server...")
    if hasattr(mcp_client, "close") and callable(mcp_client.close):
        await mcp_client.close()
    await notify.drain()
    await close_vector_store()
    await db_pool.close()


app = FastAPI(title="Project AIDA API", lifespan=lifespan)

# Only the local Streamlit dashboard may call the API from a browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_methods=["GET", "POST"],
    allow_headers=["X-AIDA-Key", "X-AIDA-User-Token", "Content-Type"],
)


async def require_api_key(x_aida_key: str | None = Header(default=None)):
    """Every /api call must send the shared key from .env (AIDA_API_KEY) in the X-AIDA-Key header."""
    expected = os.getenv("AIDA_API_KEY", "")
    if not expected:
        raise HTTPException(status_code=503, detail="AIDA_API_KEY is not set on the server. Add it to .env and restart.")
    if not x_aida_key or not hmac.compare_digest(x_aida_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


api = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])


SERVICE_ACCOUNT = {"username": "api", "role": "admin"}


async def current_user(x_aida_user_token: str | None = Header(default=None)) -> dict:
    """The signed-in dashboard user (from their session token), or the 'api' service account for
    scripts that only hold the API key. Role and enabled state are re-checked on every request."""
    if not x_aida_user_token:
        return SERVICE_ACCOUNT
    claims = users.read_token(x_aida_user_token)
    if not claims:
        raise HTTPException(status_code=401, detail="Your session has expired. Please sign in again.")
    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            "SELECT username, role, disabled FROM aida_users WHERE username = %s", (claims["username"],)
        )).fetchone()
    if not row or row["disabled"]:
        raise HTTPException(status_code=401, detail="This account is disabled or no longer exists.")
    return {"username": row["username"], "role": row["role"]}


def require_role(role: str):
    async def check(user: dict = Depends(current_user)) -> dict:
        if not users.role_at_least(user["role"], role):
            raise HTTPException(status_code=403, detail=f"This action needs the '{role}' role; you are '{user['role']}'.")
        return user
    return check


requester = Depends(require_role("requester"))
approver = Depends(require_role("approver"))
admin = Depends(require_role("admin"))


class TicketRequest(BaseModel):
    issue: str
    machine: str = machines.LOCAL


class ApprovalRequest(BaseModel):
    approved: bool


def describe_last_message(values: dict):
    """Return displayable text for the latest message; tool-call-only messages have empty content."""
    messages = values.get("messages") if values else None
    if not messages:
        return None
    last = messages[-1]
    if last.content:
        return last.content
    tool_calls = getattr(last, "tool_calls", None) or []
    if tool_calls:
        calls = ", ".join(f"`{tc['name']}`" + (f" with {tc['args']}" if tc.get("args") else "") for tc in tool_calls)
        return f"Requesting approval to run: {calls}"
    return None


def agent_names() -> list[str]:
    """AI agent nodes in the compiled graph (excludes tool executors and the human hand-off)."""
    return sorted(
        name for name in aida_graph.get_graph().nodes
        if name not in NON_AGENT_NODES and not name.endswith("_tools")
    )


async def snapshot_ticket(thread_id: str, issue: str | None = None, source: str = "user",
                          alert_key: str | None = None, learn: bool = True, machine: str | None = None) -> dict | None:
    """Read a ticket's current state from the graph checkpoint and save a summary row."""
    config = {"configurable": {"thread_id": thread_id}}
    state = await aida_graph.aget_state(config)
    if not state.values:
        return None

    ticket = {
        "thread_id": thread_id,
        "status": state.values.get("ticket_status", "unknown"),
        "current_specialist": state.values.get("current_specialist", "unknown"),
        "requires_approval": bool(state.next and "remediate_tools" in state.next),
        "last_message": describe_last_message(state.values),
    }
    if issue is None:
        messages = state.values.get("messages") or []
        issue = messages[0].content if messages else ""

    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            """
            INSERT INTO aida_tickets (thread_id, issue, status, current_specialist, requires_approval,
                                      last_message, source, alert_key, machine)
            VALUES (%(thread_id)s, %(issue)s, %(status)s, %(current_specialist)s, %(requires_approval)s,
                    %(last_message)s, %(source)s, %(alert_key)s, %(machine)s)
            ON CONFLICT (thread_id) DO UPDATE SET
                status = EXCLUDED.status,
                current_specialist = EXCLUDED.current_specialist,
                requires_approval = EXCLUDED.requires_approval,
                last_message = EXCLUDED.last_message,
                updated_at = now()
            RETURNING issue, learned, forgotten, source, alert_key, machine, created_at, updated_at
            """,
            {**ticket, "issue": issue, "source": source, "alert_key": alert_key, "machine": machine or machines.LOCAL},
        )).fetchone()

    result = {**ticket, **row}
    if learn:
        await maybe_learn(result)
    return result


async def maybe_learn(ticket: dict) -> None:
    """Ticket learning: add a newly resolved ticket to the knowledge base (once per ticket). Updates `ticket`."""
    thread_id, row = ticket["thread_id"], ticket
    if row["learned"] or row["forgotten"]:
        return
    state = await aida_graph.aget_state({"configurable": {"thread_id": thread_id}})
    tools_used = {m.name for m in (state.values or {}).get("messages", []) if isinstance(m, ToolMessage)}
    if should_learn(ticket["status"], ticket["current_specialist"], ticket["last_message"], tools_used):
        try:
            await learn_from_ticket(thread_id, row["issue"], ticket["current_specialist"], ticket["last_message"])
            async with db_pool.connection() as conn:
                await conn.execute("UPDATE aida_tickets SET learned = TRUE WHERE thread_id = %s", (thread_id,))
            row["learned"] = True
            await audit.record(db_pool, "system", "knowledge.learned", thread_id,
                               {"specialist": ticket["current_specialist"]})
        except Exception as e:
            # Learning is best-effort; never fail the ticket because the knowledge base is unavailable
            print(f"[Learning] Could not add ticket {thread_id[:8]} to the knowledge base: {e}")


async def repair_learned_tickets() -> int:
    """
    Clean up tickets learned before the needs_info rule existed: a remediation ticket that ended
    without running any tool (e.g. the agent asked a question) was wrongly marked resolved and learned.
    Such tickets are removed from the knowledge base, marked needs_info, and never re-learned.
    """
    async with db_pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT thread_id FROM aida_tickets WHERE learned AND current_specialist = 'remediate'"
        )).fetchall()

    repaired = 0
    for row in rows:
        thread_id = row["thread_id"]
        state = await aida_graph.aget_state({"configurable": {"thread_id": thread_id}})
        messages = (state.values or {}).get("messages") or []
        if any(isinstance(m, ToolMessage) for m in messages):
            continue  # a real fix ran; keep it
        try:
            await forget_ticket(thread_id)
        except Exception as e:
            print(f"[Learning] Could not remove ticket {thread_id[:8]} from the knowledge base: {e}")
            continue
        if state.values:
            # Correct the status in the agent history too (it is the source of truth for the ticket)
            await aida_graph.aupdate_state(state.config, {"ticket_status": "needs_info"}, as_node="remediate")
        async with db_pool.connection() as conn:
            await conn.execute(
                "UPDATE aida_tickets SET learned = FALSE, forgotten = TRUE, status = 'needs_info', "
                "updated_at = now() WHERE thread_id = %s",
                (thread_id,),
            )
        await audit.record(db_pool, "system", "knowledge.repaired", thread_id,
                           {"reason": "learned without running a fix; marked needs_info"})
        repaired += 1
    return repaired


@app.get("/")
async def root():
    return {"message": "Project AIDA Backend is Running! Go to http://127.0.0.1:8006/docs to interact with the API."}


def tool_text(result) -> str:
    """MCP tool results arrive as text or as a list of content blocks, depending on the adapter version."""
    if isinstance(result, str):
        return result
    if isinstance(result, list):
        return "\n".join(block.get("text", "") if isinstance(block, dict) else str(block) for block in result)
    return str(result)


async def call_tool(name: str, args: dict | None = None) -> str:
    return tool_text(await aida_tools[name].ainvoke(args or {}))


async def run_runbook_now(runbook: str) -> str:
    return await call_tool("run_runbook", {"name": runbook})


async def record_schedule_audit(actor, action, thread_id, details):
    await audit.record(db_pool, actor, action, thread_id, details)


def notify_maintenance_failure(summary, thread_id):
    notify.send_in_background("fix_failed", summary, thread_id)


def pending_tool_calls(values: dict) -> list[dict]:
    messages = (values or {}).get("messages") or []
    calls = getattr(messages[-1], "tool_calls", None) if messages else None
    return [{"name": c["name"], "args": c.get("args", {})} for c in (calls or [])]


async def run_graph_on(machine: str, graph_input, config: dict) -> None:
    """Run (or resume) a ticket's agents with every tool call sent to the ticket's machine."""
    token = machines.current_machine.set(machine or machines.LOCAL)
    try:
        async for _ in aida_graph.astream(graph_input, config=config):
            pass
    finally:
        machines.current_machine.reset(token)


async def ticket_machine(thread_id: str) -> str:
    async with db_pool.connection() as conn:
        row = await (await conn.execute("SELECT machine FROM aida_tickets WHERE thread_id = %s", (thread_id,))).fetchone()
    return row["machine"] if row else machines.LOCAL


async def start_ticket(issue: str, actor: str, source: str = "user", alert_key: str | None = None,
                       machine: str = machines.LOCAL) -> dict:
    """Run a new ticket through the agents, save it, and record it in the audit log."""
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    machine = machine or machines.LOCAL
    if machine != machines.LOCAL and not issue.startswith(monitor.AUTO_PREFIX):
        # Tell the agents (and the queue) which computer this is about
        issue = f"[On {machines.registry().get(machine, {}).get('name', machine)}] {issue}"
    await run_graph_on(machine, {"messages": [HumanMessage(content=issue)]}, config)

    ticket = await snapshot_ticket(thread_id, issue=issue, source=source, alert_key=alert_key, learn=False,
                                   machine=machine)
    await audit.record(db_pool, actor, "ticket.created", thread_id, {
        "issue": issue[:500], "source": source, "alert_key": alert_key, "machine": machine,
        "specialist": ticket["current_specialist"], "status": ticket["status"],
    })
    if ticket["requires_approval"]:
        state = await aida_graph.aget_state(config)
        tools = pending_tool_calls(state.values)
        await audit.record(db_pool, "agent:" + ticket["current_specialist"], "remediation.requested", thread_id,
                           {"tools": tools})
        wanted = ", ".join(t["name"] + (f" {t['args']}" if t["args"] else "") for t in tools)
        notify.send_in_background("approval_needed", f"AIDA wants to run {wanted} for: {issue[:200]}", thread_id)
    if source == "monitor":
        notify.send_in_background("auto_ticket", issue.replace(monitor.AUTO_PREFIX, "").strip()[:300], thread_id)
    if ticket["status"] == "escalated":
        notify.send_in_background("escalated", f"A ticket needs a human: {issue[:200]}", thread_id)
    await maybe_learn(ticket)  # after "ticket.created", so the audit log reads in order
    return ticket


async def open_monitor_ticket(alert) -> dict:
    return await start_ticket(alert.issue, actor="monitor", source="monitor", alert_key=alert.key,
                              machine=getattr(alert, "machine", None) or machines.LOCAL)


async def extra_alerts() -> list:
    """Checks beyond this computer: connected products' health and other machines."""
    alerts = []
    for collect in (product_health_alerts, machine_alerts):
        try:
            alerts += await collect()
        except Exception as e:
            print(f"[Monitor] {collect.__name__} failed: {e}")
    return alerts


async def machine_alerts() -> list:
    return await machines.monitor_all(monitor.Alert, monitor.AUTO_PREFIX)


@api.post("/tickets")
async def create_ticket(request: TicketRequest, user: dict = requester):
    machine = request.machine or machines.LOCAL
    if machine != machines.LOCAL:
        known = machines.registry().get(machine)
        if not known or not known["enabled"]:
            raise HTTPException(status_code=400, detail=f"Unknown or disabled machine: {machine}")
    return await start_ticket(request.issue, user["username"], machine=machine)


@api.get("/tickets")
async def list_tickets(limit: int = 50, user: dict = requester):
    """Most recent tickets first, read from Postgres (survives restarts)."""
    limit = max(1, min(limit, 200))
    async with db_pool.connection() as conn:
        rows = await (await conn.execute(
            """
            SELECT t.thread_id, t.issue, t.status, t.current_specialist, t.requires_approval,
                   t.last_message, t.learned, t.forgotten, t.source, t.alert_key, t.machine, t.created_at, t.updated_at,
                   e.occurrences, e.tenants, e.last_seen, e.product_id
            FROM aida_tickets t
            LEFT JOIN aida_product_errors e ON e.alert_key = t.alert_key
            ORDER BY t.created_at DESC
            LIMIT %s
            """,
            (limit,),
        )).fetchall()
    return rows


@api.get("/tickets/{thread_id}")
async def get_ticket(thread_id: str, user: dict = requester):
    ticket = await snapshot_ticket(thread_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@api.post("/tickets/{thread_id}/approve")
async def approve_remediation(thread_id: str, request: ApprovalRequest, user: dict = approver):
    actor = user["username"]
    config = {"configurable": {"thread_id": thread_id}}
    state = await aida_graph.aget_state(config)

    if not state.values:
        raise HTTPException(status_code=404, detail="Ticket not found")

    requires_approval = state.next and "remediate_tools" in state.next
    if not requires_approval:
        raise HTTPException(status_code=400, detail="No pending actions require approval")

    requested = pending_tool_calls(state.values)
    if request.approved:
        machine = await ticket_machine(thread_id)
        await audit.record(db_pool, actor, "remediation.approved", thread_id, {"tools": requested, "machine": machine})
        await run_graph_on(machine, None, config)
        # Record exactly what the tools reported
        final = await aida_graph.aget_state(config)
        call_ids = {tc["id"] for tc in getattr(state.values["messages"][-1], "tool_calls", None) or []}
        results = [
            {"tool": m.name, "result": str(m.content)[:1000]}
            for m in final.values.get("messages", []) if isinstance(m, ToolMessage) and m.tool_call_id in call_ids
        ]
        ticket = await snapshot_ticket(thread_id, learn=False)
        await audit.record(db_pool, "agent:remediate", "remediation.executed", thread_id,
                           {"results": results, "status": ticket["status"]})
        if ticket["status"] == "failed":
            notify.send_in_background("fix_failed", f"An approved fix did not work: {(ticket['last_message'] or '')[:300]}", thread_id)
        await maybe_learn(ticket)
        return {"message": "Remediation approved and executed.", **ticket}
    # Denied: answer each pending tool call with a refusal so nothing runs, then close the ticket
    pending_calls = getattr(state.values["messages"][-1], "tool_calls", None) or []
    refusals = [
        ToolMessage(content="Denied by operator. The action was not executed.",
                    tool_call_id=tc["id"], name=tc["name"])
        for tc in pending_calls
    ]
    names = ", ".join(f"`{tc['name']}`" for tc in pending_calls) or "The requested action"
    summary = AIMessage(content=f"Remediation denied by operator: {names} was not run. No changes were made to the system.")
    # Recorded as the remediate node's output; its last message has no tool calls, so the graph ends here
    await aida_graph.aupdate_state(
        config,
        {"messages": refusals + [summary], "ticket_status": "denied"},
        as_node="remediate",
    )
    ticket = await snapshot_ticket(thread_id)
    await audit.record(db_pool, actor, "remediation.denied", thread_id, {"tools": requested})
    return {"message": "Remediation denied. No action was taken.", **ticket}


@api.post("/tickets/{thread_id}/forget")
async def forget_learned_ticket(thread_id: str, user: dict = approver):
    actor = user["username"]
    """Remove a ticket from the knowledge base and stop it from being learned again."""
    async with db_pool.connection() as conn:
        row = await (await conn.execute(
            "SELECT learned FROM aida_tickets WHERE thread_id = %s", (thread_id,)
        )).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if row["learned"]:
        await forget_ticket(thread_id)
    async with db_pool.connection() as conn:
        await conn.execute(
            "UPDATE aida_tickets SET learned = FALSE, forgotten = TRUE, updated_at = now() WHERE thread_id = %s",
            (thread_id,),
        )
    await audit.record(db_pool, actor, "knowledge.removed", thread_id, {"was_learned": bool(row["learned"])})
    return {"thread_id": thread_id, "learned": False, "forgotten": True}


@api.get("/audit")
async def audit_log(limit: int = 100, thread_id: str | None = None, user: dict = approver):
    """Most recent audit entries first."""
    return await audit.recent(db_pool, max(1, min(limit, 1000)), thread_id)


@api.get("/audit/verify")
async def audit_verify(user: dict = approver):
    """Recompute the hash chain to prove no audit entry was changed or removed."""
    return await audit.verify_chain(db_pool)


@api.get("/monitor/status")
async def monitor_status(user: dict = requester):
    interval = float(os.getenv("AIDA_MONITOR_INTERVAL", "300") or 0)
    return {"enabled": interval > 0, "interval_seconds": interval, "windows": windows.monitoring_enabled(),
            "windows_status": monitor.windows_status, **monitor.last_run,
            "machines": [{"id": m["id"], "name": m["name"], **machines.status.get(m["id"], {})}
                         for m in machines.registry().values() if m["enabled"]]}


@api.post("/monitor/run")
async def monitor_run(user: dict = approver):
    actor = user["username"]
    """Run all health checks now (tickets are only opened for new problems)."""
    result = await monitor.run_once(db_pool, open_monitor_ticket, lock=monitor_lock, extra_collect=extra_alerts)
    await audit.record(db_pool, actor, "monitor.run", None,
                       {"alerts": len(result["alerts"]), "opened": [o["alert_key"] for o in result["opened"]]})
    return result


class LoginRequest(BaseModel):
    username: str
    password: str


class NewUser(BaseModel):
    username: str
    password: str
    role: str = "requester"


class UserUpdate(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = None


@api.post("/auth/login")
async def login(request: LoginRequest):
    """Sign in with a username and password; returns a session token for the X-AIDA-User-Token header."""
    username = request.username.strip().lower()
    if users.locked_out(username):
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Try again in 5 minutes.")
    user = await users.authenticate(db_pool, username, request.password)
    if not user:
        users.note_failure(username)
        await audit.record(db_pool, username or "unknown", "auth.login_failed", None, {})
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    users.clear_failures(username)
    await audit.record(db_pool, user["username"], "auth.login", None, {"role": user["role"]})
    return {**user, "token": users.issue_token(user["username"], user["role"])}


@api.get("/auth/me")
async def me(user: dict = Depends(current_user)):
    return user


@api.get("/users")
async def get_users(user: dict = admin):
    return await users.list_users(db_pool)


@api.post("/users")
async def add_user(new: NewUser, user: dict = admin):
    username = new.username.strip().lower()
    if not username.replace("_", "").replace(".", "").replace("-", "").isalnum() or len(username) > 40:
        raise HTTPException(status_code=400, detail="Usernames may contain letters, digits, '.', '_' and '-' (max 40).")
    if new.role not in users.ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {', '.join(users.ROLES)}.")
    if problem := users.validate_new_password(new.password):
        raise HTTPException(status_code=400, detail=problem)
    try:
        await users.create_user(db_pool, username, new.password, new.role)
    except Exception:
        raise HTTPException(status_code=409, detail=f"User '{username}' already exists.")
    await audit.record(db_pool, user["username"], "user.created", None, {"username": username, "role": new.role})
    return {"username": username, "role": new.role}


@api.post("/users/{username}")
async def change_user(username: str, change: UserUpdate, user: dict = admin):
    if change.role is not None and change.role not in users.ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of {', '.join(users.ROLES)}.")
    if change.password is not None and (problem := users.validate_new_password(change.password)):
        raise HTTPException(status_code=400, detail=problem)
    # Never lock everyone out: keep at least one active admin
    removing_admin = change.disabled or (change.role is not None and change.role != "admin")
    if removing_admin:
        current = [u for u in await users.list_users(db_pool) if u["username"] == username]
        if current and current[0]["role"] == "admin" and not current[0]["disabled"] \
                and await users.active_admin_count(db_pool) <= 1:
            raise HTTPException(status_code=400, detail="This is the last active admin; add another admin first.")
    if not await users.update_user(db_pool, username, change.role, change.disabled, change.password):
        raise HTTPException(status_code=404, detail="User not found")
    details = {k: v for k, v in change.model_dump().items() if v is not None and k != "password"}
    if change.password is not None:
        details["password_reset"] = True
    await audit.record(db_pool, user["username"], "user.updated", None, {"username": username, **details})
    return {"username": username, **details}


@api.get("/notify/status")
async def notify_status(user: dict = approver):
    return {**notify.configured_channels(), "recent": notify.history[-20:][::-1]}


@api.post("/notify/test")
async def notify_test(user: dict = admin):
    results = await asyncio.to_thread(notify.send_now, "test", f"Test message sent by {user['username']}.")
    await audit.record(db_pool, user["username"], "notify.test", None, {"results": results})
    if not results:
        raise HTTPException(status_code=400, detail="No notification channels are configured in .env.")
    return {"results": results}


@api.get("/runbooks")
async def list_runbooks(user: dict = requester):
    from mcp_server import RUNBOOKS
    return {name: {"description": rb["description"], "steps": [tool for tool, _args in rb["steps"]]}
            for name, rb in RUNBOOKS.items()}


@api.get("/reports/summary")
async def report_summary(days: int = 30, user: dict = approver):
    return await reports.summary(db_pool, days)


@api.get("/reports/compliance")
async def report_compliance(days: int = 30, user: dict = approver):
    """HIPAA-oriented evidence pack: technical safeguards, security check, audit integrity, access activity."""
    import json as _json
    checks = _json.loads(await call_tool("compliance_check", {"output_format": "json"}))
    security_report = await call_tool("security_audit")
    verification = await audit.verify_chain(db_pool)
    access = await reports.access_summary(db_pool, days)
    markdown = reports.compliance_markdown(checks, security_report, verification, access, days)
    await audit.record(db_pool, user["username"], "report.compliance", None,
                       {"passed": sum(c["status"] == "pass" for c in checks), "total": len(checks)})
    return {"checks": checks, "security_report": security_report, "audit": verification,
            "access": access, "markdown": markdown}


class NewSchedule(BaseModel):
    name: str
    runbook: str
    frequency: str = "weekly"
    weekday: str | None = "sunday"
    at_time: str = "02:00"


class ScheduleUpdate(BaseModel):
    enabled: bool


async def get_schedule(schedule_id: int) -> dict:
    async with db_pool.connection() as conn:
        row = await (await conn.execute("SELECT * FROM aida_schedules WHERE id = %s", (schedule_id,))).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return row


@api.get("/schedules")
async def get_schedules(user: dict = approver):
    return await scheduler.list_schedules(db_pool)


@api.post("/schedules")
async def add_schedule(new: NewSchedule, user: dict = admin):
    from mcp_server import RUNBOOKS
    if new.runbook not in RUNBOOKS:
        raise HTTPException(status_code=400, detail=f"Unknown runbook. Choose one of: {', '.join(RUNBOOKS)}.")
    if new.frequency not in ("daily", "weekly"):
        raise HTTPException(status_code=400, detail="Frequency must be 'daily' or 'weekly'.")
    weekday = None
    if new.frequency == "weekly":
        if (new.weekday or "").lower() not in scheduler.WEEKDAYS:
            raise HTTPException(status_code=400, detail="Weekly schedules need a weekday (monday ... sunday).")
        weekday = scheduler.WEEKDAYS.index(new.weekday.lower())
    try:
        scheduler.parse_time(new.at_time)
    except ValueError:
        raise HTTPException(status_code=400, detail="Time must be HH:MM in 24-hour format, e.g. 02:00.")
    name = new.name.strip()[:60]
    if not name:
        raise HTTPException(status_code=400, detail="Give the schedule a name.")
    try:
        async with db_pool.connection() as conn:
            row = await (await conn.execute(
                "INSERT INTO aida_schedules (name, runbook, frequency, weekday, at_time, created_by) "
                "VALUES (%s, %s, %s, %s, %s, %s) RETURNING *",
                (name, new.runbook, new.frequency, weekday, new.at_time.strip(), user["username"]),
            )).fetchone()
    except Exception:
        raise HTTPException(status_code=409, detail=f"A schedule named '{name}' already exists.")
    await audit.record(db_pool, user["username"], "schedule.created", None,
                       {"name": name, "runbook": new.runbook, "when": scheduler.describe(row)})
    return row


@api.post("/schedules/{schedule_id}")
async def change_schedule(schedule_id: int, change: ScheduleUpdate, user: dict = admin):
    row = await get_schedule(schedule_id)
    async with db_pool.connection() as conn:
        await conn.execute("UPDATE aida_schedules SET enabled = %s WHERE id = %s", (change.enabled, schedule_id))
    await audit.record(db_pool, user["username"], "schedule.updated", None, {"name": row["name"], "enabled": change.enabled})
    return {"id": schedule_id, "enabled": change.enabled}


@api.post("/schedules/{schedule_id}/delete")
async def delete_schedule(schedule_id: int, user: dict = admin):
    row = await get_schedule(schedule_id)
    async with db_pool.connection() as conn:
        await conn.execute("DELETE FROM aida_schedules WHERE id = %s", (schedule_id,))
    await audit.record(db_pool, user["username"], "schedule.deleted", None, {"name": row["name"]})
    return {"deleted": schedule_id}


@api.post("/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: int, user: dict = admin):
    row = await get_schedule(schedule_id)
    return await scheduler.run_schedule(db_pool, row, run_runbook_now, record_schedule_audit,
                                        notify_maintenance_failure, trigger=f"manual by {user['username']}")


# ---- Connected products (Eivanta Analytics and future SaaS products) -------------------

_opening_alerts: set[str] = set()  # alert keys whose ticket is being created right now


async def product_health_alerts() -> list:
    """Monitoring hook: one alert per connected, unpaused product whose health check fails."""
    alerts = []
    for product in await products.list_products(db_pool):
        if product["paused"] or not product["health_url"]:
            continue
        problem = await asyncio.to_thread(products.check_health, product["health_url"])
        if problem:
            alerts.append(monitor.Alert(
                key=f"health:{product['id']}", check="product_health",
                issue=(f"{monitor.AUTO_PREFIX} {product['name']} ({product['environment']}) is unhealthy: {problem}. "
                       f"Health check: {product['health_url']}"),
            ))
    return alerts


async def _open_product_error_ticket(product: dict, report: dict, alert_key: str) -> None:
    try:
        ticket = await start_ticket(products.issue_text(product, report), actor=f"product:{product['id']}",
                                    source="product", alert_key=alert_key)
        notify.send_in_background(
            "auto_ticket",
            f"{product['name']}: unhandled {report.get('error_type')} on {report.get('method')} {report.get('route')}",
            ticket["thread_id"])
    except Exception as e:
        print(f"[Intake] Could not open a ticket for {alert_key}: {e}")
    finally:
        _opening_alerts.discard(alert_key)


intake = APIRouter(prefix="/intake", tags=["Product intake"])


@intake.post("/errors")
async def intake_error(request: Request, x_aida_product: str | None = Header(default=None),
                       x_aida_timestamp: str | None = Header(default=None),
                       x_aida_signature: str | None = Header(default=None)):
    """Error reports from connected products, authenticated by each product's own signing secret."""
    body = await request.body()
    if len(body) > products.MAX_REPORT_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Report too large."})
    product = await products.get_product(db_pool, x_aida_product or "", with_secret=True)
    if not product:
        return JSONResponse(status_code=401, content={"detail": "Unknown product or invalid signature."})
    problem = products.verify(product["intake_secret"], x_aida_timestamp, x_aida_signature, body)
    if problem:
        return JSONResponse(status_code=401, content={"detail": f"Rejected: {problem}."})
    if product["paused"]:
        return JSONResponse(status_code=423, content={"detail": f"{product['name']} is paused in AIDA."})
    try:
        report = json.loads(body)
        assert isinstance(report, dict) and report.get("product") == product["id"] and report.get("error_type")
    except (ValueError, AssertionError):
        return JSONResponse(status_code=400, content={"detail": "Malformed report."})

    alert_key = products.alert_key_for(product["id"], report)
    occurrences = await products.record_occurrence(db_pool, alert_key, product["id"], report)
    if alert_key in _opening_alerts or await monitor._has_active_ticket(db_pool, alert_key, cooldown_hours=0):
        return {"status": "grouped", "alert_key": alert_key, "occurrences": occurrences}
    _opening_alerts.add(alert_key)
    task = asyncio.create_task(_open_product_error_ticket(product, report, alert_key))
    notify._background.add(task)
    task.add_done_callback(notify._background.discard)
    return JSONResponse(status_code=202, content={"status": "accepted", "alert_key": alert_key, "occurrences": occurrences})


class NewProduct(BaseModel):
    id: str
    name: str
    environment: str = "local"
    health_url: str | None = None


class ProductUpdate(BaseModel):
    paused: bool | None = None
    health_url: str | None = None
    rotate_secret: bool = False


@api.get("/products")
async def get_products(user: dict = approver):
    return await products.list_products(db_pool)


@api.post("/products")
async def add_product(new: NewProduct, user: dict = admin):
    product_id = new.id.strip().lower()
    if not products.valid_slug(product_id):
        raise HTTPException(status_code=400, detail="Product id: lowercase letters, digits and dashes, e.g. eivanta-analytics.")
    if new.health_url and not new.health_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Health URL must start with http:// or https://.")
    try:
        secret = await products.add_product(db_pool, product_id, new.name.strip()[:80] or product_id,
                                            new.environment.strip()[:20] or "local", new.health_url, user["username"])
    except Exception:
        raise HTTPException(status_code=409, detail=f"Product '{product_id}' already exists.")
    await audit.record(db_pool, user["username"], "product.added", None,
                       {"product": product_id, "environment": new.environment, "health_url": new.health_url})
    return {"id": product_id, "intake_secret": secret,
            "note": "Copy this secret into the product's .env as AIDA_INTAKE_SECRET now; it is not shown again."}


@api.post("/products/{product_id}")
async def change_product(product_id: str, change: ProductUpdate, user: dict = admin):
    if not await products.get_product(db_pool, product_id):
        raise HTTPException(status_code=404, detail="Product not found")
    if change.health_url and not change.health_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Health URL must start with http:// or https://.")
    secret = await products.update_product(db_pool, product_id, change.paused, change.health_url, change.rotate_secret)
    details = {k: v for k, v in change.model_dump().items() if v not in (None, False)}
    await audit.record(db_pool, user["username"], "product.updated", None, {"product": product_id, **details})
    return {"id": product_id, **details, **({"intake_secret": secret} if secret else {})}


# ---- Other machines (Phase 9) ---------------------------------------------------------

class NewMachine(BaseModel):
    id: str
    name: str
    ssh_target: str
    ssh_port: int = 22
    remote_command: str = machines.DEFAULT_REMOTE_COMMAND


class MachineUpdate(BaseModel):
    name: str | None = None
    ssh_target: str | None = None
    ssh_port: int | None = None
    remote_command: str | None = None
    enabled: bool | None = None


async def refresh_machines() -> None:
    machines.set_registry(await machines.list_machines(db_pool))


@api.get("/machines")
async def get_machines(user: dict = requester):
    """This computer plus every machine AIDA looks after over SSH (connection details for admins only)."""
    import socket
    rows = [{"id": machines.LOCAL, "name": f"This computer ({socket.gethostname()})", "enabled": True}]
    for m in machines.registry().values():
        row = {"id": m["id"], "name": m["name"], "enabled": m["enabled"], "status": machines.status.get(m["id"])}
        if users.role_at_least(user["role"], "admin"):
            row.update({k: m[k] for k in ("ssh_target", "ssh_port", "remote_command", "created_by")})
        rows.append(row)
    return rows


@api.post("/machines")
async def add_machine(new: NewMachine, user: dict = admin):
    machine_id = new.id.strip().lower()
    error = machines.validate(machine_id, new.ssh_target.strip(), new.ssh_port, new.remote_command)
    if error:
        raise HTTPException(status_code=400, detail=error)
    try:
        await machines.add_machine(db_pool, machine_id, new.name.strip()[:80] or machine_id, new.ssh_target.strip(),
                                   new.ssh_port, new.remote_command, user["username"])
    except Exception:
        raise HTTPException(status_code=409, detail=f"Machine '{machine_id}' already exists.")
    await refresh_machines()
    await audit.record(db_pool, user["username"], "machine.added", None,
                       {"machine": machine_id, "ssh_target": new.ssh_target, "ssh_port": new.ssh_port,
                        "remote_command": new.remote_command})
    return {"id": machine_id}


@api.post("/machines/{machine_id}")
async def change_machine(machine_id: str, change: MachineUpdate, user: dict = admin):
    if not await machines.get_machine(db_pool, machine_id):
        raise HTTPException(status_code=404, detail="Machine not found")
    error = machines.validate(None, change.ssh_target, change.ssh_port, change.remote_command)
    if error:
        raise HTTPException(status_code=400, detail=error)
    await machines.update_machine(db_pool, machine_id, **change.model_dump())
    await refresh_machines()
    details = {k: v for k, v in change.model_dump().items() if v is not None}
    await audit.record(db_pool, user["username"], "machine.updated", None, {"machine": machine_id, **details})
    return {"id": machine_id, **details}


@api.post("/machines/{machine_id}/test")
async def test_machine(machine_id: str, user: dict = admin):
    """Connect over SSH, list the agent's tools and read basic system info. Changes nothing there."""
    machine = await machines.get_machine(db_pool, machine_id)
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    machines.forget_tools(machine_id)
    try:
        tools = await machines.fetch_tools(machine)
        info = machines.tool_text(await tools["get_system_info"].ainvoke({})) if "get_system_info" in tools else ""
        result = {"ok": True, "tools": len(tools), "system_info": info,
                  "missing_tools": sorted(set(aida_tools) - set(tools))}
    except ConnectionError as e:
        result = {"ok": False, "error": str(e)}
    await audit.record(db_pool, user["username"], "machine.tested", None,
                       {"machine": machine_id, "ok": result["ok"], **({"error": result["error"][:300]} if not result["ok"] else {})})
    return result


class CloseRequest(BaseModel):
    resolution: str = "resolved"
    note: str | None = None


@api.post("/tickets/{thread_id}/close")
async def close_ticket(thread_id: str, request: CloseRequest, user: dict = approver):
    """Close a diagnosed or otherwise open ticket once the underlying problem is fixed (or not worth fixing)."""
    if request.resolution not in ("resolved", "dismissed"):
        raise HTTPException(status_code=400, detail="Resolution must be 'resolved' or 'dismissed'.")
    config = {"configurable": {"thread_id": thread_id}}
    state = await aida_graph.aget_state(config)
    if state.values:
        if state.next and "remediate_tools" in state.next:
            raise HTTPException(status_code=400, detail="This ticket is waiting for approval; approve or deny it instead.")
        node = state.values.get("current_specialist")
        if node not in aida_graph.get_graph().nodes:
            node = "human_escalation"
        await aida_graph.aupdate_state(config, {"ticket_status": request.resolution}, as_node=node)
        ticket = await snapshot_ticket(thread_id, learn=False)
    else:
        async with db_pool.connection() as conn:
            row = await (await conn.execute(
                "UPDATE aida_tickets SET status = %s, updated_at = now() WHERE thread_id = %s RETURNING thread_id",
                (request.resolution, thread_id))).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Ticket not found")
        ticket = {"thread_id": thread_id, "status": request.resolution}
    await audit.record(db_pool, user["username"], "ticket.closed", thread_id,
                       {"resolution": request.resolution, "note": (request.note or "")[:500]})
    if state.values and request.resolution == "resolved":
        await maybe_learn(ticket)
    return ticket


@api.get("/metrics")
async def metrics(user: dict = requester):
    """Live numbers for the dashboard."""
    async with db_pool.connection() as conn:
        counts = await (await conn.execute(
            """
            SELECT count(*) AS tickets_total,
                   count(*) FILTER (WHERE requires_approval) AS pending_approvals,
                   count(*) FILTER (WHERE status = 'resolved') AS tickets_resolved,
                   count(*) FILTER (WHERE status = 'denied') AS tickets_denied,
                   count(*) FILTER (WHERE learned) AS tickets_learned,
                   count(*) FILTER (WHERE source = 'monitor') AS tickets_auto
            FROM aida_tickets
            """
        )).fetchone()

    # Knowledge base size; its tables only exist after src/kb/setup.py has been run
    kb_records, kb_online = 0, False
    try:
        async with db_pool.connection() as conn:
            row = await (await conn.execute(
                """
                SELECT count(e.*) AS n
                FROM langchain_pg_collection c
                LEFT JOIN langchain_pg_embedding e ON e.collection_id = c.uuid
                WHERE c.name = %s
                """,
                (KB_COLLECTION,),
            )).fetchone()
        kb_records, kb_online = row["n"], True
    except Exception:
        pass

    agents = agent_names()
    return {
        "agents": agents,
        "agent_count": len(agents),
        "kb_online": kb_online,
        "kb_records": kb_records,
        **counts,
    }


# Register the protected /api routes (must come after they are defined)
app.include_router(api)
app.include_router(intake)
