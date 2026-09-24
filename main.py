import hmac
import os
import sys
import uuid
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load .env before importing modules that read environment variables
load_dotenv()

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from src.db import DB_URI, KB_COLLECTION, TICKETS_TABLE_SQL
from src.graph.graph import compile_aida_graph
from src.kb.learn import forget_ticket, learn_from_ticket, should_learn
from src.kb.store import close_vector_store

aida_graph = None
mcp_client = None
db_pool = None

# Graph nodes that are not AI agents (tool executors, routing sentinels, the human hand-off)
NON_AGENT_NODES = {"__start__", "__end__", "human_escalation"}


def tool_server_env() -> dict[str, str]:
    """Environment for the MCP tool server: everything except secrets."""
    secret_markers = ("KEY", "PASSWORD", "SECRET", "TOKEN")
    shell_only = {"PS1", "PS2", "PROMPT_COMMAND"}  # interactive prompt settings; the MCP SDK warns about them
    return {name: value for name, value in os.environ.items()
            if name not in shell_only and not any(marker in name.upper() for marker in secret_markers)}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global aida_graph, mcp_client, db_pool

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
    tools = await mcp_client.get_tools()
    print(f"[System] Fetched {len(tools)} tools via MCP: {[t.name for t in tools]}")

    # 3. Route tools to the correct agents
    def pick(*names):
        return [t for t in tools if t.name in names]

    net_tools = pick("ping_host", "resolve_dns", "get_adapter_status")
    rem_tools = pick("flush_dns_cache", "restart_service", "clear_temp_files")
    os_tools = pick("get_system_info", "check_disk_usage", "list_top_processes", "check_service_status")
    sec_tools = pick("list_listening_ports", "list_recent_logins")

    # 4. Compile the graph with injected tools and the Postgres checkpointer
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    aida_graph = compile_aida_graph(llm, net_tools, rem_tools, os_tools, sec_tools, checkpointer=checkpointer)

    repaired = await repair_learned_tickets()
    if repaired:
        print(f"[System] Removed {repaired} ticket(s) from the knowledge base that were learned without a real fix.")

    print("[System] Project AIDA API Ready.")

    yield

    print("\n[System] Shutting down MCP Server...")
    if hasattr(mcp_client, "close") and callable(mcp_client.close):
        await mcp_client.close()
    await close_vector_store()
    await db_pool.close()


app = FastAPI(title="Project AIDA API", lifespan=lifespan)

# Only the local Streamlit dashboard may call the API from a browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_methods=["GET", "POST"],
    allow_headers=["X-AIDA-Key", "Content-Type"],
)


async def require_api_key(x_aida_key: str | None = Header(default=None)):
    """Every /api call must send the shared key from .env (AIDA_API_KEY) in the X-AIDA-Key header."""
    expected = os.getenv("AIDA_API_KEY", "")
    if not expected:
        raise HTTPException(status_code=503, detail="AIDA_API_KEY is not set on the server. Add it to .env and restart.")
    if not x_aida_key or not hmac.compare_digest(x_aida_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


api = APIRouter(prefix="/api", dependencies=[Depends(require_api_key)])


class TicketRequest(BaseModel):
    issue: str


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


async def snapshot_ticket(thread_id: str, issue: str | None = None) -> dict | None:
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
            INSERT INTO aida_tickets (thread_id, issue, status, current_specialist, requires_approval, last_message)
            VALUES (%(thread_id)s, %(issue)s, %(status)s, %(current_specialist)s, %(requires_approval)s, %(last_message)s)
            ON CONFLICT (thread_id) DO UPDATE SET
                status = EXCLUDED.status,
                current_specialist = EXCLUDED.current_specialist,
                requires_approval = EXCLUDED.requires_approval,
                last_message = EXCLUDED.last_message,
                updated_at = now()
            RETURNING issue, learned, forgotten, created_at, updated_at
            """,
            {**ticket, "issue": issue},
        )).fetchone()

    # Ticket learning: add newly resolved tickets to the knowledge base (once per ticket)
    if not row["learned"] and not row["forgotten"] and should_learn(ticket["status"], ticket["current_specialist"], ticket["last_message"]):
        try:
            await learn_from_ticket(thread_id, row["issue"], ticket["current_specialist"], ticket["last_message"])
            async with db_pool.connection() as conn:
                await conn.execute("UPDATE aida_tickets SET learned = TRUE WHERE thread_id = %s", (thread_id,))
            row["learned"] = True
        except Exception as e:
            # Learning is best-effort; never fail the ticket because the knowledge base is unavailable
            print(f"[Learning] Could not add ticket {thread_id[:8]} to the knowledge base: {e}")

    return {**ticket, **row}


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
        repaired += 1
    return repaired


@app.get("/")
async def root():
    return {"message": "Project AIDA Backend is Running! Go to http://127.0.0.1:8006/docs to interact with the API."}


@api.post("/tickets")
async def create_ticket(request: TicketRequest):
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    initial_state = {"messages": [HumanMessage(content=request.issue)]}

    async for _ in aida_graph.astream(initial_state, config=config):
        pass

    return await snapshot_ticket(thread_id, issue=request.issue)


@api.get("/tickets")
async def list_tickets(limit: int = 50):
    """Most recent tickets first, read from Postgres (survives restarts)."""
    limit = max(1, min(limit, 200))
    async with db_pool.connection() as conn:
        rows = await (await conn.execute(
            """
            SELECT thread_id, issue, status, current_specialist, requires_approval,
                   last_message, learned, forgotten, created_at, updated_at
            FROM aida_tickets
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )).fetchall()
    return rows


@api.get("/tickets/{thread_id}")
async def get_ticket(thread_id: str):
    ticket = await snapshot_ticket(thread_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@api.post("/tickets/{thread_id}/approve")
async def approve_remediation(thread_id: str, request: ApprovalRequest):
    config = {"configurable": {"thread_id": thread_id}}
    state = await aida_graph.aget_state(config)

    if not state.values:
        raise HTTPException(status_code=404, detail="Ticket not found")

    requires_approval = state.next and "remediate_tools" in state.next
    if not requires_approval:
        raise HTTPException(status_code=400, detail="No pending actions require approval")

    if request.approved:
        async for _ in aida_graph.astream(None, config=config):
            pass
        ticket = await snapshot_ticket(thread_id)
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
    return {"message": "Remediation denied. No action was taken.", **ticket}


@api.post("/tickets/{thread_id}/forget")
async def forget_learned_ticket(thread_id: str):
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
    return {"thread_id": thread_id, "learned": False, "forgotten": True}


@api.get("/metrics")
async def metrics():
    """Live numbers for the dashboard."""
    async with db_pool.connection() as conn:
        counts = await (await conn.execute(
            """
            SELECT count(*) AS tickets_total,
                   count(*) FILTER (WHERE requires_approval) AS pending_approvals,
                   count(*) FILTER (WHERE status = 'resolved') AS tickets_resolved,
                   count(*) FILTER (WHERE status = 'denied') AS tickets_denied,
                   count(*) FILTER (WHERE learned) AS tickets_learned
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
