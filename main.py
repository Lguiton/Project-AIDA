import sys
import uuid
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load .env before importing modules that read environment variables
load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from src.db import DB_URI, KB_COLLECTION, TICKETS_TABLE_SQL
from src.graph.graph import compile_aida_graph

aida_graph = None
mcp_client = None
db_pool = None

# Graph nodes that are not AI agents (tool executors, routing sentinels, the human hand-off)
NON_AGENT_NODES = {"__start__", "__end__", "human_escalation"}


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
        await conn.execute(TICKETS_TABLE_SQL)
    print("[System] Postgres ready (tickets persist across restarts).")

    # 2. MCP tools. sys.executable enforces the virtual environment's Python
    print("[System] Connecting to MCP Server...")
    mcp_client = MultiServerMCPClient({
        "aida_diagnostics": {
            "command": sys.executable,
            "args": ["mcp_server.py"],
            "transport": "stdio",
        }
    })
    tools = await mcp_client.get_tools()
    print(f"[System] Fetched {len(tools)} tools via MCP: {[t.name for t in tools]}")

    # 3. Route tools to the correct agents
    def pick(*names):
        return [t for t in tools if t.name in names]

    net_tools = pick("ping_host", "resolve_dns", "get_adapter_status")
    rem_tools = pick("flush_dns_cache")
    os_tools = pick("get_system_info", "check_disk_usage", "list_top_processes")
    sec_tools = pick("list_listening_ports", "list_recent_logins")

    # 4. Compile the graph with injected tools and the Postgres checkpointer
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    aida_graph = compile_aida_graph(llm, net_tools, rem_tools, os_tools, sec_tools, checkpointer=checkpointer)

    print("[System] Project AIDA API Ready.")

    yield

    print("\n[System] Shutting down MCP Server...")
    if hasattr(mcp_client, "close") and callable(mcp_client.close):
        await mcp_client.close()
    await db_pool.close()


app = FastAPI(title="Project AIDA API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
            RETURNING issue, created_at, updated_at
            """,
            {**ticket, "issue": issue},
        )).fetchone()
    return {**ticket, **row}


@app.get("/")
async def root():
    return {"message": "Project AIDA Backend is Running! Go to http://127.0.0.1:8006/docs to interact with the API."}


@app.post("/api/tickets")
async def create_ticket(request: TicketRequest):
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    initial_state = {"messages": [HumanMessage(content=request.issue)]}

    async for _ in aida_graph.astream(initial_state, config=config):
        pass

    return await snapshot_ticket(thread_id, issue=request.issue)


@app.get("/api/tickets")
async def list_tickets(limit: int = 50):
    """Most recent tickets first, read from Postgres (survives restarts)."""
    limit = max(1, min(limit, 200))
    async with db_pool.connection() as conn:
        rows = await (await conn.execute(
            """
            SELECT thread_id, issue, status, current_specialist, requires_approval,
                   last_message, created_at, updated_at
            FROM aida_tickets
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (limit,),
        )).fetchall()
    return rows


@app.get("/api/tickets/{thread_id}")
async def get_ticket(thread_id: str):
    ticket = await snapshot_ticket(thread_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@app.post("/api/tickets/{thread_id}/approve")
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
    else:
        return {"message": "Remediation denied. Ticket paused."}


@app.get("/api/metrics")
async def metrics():
    """Live numbers for the dashboard."""
    async with db_pool.connection() as conn:
        counts = await (await conn.execute(
            """
            SELECT count(*) AS tickets_total,
                   count(*) FILTER (WHERE requires_approval) AS pending_approvals,
                   count(*) FILTER (WHERE status = 'resolved') AS tickets_resolved
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
