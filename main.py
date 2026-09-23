import sys
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

from langchain_mcp_adapters.client import MultiServerMCPClient
from src.graph.graph import compile_aida_graph

load_dotenv()

aida_graph = None
mcp_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global aida_graph, mcp_client
    print("\n[System] Connecting to MCP Server...")
    
    # 1. Use sys.executable to strictly enforce the virtual environment Python
    mcp_client = MultiServerMCPClient({
        "aida_diagnostics": {
            "command": sys.executable,
            "args": ["mcp_server.py"],
            "transport": "stdio",
        }
    })
    
    # 2. Fetch tools dynamically from the MCP server
    tools = await mcp_client.get_tools()
    print(f"[System] Fetched {len(tools)} tools via MCP: {[t.name for t in tools]}")
    
    # 3. Route tools to the correct agents
    def pick(*names):
        return [t for t in tools if t.name in names]

    net_tools = pick("ping_host", "resolve_dns", "get_adapter_status")
    rem_tools = pick("flush_dns_cache")
    os_tools = pick("get_system_info", "check_disk_usage", "list_top_processes")
    sec_tools = pick("list_listening_ports", "list_recent_logins")
    
    # 4. Compile the graph with injected tools
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
    aida_graph = compile_aida_graph(llm, net_tools, rem_tools, os_tools, sec_tools)
    
    print("[System] Project AIDA API Ready.")
    
    yield
    
    print("\n[System] Shutting down MCP Server...")
    if hasattr(mcp_client, "close") and callable(mcp_client.close):
        await mcp_client.close()

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
        
    state = aida_graph.get_state(config)
    requires_approval = state.next and "remediate_tools" in state.next
    last_message = describe_last_message(state.values)
    
    return {
        "thread_id": thread_id,
        "status": state.values.get("ticket_status", "unknown"),
        "current_specialist": state.values.get("current_specialist", "unknown"),
        "requires_approval": bool(requires_approval),
        "last_message": last_message
    }

@app.get("/api/tickets/{thread_id}")
async def get_ticket(thread_id: str):
    config = {"configurable": {"thread_id": thread_id}}
    state = aida_graph.get_state(config)
    
    if not state.values:
        raise HTTPException(status_code=404, detail="Ticket not found")
        
    requires_approval = state.next and "remediate_tools" in state.next
    last_message = describe_last_message(state.values)
    
    return {
        "thread_id": thread_id,
        "status": state.values.get("ticket_status", "unknown"),
        "current_specialist": state.values.get("current_specialist", "unknown"),
        "requires_approval": bool(requires_approval),
        "last_message": last_message
    }

@app.post("/api/tickets/{thread_id}/approve")
async def approve_remediation(thread_id: str, request: ApprovalRequest):
    config = {"configurable": {"thread_id": thread_id}}
    state = aida_graph.get_state(config)
    
    if not state.values:
        raise HTTPException(status_code=404, detail="Ticket not found")
        
    requires_approval = state.next and "remediate_tools" in state.next
    if not requires_approval:
        raise HTTPException(status_code=400, detail="No pending actions require approval")
        
    if request.approved:
        async for _ in aida_graph.astream(None, config=config):
            pass
        final_state = aida_graph.get_state(config)
        last_message = describe_last_message(final_state.values)
        return {"message": "Remediation approved and executed.", "last_message": last_message}
    else:
        return {"message": "Remediation denied. Ticket paused."}