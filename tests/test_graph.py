"""Routing and ticket status through the LangGraph workflow (in-memory checkpointer, no database)."""
import asyncio

import pytest
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool

from src.graph.graph import compile_aida_graph
from tests.fakes import FakeChatModel


@tool
def flush_dns_cache() -> str:
    """Fake flush."""
    return "SUCCESS: flushed"


@tool
def get_system_info() -> str:
    """Fake system info."""
    return "Load average 0.1 on 4 CPUs"


@tool
def list_listening_ports() -> str:
    """Fake ports."""
    return "tcp 22 sshd all interfaces"


@tool
def resolve_dns(hostname: str) -> str:
    """Fake DNS."""
    return f"{hostname} resolves to 127.0.0.1"


def build():
    return compile_aida_graph(FakeChatModel(), [resolve_dns], [flush_dns_cache], [get_system_info], [list_listening_ports])


def run(graph, text, thread="t1"):
    config = {"configurable": {"thread_id": thread}}

    async def go():
        async for _ in graph.astream({"messages": [HumanMessage(content=text)]}, config=config):
            pass
        return await graph.aget_state(config)

    return asyncio.run(go())


@pytest.mark.parametrize("issue,specialist", [
    ("my computer is slow", "os_diag"),
    ("which ports are open", "security"),
    ("I can't reach google.com", "network"),
])
def test_read_only_specialists_run_tools_and_resolve(issue, specialist):
    state = run(build(), issue)
    assert state.values["current_specialist"] == specialist
    assert state.values["ticket_status"] == "resolved"
    assert state.next == ()  # finished without waiting for approval
    assert "Tool result:" in state.values["messages"][-1].content


def test_remediation_pauses_for_approval():
    state = run(build(), "please flush my dns")
    assert state.values["current_specialist"] == "remediate"
    assert state.values["ticket_status"] == "in_progress"
    assert state.next == ("remediate_tools",)  # the destructive tool has NOT run


def test_unrelated_issue_is_escalated():
    state = run(build(), "what should I cook tonight")
    assert state.values["ticket_status"] == "escalated"
