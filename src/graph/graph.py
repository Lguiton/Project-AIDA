from functools import partial
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

from src.graph.state import AidaState
from src.graph.router import triage_router_node, router_edge
from src.graph.network import network_specialist_node
from src.graph.remediate import remediate_specialist_node
from src.graph.knowledge import knowledge_specialist_node
from src.graph.os_diag import os_diag_specialist_node
from src.graph.security import security_specialist_node
from src.graph.app_errors import app_errors_specialist_node

async def mock_escalation_node(state: AidaState):
    return {"ticket_status": "escalated"}

def compile_aida_graph(llm, network_tools, remediation_tools, os_tools, security_tools, checkpointer=None):
    workflow = StateGraph(AidaState)

    # Inject the LLM and the dynamically provided tools into each node
    bound_router = partial(triage_router_node, llm=llm)
    bound_network = partial(network_specialist_node, llm=llm, tools=network_tools)
    bound_remediate = partial(remediate_specialist_node, llm=llm, tools=remediation_tools)
    bound_knowledge = partial(knowledge_specialist_node, llm=llm)
    bound_app_errors = partial(app_errors_specialist_node, llm=llm)
    bound_os_diag = partial(os_diag_specialist_node, llm=llm, tools=os_tools)
    bound_security = partial(security_specialist_node, llm=llm, tools=security_tools)

    workflow.add_node("triage", bound_router)
    
    workflow.add_node("network", bound_network)
    workflow.add_node("network_tools", ToolNode(network_tools))
    
    workflow.add_node("remediate", bound_remediate)
    workflow.add_node("remediate_tools", ToolNode(remediation_tools))
    
    workflow.add_node("knowledge", bound_knowledge)
    workflow.add_node("app_errors", bound_app_errors)

    workflow.add_node("os_diag", bound_os_diag)
    workflow.add_node("os_diag_tools", ToolNode(os_tools))

    workflow.add_node("security", bound_security)
    workflow.add_node("security_tools", ToolNode(security_tools))

    workflow.add_node("human_escalation", mock_escalation_node)

    workflow.add_edge(START, "triage")
    workflow.add_conditional_edges("triage", router_edge, {
        "network": "network", "os_diag": "os_diag", "security": "security",
        "remediate": "remediate", "knowledge": "knowledge", "app_errors": "app_errors",
        "human_escalation": "human_escalation"
    })

    workflow.add_conditional_edges("network", tools_condition, {"tools": "network_tools", "__end__": END})
    workflow.add_edge("network_tools", "network")

    workflow.add_conditional_edges("remediate", tools_condition, {"tools": "remediate_tools", "__end__": END})
    workflow.add_edge("remediate_tools", "remediate")

    workflow.add_edge("knowledge", END)
    workflow.add_edge("app_errors", END)
    workflow.add_conditional_edges("os_diag", tools_condition, {"tools": "os_diag_tools", "__end__": END})
    workflow.add_edge("os_diag_tools", "os_diag")

    workflow.add_conditional_edges("security", tools_condition, {"tools": "security_tools", "__end__": END})
    workflow.add_edge("security_tools", "security")

    workflow.add_edge("human_escalation", END)

    # Postgres checkpointer in production (tickets survive restarts); in-memory fallback for tests
    return workflow.compile(checkpointer=checkpointer or MemorySaver(), interrupt_before=["remediate_tools"])