from functools import partial
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver

from src.graph.state import AidaState
from src.graph.router import triage_router_node, router_edge
from src.graph.network import network_specialist_node
from src.graph.remediate import remediate_specialist_node
from src.graph.knowledge import knowledge_specialist_node

async def mock_escalation_node(state: AidaState):
    return {"ticket_status": "escalated"}

async def mock_specialist_node(state: AidaState):
    return {"ticket_status": "in_progress"}

def compile_aida_graph(llm, network_tools, remediation_tools):
    workflow = StateGraph(AidaState)

    # Inject the LLM and the dynamically provided tools into each node
    bound_router = partial(triage_router_node, llm=llm)
    bound_network = partial(network_specialist_node, llm=llm, tools=network_tools)
    bound_remediate = partial(remediate_specialist_node, llm=llm, tools=remediation_tools)
    bound_knowledge = partial(knowledge_specialist_node, llm=llm)

    workflow.add_node("triage", bound_router)
    
    workflow.add_node("network", bound_network)
    workflow.add_node("network_tools", ToolNode(network_tools))
    
    workflow.add_node("remediate", bound_remediate)
    workflow.add_node("remediate_tools", ToolNode(remediation_tools))
    
    workflow.add_node("knowledge", bound_knowledge)

    workflow.add_node("os_diag", mock_specialist_node)
    workflow.add_node("security", mock_specialist_node)
    workflow.add_node("human_escalation", mock_escalation_node)

    workflow.add_edge(START, "triage")
    workflow.add_conditional_edges("triage", router_edge, {
        "network": "network", "os_diag": "os_diag", "security": "security",
        "remediate": "remediate", "knowledge": "knowledge",
        "human_escalation": "human_escalation"
    })

    workflow.add_conditional_edges("network", tools_condition, {"tools": "network_tools", "__end__": END})
    workflow.add_edge("network_tools", "network")

    workflow.add_conditional_edges("remediate", tools_condition, {"tools": "remediate_tools", "__end__": END})
    workflow.add_edge("remediate_tools", "remediate")

    workflow.add_edge("knowledge", END)
    workflow.add_edge("os_diag", END)
    workflow.add_edge("security", END)
    workflow.add_edge("human_escalation", END)

    memory = MemorySaver()
    return workflow.compile(checkpointer=memory, interrupt_before=["remediate_tools"])