from langchain_core.prompts import ChatPromptTemplate
from src.graph.state import AidaState

async def network_specialist_node(state: AidaState, llm, tools) -> dict:
    messages = state.get("messages", [])
    system_prompt = (
        "You are the Network Diagnostics Specialist. "
        "Use the provided tools to check connectivity. Once isolated, output a diagnosis."
    )
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("placeholder", "{messages}")])
    
    # Bind the dynamically injected tools
    agent_llm = llm.bind_tools(tools)
    response = await (prompt | agent_llm).ainvoke({"messages": messages})
    # A reply with no pending tool calls is the specialist's final answer
    status = "in_progress" if getattr(response, "tool_calls", None) else "resolved"
    return {"messages": [response], "current_specialist": "network", "ticket_status": status}
