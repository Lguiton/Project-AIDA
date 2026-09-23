from langchain_core.prompts import ChatPromptTemplate
from src.graph.state import AidaState

async def security_specialist_node(state: AidaState, llm, tools) -> dict:
    messages = state.get("messages", [])
    system_prompt = (
        "You are the Security Specialist. "
        "Investigate security concerns such as suspicious activity, unexpected open ports or services, "
        "and unfamiliar logins. Use the provided read-only tools (listening ports, recent logins) to gather "
        "real evidence from the host before drawing conclusions. "
        "Report what you found, flag anything that looks unusual and explain why, and recommend next steps. "
        "If the evidence suggests an active compromise, say clearly that the ticket should be escalated to a human. "
        "Do not claim to have changed anything on the system."
    )
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("placeholder", "{messages}")])

    agent_llm = llm.bind_tools(tools)
    response = await (prompt | agent_llm).ainvoke({"messages": messages})
    # A reply with no pending tool calls is the specialist's final answer
    status = "in_progress" if getattr(response, "tool_calls", None) else "resolved"
    return {"messages": [response], "current_specialist": "security", "ticket_status": status}
