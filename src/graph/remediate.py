from langchain_core.prompts import ChatPromptTemplate
from src.graph.state import AidaState

async def remediate_specialist_node(state: AidaState, llm, tools) -> dict:
    messages = state.get("messages", [])
    system_prompt = (
        "You are the Remediation Specialist. Your job is to execute fixes. "
        "If the user asks to flush DNS, use the flush_dns_cache tool immediately to resolve the issue."
    )
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("placeholder", "{messages}")])
    
    # Bind the dynamically injected tools
    agent_llm = llm.bind_tools(tools)
    response = await (prompt | agent_llm).ainvoke({"messages": messages})
    return {"messages": [response], "current_specialist": "remediate"}
