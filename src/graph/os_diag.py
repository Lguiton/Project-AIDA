from langchain_core.prompts import ChatPromptTemplate
from src.graph.state import AidaState

async def os_diag_specialist_node(state: AidaState, llm, tools) -> dict:
    messages = state.get("messages", [])
    system_prompt = (
        "You are the OS Diagnostics Specialist. "
        "Investigate operating-system problems such as slowness, freezes, crashes, high CPU or memory use, "
        "and low disk space. Use the provided read-only tools to gather real evidence from the host "
        "(system info, disk usage, top processes, service status) before drawing conclusions. "
        "Judge CPU pressure by comparing the load average to the number of CPUs: a load well below the CPU count "
        "means the machine is mostly idle, even if one process briefly shows high CPU. "
        "Process CPU figures are percent of one core (100% = one full core). "
        "Only call something a problem if the numbers support it; if everything looks healthy, say so plainly. "
        "Then give a clear diagnosis that cites the numbers you observed, and recommend next steps. "
        "Do not claim to have changed anything on the system."
    )
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("placeholder", "{messages}")])

    agent_llm = llm.bind_tools(tools)
    response = await (prompt | agent_llm).ainvoke({"messages": messages})
    # A reply with no pending tool calls is the specialist's final answer
    status = "in_progress" if getattr(response, "tool_calls", None) else "resolved"
    return {"messages": [response], "current_specialist": "os_diag", "ticket_status": status}
