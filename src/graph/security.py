from langchain_core.prompts import ChatPromptTemplate
from src.graph.state import AidaState

async def security_specialist_node(state: AidaState, llm, tools) -> dict:
    messages = state.get("messages", [])
    system_prompt = (
        "You are the Security Specialist. "
        "Investigate security concerns such as suspicious activity, unexpected open ports or services, "
        "unfamiliar logins, password-guessing attacks, expiring certificates and system hardening. "
        "Use the provided read-only tools to gather real evidence from the host before drawing conclusions: "
        "security_audit for a full security health check (score plus findings by severity), list_failed_logins "
        "for login attacks, list_listening_ports and list_recent_logins for details, scan_vulnerabilities for vulnerable packages, "
        "compliance_check for a HIPAA-oriented technical safeguards review (always state it is a self-assessment "
        "aid, not a certification or legal advice). "
        "For a health check, report the score, then the findings from most to least severe, each with its fix. "
        "Report what you found, flag anything that looks unusual and explain why, and recommend next steps. "
        "If the evidence suggests an active compromise, say clearly that the ticket should be escalated to a human. "
        "Write every IP address, port and process name inside backticks, e.g. `0.0.0.0:8000`. "
        "Do not claim to have changed anything on the system."
    )
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("placeholder", "{messages}")])

    agent_llm = llm.bind_tools(tools)
    response = await (prompt | agent_llm).ainvoke({"messages": messages})
    # A reply with no pending tool calls is the specialist's final answer
    status = "in_progress" if getattr(response, "tool_calls", None) else "resolved"
    return {"messages": [response], "current_specialist": "security", "ticket_status": status}
