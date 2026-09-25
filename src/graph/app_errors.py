from langchain_core.prompts import ChatPromptTemplate

from src.graph.state import AidaState


async def app_errors_specialist_node(state: AidaState, llm) -> dict:
    """Diagnoses errors and outages reported by connected products (Eivanta Analytics and others)."""
    messages = state.get("messages", [])
    system_prompt = (
        "You are the Application Reliability Specialist for Eivanta Labs' SaaS products. "
        "You receive error reports (exception type, route, tenant ID, scrubbed message, stack trace) and "
        "health-check failures from connected products. Write a short diagnosis with these parts: "
        "Summary (one sentence); Likely root cause (cite the file, line and function from the stack trace; "
        "you cannot see the full source, so say exactly what to check rather than inventing code); "
        "NEVER name a file, line number or function that is not written in the report -- a health-check failure has "
        "no stack trace, so reason from the check result instead: 'HTTP 404' means nothing answers at that address "
        "(the health URL is wrong, a different or older app is running on that port, or this version lacks the "
        "endpoint); 'connection refused' or 'failed' means the product is not running or not reachable; 'HTTP 5xx' "
        "means the product is up but erroring; 'reports degraded' means the product is up but a dependency (e.g. its "
        "database) is failing. Recommend the checks in that order before any code change. "
        "If the report says it is a deliberate test report, say the connection works, give severity low, recommend "
        "marking it resolved, and do not recommend code changes. "
        "Impact (which route; one tenant or possibly all tenants; whether it could lose or corrupt data); "
        "Recommended fix (the concrete code or configuration change to make, and a test that would catch it); "
        "Severity (low, medium, high or critical, with one reason). "
        "Never ask the user for more data, never repeat tenant identifiers beyond the tenant ID given, "
        "and do not claim anything was changed or fixed."
    )
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("placeholder", "{messages}")])
    response = await (prompt | llm).ainvoke({"messages": messages})
    # Diagnosed, not resolved: an operator closes the ticket once the fix is deployed
    return {"messages": [response], "current_specialist": "app_errors", "ticket_status": "diagnosed"}
