from typing import Literal
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from src.graph.state import AidaState

class RouteDecision(BaseModel):
    destination: Literal["network", "remediate", "knowledge", "os_diag", "security", "human_escalation"] = Field(
        description="The specialist agent to route the ticket to."
    )

async def triage_router_node(state: AidaState, llm) -> dict:
    messages = state.get("messages", [])
    
    system_prompt = (
        "You are the Cognitive Router for Project AIDA, an autonomous IT Help Desk. "
        "Analyze the user's IT issue and route it to the exact correct specialist.\n\n"
        "ROUTING RULES:\n"
        "1. 'knowledge' -> Use this IF the issue contains specific error codes (e.g., Error 412, BSOD, SYSTEM_SERVICE_EXCEPTION) or asks about past/historical issues.\n"
        "2. 'remediate' -> Use this IF the user explicitly requests an action, fix, or remediation (e.g., 'flush my DNS', 'reset the password').\n"
        "3. 'network' -> Use this IF the issue is strictly about live connectivity, cannot reach a website, or internet outages.\n"
        "4. 'human_escalation' -> Use this if the issue is completely unrelated to IT.\n\n"
        "Failure to route correctly will break the system. Route based strictly on the rules above."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("placeholder", "{messages}")
    ])
    
    # Force the LLM to output a valid JSON matching our Pydantic schema
    router_llm = llm.with_structured_output(RouteDecision)
    decision = await (prompt | router_llm).ainvoke({"messages": messages})
    
    return {"current_specialist": decision.destination, "ticket_status": "in_progress"}

def router_edge(state: AidaState) -> str:
    return state.get("current_specialist", "human_escalation")