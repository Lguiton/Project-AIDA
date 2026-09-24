from typing import Literal
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field
from src.graph.state import AidaState

class RouteDecision(BaseModel):
    destination: Literal["network", "remediate", "knowledge", "app_errors", "os_diag", "security", "human_escalation"] = Field(
        description="The specialist agent to route the ticket to."
    )

async def triage_router_node(state: AidaState, llm) -> dict:
    messages = state.get("messages", [])
    
    system_prompt = (
        "You are the Cognitive Router for Project AIDA, an autonomous IT Help Desk. "
        "Analyze the user's IT issue and route it to the exact correct specialist.\n\n"
        "ROUTING RULES:\n"
        "0. 'app_errors' -> Use this FIRST for any report from a connected product: text starting with '[Error reported by', an exception with a stack trace from an application, or a product/website health check failing ('is unhealthy', 'is down').\n"
        "1. 'knowledge' -> Use this IF the issue contains specific error codes (e.g., Error 412, BSOD, SYSTEM_SERVICE_EXCEPTION) or asks about past/historical issues.\n"
        "2. 'remediate' -> Use this IF the user explicitly requests an action, fix, or remediation (e.g., 'flush my DNS', 'restart the ssh service', 'clear my temp files', 'free up disk space', 'block the IP address 1.2.3.4', 'install security updates', 'restart the nginx container', 'run a Defender scan', 'update Defender', 'restart the print spooler', 'clear my Windows temp files').\n"
        "3. 'network' -> Use this IF the issue is strictly about live connectivity, cannot reach a website, DNS lookups, or internet outages.\n"
        "4. 'os_diag' -> Use this IF the machine is slow, freezing, running out of memory or disk space, a process is using too much CPU, or a service is failed or not running -- on Linux/WSL or on Windows (e.g. 'Windows is slow', 'my C: drive is full', 'Windows event log errors', 'a Windows service stopped').\n"
        "5. 'security' -> Use this IF the user reports suspicious activity, unknown logins, possible malware, asks which ports/services are exposed, failed or brute-force logins, a security health check/audit/hardening review, a vulnerability scan, a HIPAA/compliance check, TLS certificates, or Windows security (Microsoft Defender/antivirus status, Windows Firewall, Windows Update).\n"
        "6. 'human_escalation' -> Use this if the issue is completely unrelated to IT.\n\n"
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