"""Ticket learning: resolved tickets are added to the knowledge base so similar issues are answered from history."""
from langchain_core.documents import Document

from src.kb.store import get_vector_store

# Specialists whose answers are not new knowledge (knowledge answers come from the KB itself)
NOT_LEARNED_FROM = {"knowledge", "human_escalation", "triage", "unknown"}
MAX_RESOLUTION_CHARS = 4000


# Tools whose output is a point-in-time report about this machine, not a reusable fix
SNAPSHOT_ONLY_TOOLS = {"security_audit", "scan_vulnerabilities", "compliance_check"}


def should_learn(status: str | None, specialist: str | None, resolution: str | None,
                 tools_used: set[str] | None = None) -> bool:
    if tools_used and tools_used <= SNAPSHOT_ONLY_TOOLS:
        return False  # e.g. a security score changes over time; replaying it later would mislead
    return status == "resolved" and specialist not in NOT_LEARNED_FROM and bool(resolution and resolution.strip())


async def learn_from_ticket(thread_id: str, issue: str, specialist: str, resolution: str) -> None:
    """Store the ticket as a historical case. Uses the ticket id as the document id, so repeats overwrite."""
    document = Document(
        page_content=(
            f"User reported: {issue.strip()}\n"
            f"Resolution ({specialist} specialist): {resolution.strip()[:MAX_RESOLUTION_CHARS]}"
        ),
        metadata={"ticket_id": f"AIDA-{thread_id[:8]}", "category": specialist, "source": "aida"},
    )
    await get_vector_store().aadd_documents([document], ids=[f"aida-{thread_id}"])


async def forget_ticket(thread_id: str) -> None:
    """Remove a learned ticket from the knowledge base (e.g. an operator judged it a bad answer)."""
    await get_vector_store().adelete(ids=[f"aida-{thread_id}"])
