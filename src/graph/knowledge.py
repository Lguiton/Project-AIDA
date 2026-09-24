from langchain_core.prompts import ChatPromptTemplate

from src.graph.state import AidaState
from src.kb.store import get_vector_store


async def knowledge_specialist_node(state: AidaState, llm) -> dict:
    messages = state.get("messages", [])
    user_issue = messages[0].content

    # Seeded tickets plus tickets AIDA has resolved and learned from
    docs = await get_vector_store().asimilarity_search(user_issue, k=3)
    context = "\n\n".join(f"Ticket {d.metadata.get('ticket_id', 'unknown')}: {d.page_content}" for d in docs)

    system_prompt = (
        "You are the Knowledge Base Specialist. "
        "Review the following historical IT tickets to see if this issue has been solved before.\n\n"
        "Historical Context:\n{context}\n\n"
        "If a relevant resolution exists, provide the steps to the user and cite the ticket id. "
        "If not, state that you could not find a historical precedent."
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("placeholder", "{messages}")
    ])

    response = await (prompt | llm).ainvoke({
        "context": context or "(no historical tickets found)",
        "messages": messages
    })

    return {"messages": [response], "current_specialist": "knowledge", "ticket_status": "resolved"}
