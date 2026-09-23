from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import OpenAIEmbeddings
from langchain_postgres import PGVector
from sqlalchemy.ext.asyncio import create_async_engine
from src.graph.state import AidaState

CONNECTION_STRING = "postgresql+psycopg://aida:aida_password@localhost:55432/aida_kb"
COLLECTION_NAME = "historical_tickets"

# Initialize the async engine globally so it pools connections efficiently across node executions
async_engine = create_async_engine(CONNECTION_STRING)

async def knowledge_specialist_node(state: AidaState, llm) -> dict:
    messages = state.get("messages", [])
    user_issue = messages[0].content 
    
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
    
    # Pass the async_engine explicitly instead of the raw connection string
    vector_store = PGVector(
        embeddings=embeddings,
        collection_name=COLLECTION_NAME,
        connection=async_engine,
        use_jsonb=True,
    )
    
    docs = await vector_store.asimilarity_search(user_issue, k=2)
    context = "\n\n".join([f"Ticket {d.metadata['ticket_id']}: {d.page_content}" for d in docs])
    
    system_prompt = (
        "You are the Knowledge Base Specialist. "
        "Review the following historical IT tickets to see if this issue has been solved before.\n\n"
        "Historical Context:\n{context}\n\n"
        "If a relevant resolution exists, provide the steps to the user. "
        "If not, state that you could not find a historical precedent."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("placeholder", "{messages}")
    ])
    
    response = await (prompt | llm).ainvoke({
        "context": context,
        "messages": messages
    })
    
    return {"messages": [response], "current_specialist": "knowledge", "ticket_status": "resolved"}
