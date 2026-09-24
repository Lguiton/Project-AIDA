from dotenv import load_dotenv
from langchain_openai import OpenAIEmbeddings
from langchain_postgres import PGVector
from langchain_core.documents import Document

load_dotenv()

from src.db import KB_COLLECTION as COLLECTION_NAME, SQLALCHEMY_URI as CONNECTION_STRING

def seed_database():
    print("Initializing pgvector database...")
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
    
    # Passing a string defaults to a synchronous SQLAlchemy engine
    vector_store = PGVector(
        embeddings=embeddings,
        collection_name=COLLECTION_NAME,
        connection=CONNECTION_STRING,
        use_jsonb=True,
    )
    
    vector_store.create_collection()
    
    docs = [
        Document(
            page_content="User reported Error 0x80070057 when trying to update Windows. Resolution: Cleared the SoftwareDistribution folder and restarted the Windows Update service.",
            metadata={"ticket_id": "INC-1042", "category": "OS"}
        ),
        Document(
            page_content="User unable to connect to the corporate VPN. Client throws Error 412. Resolution: The user's account was locked in Active Directory. Unlocked account and forced password reset.",
            metadata={"ticket_id": "INC-1088", "category": "Security"}
        ),
        Document(
            page_content="Blue screen of death (BSOD) with error code SYSTEM_SERVICE_EXCEPTION after recent driver update. Resolution: Booted into Safe Mode and rolled back the Nvidia display driver.",
            metadata={"ticket_id": "INC-1105", "category": "Hardware"}
        )
    ]
    
    print(f"Adding {len(docs)} historical tickets to pgvector...")
    # Fixed ids so running setup again updates the seed tickets instead of duplicating them
    vector_store.add_documents(docs, ids=[f"seed-{d.metadata['ticket_id']}" for d in docs])
    print("Seeding complete.")

if __name__ == "__main__":
    seed_database()