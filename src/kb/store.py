"""Shared pgvector knowledge base used by the knowledge specialist and by ticket learning."""
from langchain_postgres import PGVector
from sqlalchemy.ext.asyncio import create_async_engine

from src.db import KB_COLLECTION, SQLALCHEMY_URI


def default_embeddings():
    from langchain_openai import OpenAIEmbeddings
    return OpenAIEmbeddings(model="text-embedding-3-small")


# Tests replace this with a fake so they never call OpenAI
embeddings_factory = default_embeddings

_engine = None
_store = None


def get_vector_store() -> PGVector:
    """One async vector store per running app (the engine pools its database connections)."""
    global _engine, _store
    if _store is None:
        _engine = create_async_engine(SQLALCHEMY_URI)
        _store = PGVector(
            embeddings=embeddings_factory(),
            collection_name=KB_COLLECTION,
            connection=_engine,
            use_jsonb=True,
        )
    return _store


async def close_vector_store() -> None:
    """Release database connections (called when the API shuts down)."""
    global _engine, _store
    if _engine is not None:
        await _engine.dispose()
    _engine, _store = None, None
