"""
Shared test setup.

Tests never call OpenAI and never change your system:
- the AI model is replaced by a scripted fake (tests/fakes.py)
- embeddings are replaced by deterministic fake vectors
- API tests use a separate Postgres database, aida_test, on the same server as AIDA
- the only remediation that is approved in tests is clear_temp_files, pointed at a temp folder
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)  # main.py starts mcp_server.py by relative path

BASE_DB_URI = os.getenv("AIDA_DB_URI", "postgresql://aida:aida_password@localhost:55432/aida_kb")
TEST_DB_NAME = "aida_test"
TEST_DB_URI = BASE_DB_URI.rsplit("/", 1)[0] + "/" + TEST_DB_NAME

# Must be set before any AIDA module is imported (src.db reads it at import time)
os.environ["AIDA_DB_URI"] = TEST_DB_URI
os.environ["AIDA_API_KEY"] = "test-api-key"
os.environ["AIDA_UI_PASSWORD"] = "test-password"
os.environ["AIDA_MONITOR_INTERVAL"] = "0"  # tests trigger monitoring runs explicitly
os.environ["AIDA_SCHEDULER_INTERVAL"] = "0"  # tests run schedules explicitly
os.environ["AIDA_MONITOR_WINDOWS"] = "off"  # Windows tests use a fake powershell.exe
os.environ.setdefault("OPENAI_API_KEY", "not-used-in-tests")


def _postgres_available() -> str | None:
    """Create the test database if needed. Returns an error message if Postgres is unreachable."""
    try:
        import psycopg
        with psycopg.connect(BASE_DB_URI, autocommit=True, connect_timeout=3) as conn:
            exists = conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (TEST_DB_NAME,)).fetchone()
            if not exists:
                conn.execute(f'CREATE DATABASE "{TEST_DB_NAME}"')
        with psycopg.connect(TEST_DB_URI, autocommit=True) as conn:
            conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
        return None
    except Exception as e:
        return str(e)


@pytest.fixture(scope="session")
def test_db():
    error = _postgres_available()
    if error:
        pytest.skip(f"Postgres not reachable (start it with 'docker compose up -d'): {error}")
    import psycopg
    with psycopg.connect(TEST_DB_URI, autocommit=True) as conn:
        conn.execute("DROP TABLE IF EXISTS aida_tickets")
        conn.execute("DROP TABLE IF EXISTS aida_audit")
        conn.execute("DROP TABLE IF EXISTS aida_users")
        conn.execute("DROP TABLE IF EXISTS aida_schedules")
        conn.execute("DROP TABLE IF EXISTS aida_products")
        conn.execute("DROP TABLE IF EXISTS aida_product_errors")
        conn.execute("DROP TABLE IF EXISTS aida_machines")
        conn.execute("DROP TABLE IF EXISTS aida_product_health")
    return TEST_DB_URI


@pytest.fixture
def temp_dir_for_tools(tmp_path, monkeypatch):
    """clear_temp_files only ever touches this folder during tests (the MCP server inherits the env var)."""
    monkeypatch.setenv("AIDA_TEMP_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def api_client(test_db, temp_dir_for_tools, monkeypatch):
    """Factory for TestClients running the real API with the fake model and fake embeddings.
    Each `with make_client() as client:` is a full app start/stop, like restarting uvicorn."""
    from fastapi.testclient import TestClient
    from langchain_core.embeddings import DeterministicFakeEmbedding

    import main
    import src.kb.store as store
    from tests.fakes import FakeChatModel

    monkeypatch.setattr(main, "ChatOpenAI", lambda **kwargs: FakeChatModel())
    monkeypatch.setattr(store, "embeddings_factory", lambda: DeterministicFakeEmbedding(size=16))

    def make_client(api_key: str | None = "test-api-key"):
        headers = {"X-AIDA-Key": api_key} if api_key else {}
        return TestClient(main.app, headers=headers)

    return make_client


def login(client, username: str, password: str) -> dict:
    """Sign in through the API and return headers carrying that user's session token."""
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"X-AIDA-User-Token": response.json()["token"]}


def make_user(client, username: str, role: str, password: str = "correct-horse-1") -> dict:
    """Create a user as the admin service account (API key only) and return their headers."""
    response = client.post("/api/users", json={"username": username, "password": password, "role": role})
    assert response.status_code in (200, 409), response.text
    return login(client, username, password)
