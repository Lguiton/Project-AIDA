import os

# Postgres from docker-compose.yml (pgvector image). Override with AIDA_DB_URI in .env if needed.
DB_URI = os.getenv("AIDA_DB_URI", "postgresql://aida:aida_password@localhost:55432/aida_kb")

# Collection name used by src/kb/setup.py and the knowledge specialist
KB_COLLECTION = "historical_tickets"

TICKETS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS aida_tickets (
    thread_id          TEXT PRIMARY KEY,
    issue              TEXT NOT NULL,
    status             TEXT,
    current_specialist TEXT,
    requires_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    last_message       TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""
