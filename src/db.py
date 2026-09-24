import os

# Postgres from docker-compose.yml (pgvector image). Override with AIDA_DB_URI in .env if needed.
DB_URI = os.getenv("AIDA_DB_URI", "postgresql://aida:aida_password@localhost:55432/aida_kb")

# SQLAlchemy (used by langchain-postgres) needs the driver named in the URL
SQLALCHEMY_URI = DB_URI.replace("postgresql://", "postgresql+psycopg://", 1) if DB_URI.startswith("postgresql://") else DB_URI

# Collection name used by src/kb/setup.py, the knowledge specialist and ticket learning
KB_COLLECTION = "historical_tickets"

# Run in order at startup (one statement each: psycopg sends one command per execute)
TICKETS_TABLE_SQL = (
    """
    CREATE TABLE IF NOT EXISTS aida_tickets (
        thread_id          TEXT PRIMARY KEY,
        issue              TEXT NOT NULL,
        status             TEXT,
        current_specialist TEXT,
        requires_approval  BOOLEAN NOT NULL DEFAULT FALSE,
        last_message       TEXT,
        learned            BOOLEAN NOT NULL DEFAULT FALSE,
        forgotten          BOOLEAN NOT NULL DEFAULT FALSE,
        created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    # Upgrade tables created before ticket learning existed
    "ALTER TABLE aida_tickets ADD COLUMN IF NOT EXISTS learned BOOLEAN NOT NULL DEFAULT FALSE",
    # Operator removed the ticket from the knowledge base; never re-learn it
    "ALTER TABLE aida_tickets ADD COLUMN IF NOT EXISTS forgotten BOOLEAN NOT NULL DEFAULT FALSE",
    # Where the ticket came from ('user' or 'monitor') and, for monitoring tickets, which alert
    "ALTER TABLE aida_tickets ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'user'",
    "ALTER TABLE aida_tickets ADD COLUMN IF NOT EXISTS alert_key TEXT",
    "CREATE INDEX IF NOT EXISTS aida_tickets_alert_key ON aida_tickets (alert_key) WHERE alert_key IS NOT NULL",
)
