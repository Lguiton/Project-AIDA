"""
Tamper-evident audit log.

Every important action (ticket created, remediation approved/denied/executed, knowledge changes,
monitoring alerts) is appended to `aida_audit`. Each entry stores the SHA-256 hash of its own content
plus the previous entry's hash, forming a chain: changing or deleting any past entry breaks every hash
after it, which `verify_chain` detects. A database trigger also blocks UPDATE, DELETE and TRUNCATE.
"""
import hashlib
import json
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64
_LOCK_ID = 7_424_242  # serialises appends so the chain never forks

AUDIT_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS aida_audit (
        id         BIGSERIAL PRIMARY KEY,
        ts         TEXT NOT NULL,
        actor      TEXT NOT NULL,
        action     TEXT NOT NULL,
        thread_id  TEXT,
        details    JSONB NOT NULL DEFAULT '{}'::jsonb,
        prev_hash  TEXT NOT NULL,
        hash       TEXT NOT NULL
    )
    """,
    """
    CREATE OR REPLACE FUNCTION aida_audit_block_changes() RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'aida_audit is append-only: % is not allowed', TG_OP;
    END
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS aida_audit_no_change ON aida_audit",
    """
    CREATE TRIGGER aida_audit_no_change BEFORE UPDATE OR DELETE ON aida_audit
    FOR EACH ROW EXECUTE FUNCTION aida_audit_block_changes()
    """,
    "DROP TRIGGER IF EXISTS aida_audit_no_truncate ON aida_audit",
    """
    CREATE TRIGGER aida_audit_no_truncate BEFORE TRUNCATE ON aida_audit
    FOR EACH STATEMENT EXECUTE FUNCTION aida_audit_block_changes()
    """,
)


def _entry_hash(prev_hash: str, ts: str, actor: str, action: str, thread_id: str | None, details: dict) -> str:
    payload = json.dumps(
        {"ts": ts, "actor": actor, "action": action, "thread_id": thread_id, "details": details},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
    )
    return hashlib.sha256((prev_hash + payload).encode()).hexdigest()


async def ensure_audit_schema(pool) -> None:
    async with pool.connection() as conn:
        for statement in AUDIT_SCHEMA_SQL:
            await conn.execute(statement)


async def record(pool, actor: str, action: str, thread_id: str | None = None, details: dict | None = None) -> dict:
    """Append one entry to the audit chain and return it."""
    # Round-trip through JSON so the hash covers exactly what the database will store and return
    details = json.loads(json.dumps(details or {}, default=str))
    ts = datetime.now(timezone.utc).isoformat()
    async with pool.connection() as conn:
        async with conn.transaction():
            await conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_ID,))
            last = await (await conn.execute("SELECT hash FROM aida_audit ORDER BY id DESC LIMIT 1")).fetchone()
            prev_hash = last["hash"] if last else GENESIS_HASH
            entry_hash = _entry_hash(prev_hash, ts, actor, action, thread_id, details)
            row = await (await conn.execute(
                """
                INSERT INTO aida_audit (ts, actor, action, thread_id, details, prev_hash, hash)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)
                RETURNING id, ts, actor, action, thread_id, details, prev_hash, hash
                """,
                (ts, actor, action, thread_id, json.dumps(details), prev_hash, entry_hash),
            )).fetchone()
    return row


async def recent(pool, limit: int = 100, thread_id: str | None = None) -> list[dict]:
    query = "SELECT id, ts, actor, action, thread_id, details, hash FROM aida_audit"
    params: tuple = ()
    if thread_id:
        query += " WHERE thread_id = %s"
        params = (thread_id,)
    query += " ORDER BY id DESC LIMIT %s"
    async with pool.connection() as conn:
        return await (await conn.execute(query, params + (limit,))).fetchall()


async def verify_chain(pool) -> dict:
    """Recompute every hash from the start. Reports the first entry that no longer matches."""
    async with pool.connection() as conn:
        rows = await (await conn.execute(
            "SELECT id, ts, actor, action, thread_id, details, prev_hash, hash FROM aida_audit ORDER BY id"
        )).fetchall()
    expected_prev = GENESIS_HASH
    for row in rows:
        recomputed = _entry_hash(row["prev_hash"], row["ts"], row["actor"], row["action"], row["thread_id"], row["details"])
        if row["prev_hash"] != expected_prev or recomputed != row["hash"]:
            return {"ok": False, "entries": len(rows), "first_bad_id": row["id"],
                    "message": f"Audit log was altered at entry #{row['id']}; entries from there on cannot be trusted."}
        expected_prev = row["hash"]
    return {"ok": True, "entries": len(rows), "first_bad_id": None,
            "message": f"All {len(rows)} audit entries verified; the chain is intact."}
