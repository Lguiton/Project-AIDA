"""
Scheduled maintenance: run a runbook automatically at a set time (daily or weekly).

The admin who creates a schedule approves it in advance; each run is recorded in the audit log as
"schedule:<name>" together with who approved it, appears in the ticket queue, and sends a notification
if it fails. Times are in AIDA_TIMEZONE.
"""
import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]

SCHEDULES_SQL = (
    """
    CREATE TABLE IF NOT EXISTS aida_schedules (
        id            SERIAL PRIMARY KEY,
        name          TEXT NOT NULL UNIQUE,
        runbook       TEXT NOT NULL,
        frequency     TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly')),
        weekday       INT CHECK (weekday BETWEEN 0 AND 6),
        at_time       TEXT NOT NULL,
        enabled       BOOLEAN NOT NULL DEFAULT TRUE,
        created_by    TEXT NOT NULL,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_run_at   TIMESTAMPTZ,
        last_status   TEXT,
        last_result   TEXT
    )
    """,
)


def local_tz() -> ZoneInfo:
    try:
        return ZoneInfo(os.getenv("AIDA_TIMEZONE", "America/Los_Angeles"))
    except Exception:
        return ZoneInfo("UTC")


def parse_time(value: str) -> tuple[int, int]:
    hours, minutes = value.strip().split(":")
    hours, minutes = int(hours), int(minutes)
    if not (0 <= hours < 24 and 0 <= minutes < 60):
        raise ValueError("time must be HH:MM (24-hour)")
    return hours, minutes


def next_run_after(schedule: dict, after: datetime) -> datetime:
    """The first scheduled time strictly after `after` (timezone-aware), in UTC."""
    tz = local_tz()
    hours, minutes = parse_time(schedule["at_time"])
    local_after = after.astimezone(tz)
    candidate = local_after.replace(hour=hours, minute=minutes, second=0, microsecond=0)
    for _ in range(9):
        if candidate > local_after and (schedule["frequency"] == "daily" or candidate.weekday() == schedule["weekday"]):
            return candidate.astimezone(timezone.utc)
        candidate = (candidate + timedelta(days=1)).replace(hour=hours, minute=minutes)
    raise ValueError("could not compute the next run")


def describe(schedule: dict) -> str:
    when = "every day" if schedule["frequency"] == "daily" else f"every {WEEKDAYS[schedule['weekday']].title()}"
    return f"{when} at {schedule['at_time']}"


async def ensure_schema(pool) -> None:
    async with pool.connection() as conn:
        for statement in SCHEDULES_SQL:
            await conn.execute(statement)


async def list_schedules(pool) -> list[dict]:
    async with pool.connection() as conn:
        rows = await (await conn.execute("SELECT * FROM aida_schedules ORDER BY name")).fetchall()
    now = datetime.now(timezone.utc)
    for row in rows:
        row["description"] = describe(row)
        row["next_run_at"] = next_run_after(row, max(row["last_run_at"] or row["created_at"], now)).isoformat() if row["enabled"] else None
    return rows


def due(schedule: dict, now: datetime) -> bool:
    return schedule["enabled"] and next_run_after(schedule, schedule["last_run_at"] or schedule["created_at"]) <= now


async def run_schedule(pool, schedule: dict, run_runbook, record_audit, notify_failure, trigger: str = "schedule") -> dict:
    """Run one schedule's runbook, save the outcome as a ticket row, audit it, notify on failure."""
    result_text = await run_runbook(schedule["runbook"])
    status = "failed" if result_text.startswith(("FAILED", "REFUSED")) else "resolved"
    thread_id = f"maint-{uuid.uuid4()}"
    issue = f"[Scheduled maintenance] {schedule['name']}: runbook {schedule['runbook']} ({describe(schedule)})"
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO aida_tickets (thread_id, issue, status, current_specialist, requires_approval, last_message, source)
            VALUES (%s, %s, %s, 'maintenance', FALSE, %s, 'schedule')
            """,
            (thread_id, issue, status, result_text),
        )
        await conn.execute(
            "UPDATE aida_schedules SET last_run_at = now(), last_status = %s, last_result = %s WHERE id = %s",
            (status, result_text[:4000], schedule["id"]),
        )
    await record_audit(f"schedule:{schedule['name']}", "maintenance.executed", thread_id, {
        "runbook": schedule["runbook"], "approved_by": schedule["created_by"], "trigger": trigger,
        "status": status, "result": result_text[:1000],
    })
    if status == "failed":
        notify_failure(f"Scheduled maintenance '{schedule['name']}' failed: {result_text.splitlines()[0][:200]}", thread_id)
    return {"thread_id": thread_id, "status": status, "result": result_text}


async def scheduler_loop(pool, run_runbook, record_audit, notify_failure, interval: float = 60) -> None:
    while True:
        try:
            now = datetime.now(timezone.utc)
            async with pool.connection() as conn:
                schedules = await (await conn.execute("SELECT * FROM aida_schedules WHERE enabled")).fetchall()
            for schedule in schedules:
                if due(schedule, now):
                    print(f"[Scheduler] Running '{schedule['name']}' ({schedule['runbook']})")
                    await run_schedule(pool, schedule, run_runbook, record_audit, notify_failure)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[Scheduler] Error: {e}")
        await asyncio.sleep(interval)
