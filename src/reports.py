"""
Reports: what AIDA did and what it saved, plus a compliance evidence pack.

The "hours saved" figure is an estimate: resolved tickets x AIDA_MINUTES_SAVED_PER_TICKET (default 15),
the assumed time a person would have spent on each. Change the assumption in .env to match your team.
"""
import os
import socket
from datetime import datetime, timezone


def _tz() -> str:
    return os.getenv("AIDA_TIMEZONE", "America/Los_Angeles")


async def summary(pool, days: int = 30) -> dict:
    days = max(1, min(int(days), 365))
    minutes_per_ticket = float(os.getenv("AIDA_MINUTES_SAVED_PER_TICKET", "15") or 15)
    async with pool.connection() as conn:
        async def rows(sql, params=()):
            return await (await conn.execute(sql, params)).fetchall()

        window = "created_at >= now() - make_interval(days => %s)"
        totals = (await rows(f"""
            SELECT count(*) AS total,
                   count(*) FILTER (WHERE status = 'resolved') AS resolved,
                   count(*) FILTER (WHERE status = 'denied') AS denied,
                   count(*) FILTER (WHERE status = 'failed') AS failed,
                   count(*) FILTER (WHERE source = 'monitor') AS auto_detected,
                   count(*) FILTER (WHERE requires_approval) AS awaiting_approval
            FROM aida_tickets WHERE {window}""", (days,)))[0]

        by_status = await rows(f"SELECT coalesce(status, 'unknown') AS name, count(*) AS n FROM aida_tickets WHERE {window} GROUP BY 1 ORDER BY 2 DESC", (days,))
        by_specialist = await rows(f"SELECT coalesce(current_specialist, 'unknown') AS name, count(*) AS n FROM aida_tickets WHERE {window} GROUP BY 1 ORDER BY 2 DESC", (days,))
        by_day = await rows(f"""
            SELECT to_char(date_trunc('day', created_at AT TIME ZONE %s), 'YYYY-MM-DD') AS day, count(*) AS n
            FROM aida_tickets WHERE {window} GROUP BY 1 ORDER BY 1""", (_tz(), days))

        # Tickets resolved with no human step at all (no fix needed approval). Only tickets created since the
        # audit log existed can be judged, so the rate is over those.
        hf = (await rows(f"""
            SELECT count(*) AS audited,
                   count(*) FILTER (WHERE NOT EXISTS (
                       SELECT 1 FROM aida_audit a WHERE a.thread_id = t.thread_id AND a.action = 'remediation.requested'
                   )) AS hands_free
            FROM aida_tickets t
            WHERE t.status = 'resolved' AND t.{window}
              AND EXISTS (SELECT 1 FROM aida_audit c WHERE c.thread_id = t.thread_id AND c.action = 'ticket.created')
        """, (days,)))[0]
        hands_free, audited_resolved = hf["hands_free"], hf["audited"]

        # How long fixes waited for a human decision
        waits = await rows(f"""
            SELECT extract(epoch FROM (d.ts::timestamptz - r.ts::timestamptz)) / 60 AS minutes, d.action
            FROM aida_audit r
            JOIN LATERAL (
                SELECT ts, action FROM aida_audit d
                WHERE d.thread_id = r.thread_id AND d.action IN ('remediation.approved', 'remediation.denied') AND d.id > r.id
                ORDER BY d.id LIMIT 1
            ) d ON TRUE
            WHERE r.action = 'remediation.requested' AND r.ts::timestamptz >= now() - make_interval(days => %s)
        """, (days,))

        recurring_alerts = await rows(f"""
            SELECT alert_key AS name, count(*) AS n FROM aida_tickets
            WHERE alert_key IS NOT NULL AND {window} GROUP BY 1 ORDER BY 2 DESC LIMIT 5""", (days,))
        recurring_issues = await rows(f"""
            SELECT min(issue) AS name, count(*) AS n FROM aida_tickets
            WHERE source = 'user' AND {window} GROUP BY lower(trim(issue)) HAVING count(*) > 1 ORDER BY 2 DESC LIMIT 5""", (days,))

    minutes = sorted(w["minutes"] for w in waits)
    median_wait = minutes[len(minutes) // 2] if minutes else None
    approvals = sum(1 for w in waits if w["action"] == "remediation.approved")
    return {
        "days": days,
        **totals,
        "hands_free_resolved": hands_free,
        "hands_free_rate": round(hands_free / audited_resolved * 100) if audited_resolved else None,
        "audited_resolved": audited_resolved,
        "approvals": approvals,
        "denials": len(waits) - approvals,
        "median_approval_wait_minutes": round(float(median_wait), 1) if median_wait is not None else None,
        "estimated_hours_saved": round(totals["resolved"] * minutes_per_ticket / 60, 1),
        "minutes_saved_per_ticket": minutes_per_ticket,
        "by_status": by_status,
        "by_specialist": by_specialist,
        "by_day": by_day,
        "recurring_alerts": recurring_alerts,
        "recurring_issues": recurring_issues,
    }


async def access_summary(pool, days: int = 30) -> dict:
    async with pool.connection() as conn:
        roles = await (await conn.execute(
            "SELECT role, count(*) FILTER (WHERE NOT disabled) AS active, count(*) FILTER (WHERE disabled) AS disabled "
            "FROM aida_users GROUP BY role ORDER BY role")).fetchall()
        activity = await (await conn.execute("""
            SELECT action, count(*) AS n FROM aida_audit
            WHERE ts::timestamptz >= now() - make_interval(days => %s)
              AND action IN ('auth.login', 'auth.login_failed', 'remediation.approved', 'remediation.denied',
                             'user.created', 'user.updated', 'knowledge.removed')
            GROUP BY action ORDER BY action""", (days,))).fetchall()
    return {"roles": roles, "activity": {a["action"]: a["n"] for a in activity}}


def compliance_markdown(checks: list[dict], security_report: str, audit_verification: dict,
                        access: dict, days: int) -> str:
    """A self-contained evidence document an auditor can read."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    passed = sum(c["status"] == "pass" for c in checks)
    lines = [
        "# AIDA Compliance Evidence Report",
        "",
        f"- Host: `{socket.gethostname()}`",
        f"- Generated: {now}",
        f"- Period for activity figures: last {days} days",
        "",
        "> This is a technical self-assessment aid produced by Project AIDA. It is not a HIPAA certification "
        "or legal advice; review it with your compliance officer.",
        "",
        f"## Technical safeguards ({passed}/{len(checks)} pass)",
        "",
        "| Status | Safeguard | HIPAA citation | Finding | Recommended fix |",
        "|---|---|---|---|---|",
    ]
    for c in checks:
        lines.append(f"| {c['status'].upper()} | {c['safeguard']} | §{c['citation']} | "
                     f"{c['detail'].replace('|', '/')} | {c['fix'].replace('|', '/') or '—'} |")
    lines += [
        "",
        "## Audit controls (§164.312(b))",
        "",
        f"- AIDA audit log integrity: **{'intact' if audit_verification['ok'] else 'ALTERED'}** — {audit_verification['message']}",
        "- Every ticket, approval, denial, executed fix, sign-in and account change is recorded with who did it and when, "
        "in a hash-chained, append-only log.",
        "",
        "## Access control (§164.312(a)(1), §164.308(a)(4))",
        "",
        "| Role | Active accounts | Disabled accounts |",
        "|---|---|---|",
    ]
    for r in access["roles"]:
        lines.append(f"| {r['role']} | {r['active']} | {r['disabled']} |")
    activity = access["activity"]
    lines += [
        "",
        f"- Sign-ins: {activity.get('auth.login', 0)}; failed sign-ins: {activity.get('auth.login_failed', 0)}",
        f"- Fixes approved: {activity.get('remediation.approved', 0)}; denied: {activity.get('remediation.denied', 0)}",
        f"- Account changes: {activity.get('user.created', 0) + activity.get('user.updated', 0)}",
        "",
        "## Security health check",
        "",
        "```",
        security_report.strip(),
        "```",
        "",
    ]
    return "\n".join(lines)
