"""
Connected products (INT-04 on the Eivanta side): the SaaS products AIDA watches.

Each product has:
  - an intake secret, used to verify that error reports really come from it (HMAC-SHA256 over
    "<timestamp>.<body>", sent as X-AIDA-Signature with X-AIDA-Product and X-AIDA-Timestamp);
    shown once when the product is added or the secret is rotated, never returned by list calls
  - an optional health URL that AIDA monitoring checks on its schedule
  - a pause switch: a paused product's reports are refused and its health is not checked

Error reports are grouped by their signature (same bug = same ticket). While that ticket is open,
new occurrences only increase its counter; once it is closed, a new occurrence opens a new ticket.
"""
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.error
import urllib.request
from collections import OrderedDict

MAX_REPORT_BYTES = 64 * 1024
MAX_CLOCK_SKEW_SECONDS = 300
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")

PRODUCTS_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS aida_products (
        id            TEXT PRIMARY KEY,
        name          TEXT NOT NULL,
        environment   TEXT NOT NULL DEFAULT 'local',
        health_url    TEXT,
        intake_secret TEXT NOT NULL,
        paused        BOOLEAN NOT NULL DEFAULT FALSE,
        created_by    TEXT NOT NULL,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS aida_product_errors (
        alert_key     TEXT PRIMARY KEY,
        product_id    TEXT NOT NULL,
        occurrences   INT NOT NULL DEFAULT 0,
        tenants       TEXT[] NOT NULL DEFAULT '{}',
        first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_report   JSONB
    )
    """,
    # Where to open the product's own dashboard from AIDA (a link, never embedded)
    "ALTER TABLE aida_products ADD COLUMN IF NOT EXISTS dashboard_url TEXT",
    # Every health check result, for uptime history (kept 90 days)
    """
    CREATE TABLE IF NOT EXISTS aida_product_health (
        id           BIGSERIAL PRIMARY KEY,
        product_id   TEXT NOT NULL,
        checked_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        state        TEXT NOT NULL,
        detail       TEXT,
        response_ms  INT,
        version      TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS aida_product_health_recent ON aida_product_health (product_id, checked_at DESC)",
)

PUBLIC_COLUMNS = "id, name, environment, health_url, dashboard_url, paused, created_by, created_at"
CLOSED_STATUSES = ("resolved", "denied", "failed", "dismissed")
HEALTH_KEEP_DAYS = 90


def valid_slug(value: str) -> bool:
    return bool(_SLUG.match(value or ""))


def new_secret() -> str:
    return secrets.token_urlsafe(32)


async def ensure_schema(pool) -> None:
    async with pool.connection() as conn:
        for statement in PRODUCTS_SCHEMA_SQL:
            await conn.execute(statement)


async def list_products(pool) -> list[dict]:
    async with pool.connection() as conn:
        return await (await conn.execute(f"SELECT {PUBLIC_COLUMNS} FROM aida_products ORDER BY name")).fetchall()


async def get_product(pool, product_id: str, with_secret: bool = False) -> dict | None:
    columns = PUBLIC_COLUMNS + (", intake_secret" if with_secret else "")
    async with pool.connection() as conn:
        return await (await conn.execute(f"SELECT {columns} FROM aida_products WHERE id = %s", (product_id,))).fetchone()


async def add_product(pool, product_id, name, environment, health_url, created_by, dashboard_url=None) -> str:
    secret = new_secret()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO aida_products (id, name, environment, health_url, intake_secret, created_by, dashboard_url) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (product_id, name, environment, health_url or None, secret, created_by, dashboard_url or None),
        )
    return secret


async def update_product(pool, product_id, paused=None, health_url=None, rotate_secret=False,
                         dashboard_url=None) -> str | None:
    """Returns the new secret when rotated. An empty string clears a URL."""
    sets, params, secret = [], [], None
    if dashboard_url is not None:
        sets.append("dashboard_url = %s"); params.append(dashboard_url or None)
    if paused is not None:
        sets.append("paused = %s"); params.append(paused)
    if health_url is not None:
        sets.append("health_url = %s"); params.append(health_url or None)
    if rotate_secret:
        secret = new_secret()
        sets.append("intake_secret = %s"); params.append(secret)
    if sets:
        async with pool.connection() as conn:
            await conn.execute(f"UPDATE aida_products SET {', '.join(sets)} WHERE id = %s", (*params, product_id))
    return secret


# ---- verifying reports --------------------------------------------------------

_seen_signatures: "OrderedDict[str, float]" = OrderedDict()


def _remember(signature: str) -> bool:
    """False if this exact signed report was already accepted recently (a replay)."""
    now = time.time()
    while _seen_signatures and next(iter(_seen_signatures.values())) < now - MAX_CLOCK_SKEW_SECONDS * 2:
        _seen_signatures.popitem(last=False)
    if signature in _seen_signatures:
        return False
    _seen_signatures[signature] = now
    return True


def expected_signature(secret: str, timestamp: str, body: bytes) -> str:
    return hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def verify(secret: str, timestamp: str, signature: str, body: bytes) -> str | None:
    """Returns an error message, or None when the report is authentic and fresh."""
    try:
        age = abs(time.time() - int(timestamp))
    except (TypeError, ValueError):
        return "missing or invalid X-AIDA-Timestamp"
    if age > MAX_CLOCK_SKEW_SECONDS:
        return "report timestamp is too old or in the future"
    if not signature or not hmac.compare_digest(signature, expected_signature(secret, timestamp, body)):
        return "invalid signature"
    if not _remember(signature):
        return "duplicate report (replay)"
    return None


# ---- turning a report into a ticket ------------------------------------------------

def _clean(value, limit: int = 300) -> str:
    return str(value or "").replace("\n", " ").strip()[:limit]


def alert_key_for(product_id: str, report: dict) -> str:
    signature = re.sub(r"[^A-Za-z0-9]", "", str(report.get("signature") or ""))[:32]
    if not signature:
        raw = f"{report.get('error_type')}|{report.get('route')}"
        signature = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"error:{product_id}:{signature}"


def issue_text(product: dict, report: dict) -> str:
    """What the Application Reliability specialist reads. Only fields the product already scrubbed."""
    frames = report.get("frames") or []
    stack = "\n".join(
        f"  {_clean(f.get('file'), 120)}:{int(f.get('line') or 0)} in {_clean(f.get('function'), 80)}"
        + (f": {_clean(f.get('code'), 160)}" if f.get("code") else "")
        + ("" if f.get("in_app") else " (library)")
        for f in frames[-15:] if isinstance(f, dict)
    ) or "  (no stack trace provided)"
    return (
        f"[Error reported by {product['name']} ({product['environment']})] "
        f"Unhandled {_clean(report.get('error_type'), 80)} on {_clean(report.get('method'), 10)} "
        f"{_clean(report.get('route'), 200)}.\n"
        f"Tenant: {_clean(report.get('tenant_id'), 128) or 'none (anonymous request)'}. "
        f"Request ID: {_clean(report.get('request_id'), 64) or 'unknown'}.\n"
        f"Message: {_clean(report.get('message'))}\n"
        f"Stack trace (most recent call last):\n{stack}\n"
        f"Diagnose the likely root cause and recommend a fix."
    )


async def record_occurrence(pool, alert_key: str, product_id: str, report: dict) -> int:
    tenant = _clean(report.get("tenant_id"), 128)
    async with pool.connection() as conn:
        row = await (await conn.execute(
            """
            INSERT INTO aida_product_errors (alert_key, product_id, occurrences, tenants, last_report)
            VALUES (%s, %s, 1, CASE WHEN %s = '' THEN '{}'::text[] ELSE ARRAY[%s] END, %s::jsonb)
            ON CONFLICT (alert_key) DO UPDATE SET
                occurrences = aida_product_errors.occurrences + 1,
                last_seen = now(),
                last_report = EXCLUDED.last_report,
                tenants = CASE
                    WHEN %s = '' OR %s = ANY(aida_product_errors.tenants)
                         OR cardinality(aida_product_errors.tenants) >= 50 THEN aida_product_errors.tenants
                    ELSE array_append(aida_product_errors.tenants, %s) END
            RETURNING occurrences
            """,
            (alert_key, product_id, tenant, tenant, json.dumps(report), tenant, tenant, tenant),
        )).fetchone()
    return row["occurrences"]


# ---- health checks ---------------------------------------------------------------

def probe_health(url: str, timeout: float = 5.0) -> dict:
    """One health check: state 'up', 'maintenance' or 'down', a detail, the response time and any version."""
    started = time.monotonic()
    elapsed = lambda: int((time.monotonic() - started) * 1000)
    down = lambda detail: {"state": "down", "detail": detail, "response_ms": elapsed(), "version": None}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=timeout) as response:
            status, body = response.status, response.read(65536)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return down("health check returned HTTP 404: nothing answers at that address. Check the health URL, and "
                        "that the right app (and version) is running on that port")
        return down(f"health check returned HTTP {e.code}")
    except Exception as e:
        return down(f"health check failed: {str(e)[:150]}")
    if status != 200:
        return down(f"health check returned HTTP {status}")
    try:
        data = json.loads(body)
        data = data if isinstance(data, dict) else {}
    except ValueError:
        data = {}  # a 200 with a non-JSON body counts as up
    version = _clean(data.get("version") or data.get("build") or data.get("commit"), 40) or None
    overall = str(data.get("overall_status") or data.get("status") or "").lower()
    if overall in ("degraded", "down", "error", "unhealthy"):
        reasons = []
        if data.get("database_reachable") is False:
            reasons.append("database unreachable")
        if data.get("detail"):
            reasons.append(_clean(data["detail"], 150))
        result = down(f"product reports '{overall}'" + (f" ({'; '.join(reasons)})" if reasons else ""))
        return {**result, "version": version}
    if overall == "maintenance":
        reason = _clean((data.get("maintenance") or {}).get("reason") if isinstance(data.get("maintenance"), dict) else "", 150)
        return {"state": "maintenance", "detail": "in declared maintenance" + (f": {reason}" if reason else ""),
                "response_ms": elapsed(), "version": version}
    return {"state": "up", "detail": None, "response_ms": elapsed(), "version": version}


def check_health(url: str, timeout: float = 5.0) -> str | None:
    """None when healthy (or in declared maintenance); otherwise a short reason."""
    result = probe_health(url, timeout)
    return result["detail"] if result["state"] == "down" else None


async def record_health(pool, product_id: str, result: dict) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO aida_product_health (product_id, state, detail, response_ms, version) VALUES (%s, %s, %s, %s, %s)",
            (product_id, result["state"], result.get("detail"), result.get("response_ms"), result.get("version")),
        )
        await conn.execute(
            "DELETE FROM aida_product_health WHERE product_id = %s AND checked_at < now() - make_interval(days => %s)",
            (product_id, HEALTH_KEEP_DAYS),
        )


# ---- what the dashboard shows ---------------------------------------------------------

_LATEST_TICKETS = f"""
    SELECT DISTINCT ON (alert_key) alert_key, thread_id, status, created_at
    FROM aida_tickets WHERE alert_key IS NOT NULL
    ORDER BY alert_key, created_at DESC
"""


async def overview(pool) -> list[dict]:
    """One row per product: latest health, uptime, open errors and open tickets."""
    closed = list(CLOSED_STATUSES)
    async with pool.connection() as conn:
        rows = await (await conn.execute(f"""
            WITH latest_ticket AS ({_LATEST_TICKETS})
            SELECT p.id, p.name, p.environment, p.paused, p.health_url, p.dashboard_url,
                   h.state, h.detail, h.checked_at, h.response_ms, h.version,
                   (SELECT round(100.0 * count(*) FILTER (WHERE state <> 'down') / nullif(count(*), 0), 1)
                      FROM aida_product_health WHERE product_id = p.id AND checked_at > now() - interval '24 hours') AS uptime_24h,
                   (SELECT round(100.0 * count(*) FILTER (WHERE state <> 'down') / nullif(count(*), 0), 1)
                      FROM aida_product_health WHERE product_id = p.id AND checked_at > now() - interval '30 days') AS uptime_30d,
                   (SELECT count(*) FROM aida_product_errors e JOIN latest_ticket t ON t.alert_key = e.alert_key
                      WHERE e.product_id = p.id AND NOT (coalesce(t.status, '') = ANY(%(closed)s))) AS open_errors,
                   (SELECT count(*) FROM latest_ticket t
                      WHERE (t.alert_key LIKE 'error:' || p.id || ':%%' OR t.alert_key = 'health:' || p.id)
                        AND NOT (coalesce(t.status, '') = ANY(%(closed)s))) AS open_tickets
            FROM aida_products p
            LEFT JOIN LATERAL (SELECT state, detail, checked_at, response_ms, version FROM aida_product_health
                               WHERE product_id = p.id ORDER BY checked_at DESC LIMIT 1) h ON TRUE
            ORDER BY p.name
        """, {"closed": closed})).fetchall()
    return rows


async def detail(pool, product_id: str, days: int = 30) -> dict | None:
    product = await get_product(pool, product_id)
    if product is None:
        return None
    closed = list(CLOSED_STATUSES)
    async with pool.connection() as conn:
        daily = await (await conn.execute("""
            SELECT to_char(date_trunc('day', checked_at), 'YYYY-MM-DD') AS day, count(*) AS checks,
                   round(100.0 * count(*) FILTER (WHERE state <> 'down') / count(*), 1) AS uptime
            FROM aida_product_health WHERE product_id = %s AND checked_at > now() - make_interval(days => %s)
            GROUP BY 1 ORDER BY 1""", (product_id, days))).fetchall()
        recent = await (await conn.execute("""
            SELECT checked_at, state, detail, response_ms, version FROM aida_product_health
            WHERE product_id = %s ORDER BY checked_at DESC LIMIT 20""", (product_id,))).fetchall()
        errors = await (await conn.execute(f"""
            WITH latest_ticket AS ({_LATEST_TICKETS})
            SELECT e.alert_key, e.occurrences, cardinality(e.tenants) AS tenants, e.first_seen, e.last_seen,
                   e.last_report->>'error_type' AS error_type, e.last_report->>'method' AS method,
                   e.last_report->>'route' AS route, t.thread_id, t.status,
                   (t.status IS NULL OR NOT (t.status = ANY(%(closed)s))) AS open
            FROM aida_product_errors e LEFT JOIN latest_ticket t ON t.alert_key = e.alert_key
            WHERE e.product_id = %(id)s
            ORDER BY open DESC, e.last_seen DESC LIMIT 50""", {"closed": closed, "id": product_id})).fetchall()
    return {"product": product, "daily_uptime": daily, "recent_checks": recent, "errors": errors}
