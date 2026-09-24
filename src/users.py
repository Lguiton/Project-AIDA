"""
Operator accounts and roles.

Roles (each includes everything the one before it can do):
  requester  submit tickets and see the queue
  approver   approve or deny fixes, run health checks, manage the knowledge base, read the audit log
  admin      manage users, send test notifications

The dashboard signs users in through the API and gets a short-lived signed session token, which it
sends with every request. The API trusts the token's username and role for permissions and the audit log.
Requests that carry the API key but no token (scripts, tests) act as the built-in service account "api".
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time

ROLES = ("requester", "approver", "admin")
PBKDF2_ITERATIONS = 200_000
TOKEN_TTL_SECONDS = 12 * 3600
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300

USERS_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS aida_users (
        username       TEXT PRIMARY KEY,
        password_hash  TEXT NOT NULL,
        role           TEXT NOT NULL CHECK (role IN ('requester', 'approver', 'admin')),
        disabled       BOOLEAN NOT NULL DEFAULT FALSE,
        created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
)


def role_at_least(role: str, required: str) -> bool:
    return role in ROLES and ROLES.index(role) >= ROLES.index(required)


# ---- passwords --------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _algo, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def validate_new_password(password: str) -> str | None:
    if len(password or "") < 10:
        return "Passwords must be at least 10 characters."
    return None


# ---- session tokens -----------------------------------------------------------

def _secret() -> bytes:
    secret = os.getenv("AIDA_API_KEY", "")
    if not secret:
        raise RuntimeError("AIDA_API_KEY is not set")
    return hashlib.sha256(("aida-session:" + secret).encode()).digest()


def issue_token(username: str, role: str, ttl: int = TOKEN_TTL_SECONDS) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(
        {"u": username, "r": role, "exp": int(time.time()) + ttl}, separators=(",", ":")
    ).encode()).decode().rstrip("=")
    signature = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def read_token(token: str) -> dict | None:
    """Return {"username", "role"} for a valid, unexpired token, else None."""
    try:
        payload, signature = token.rsplit(".", 1)
        expected = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if data["exp"] < time.time() or data["r"] not in ROLES:
            return None
        return {"username": data["u"], "role": data["r"]}
    except (ValueError, KeyError, TypeError, RuntimeError):
        return None


# ---- login throttling ---------------------------------------------------------

_failures: dict[str, list[float]] = {}


def locked_out(username: str) -> bool:
    recent = [t for t in _failures.get(username, []) if t > time.time() - LOCKOUT_SECONDS]
    _failures[username] = recent
    return len(recent) >= MAX_FAILED_LOGINS


def note_failure(username: str) -> None:
    _failures.setdefault(username, []).append(time.time())


def clear_failures(username: str) -> None:
    _failures.pop(username, None)


# ---- database ---------------------------------------------------------------

async def ensure_users(pool) -> str | None:
    """Create the table; if there are no users yet, create 'admin' with AIDA_UI_PASSWORD. Returns a note."""
    async with pool.connection() as conn:
        for statement in USERS_SCHEMA_SQL:
            await conn.execute(statement)
        count = (await (await conn.execute("SELECT count(*) AS n FROM aida_users")).fetchone())["n"]
        if count:
            return None
        bootstrap = os.getenv("AIDA_UI_PASSWORD", "")
        if not bootstrap:
            return "No users exist and AIDA_UI_PASSWORD is not set, so nobody can sign in yet."
        await conn.execute(
            "INSERT INTO aida_users (username, password_hash, role) VALUES ('admin', %s, 'admin')",
            (hash_password(bootstrap),),
        )
        return "Created the first user 'admin' with the password from AIDA_UI_PASSWORD."


async def authenticate(pool, username: str, password: str) -> dict | None:
    async with pool.connection() as conn:
        row = await (await conn.execute(
            "SELECT username, password_hash, role, disabled FROM aida_users WHERE username = %s", (username,)
        )).fetchone()
    if not row or row["disabled"] or not verify_password(password, row["password_hash"]):
        return None
    return {"username": row["username"], "role": row["role"]}


async def list_users(pool) -> list[dict]:
    async with pool.connection() as conn:
        return await (await conn.execute(
            "SELECT username, role, disabled, created_at FROM aida_users ORDER BY username"
        )).fetchall()


async def create_user(pool, username: str, password: str, role: str) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO aida_users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, hash_password(password), role),
        )


async def update_user(pool, username: str, role: str | None = None, disabled: bool | None = None,
                      password: str | None = None) -> bool:
    sets, params = [], []
    if role is not None:
        sets.append("role = %s"); params.append(role)
    if disabled is not None:
        sets.append("disabled = %s"); params.append(disabled)
    if password is not None:
        sets.append("password_hash = %s"); params.append(hash_password(password))
    if not sets:
        return True
    async with pool.connection() as conn:
        result = await conn.execute(f"UPDATE aida_users SET {', '.join(sets)} WHERE username = %s",
                                    (*params, username))
        return result.rowcount > 0


async def active_admin_count(pool) -> int:
    async with pool.connection() as conn:
        return (await (await conn.execute(
            "SELECT count(*) AS n FROM aida_users WHERE role = 'admin' AND NOT disabled"
        )).fetchone())["n"]
