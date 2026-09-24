"""
Proactive monitoring: AIDA checks the machine on a schedule and opens its own tickets.

Each check returns Alerts. An alert has a stable `key` (e.g. "disk:/") so the same problem does not
open a new ticket every few minutes: while a ticket for that key is still open, or was opened within
the cooldown window, the alert is recorded but no new ticket is created.

Settings (.env):
  AIDA_MONITOR_INTERVAL      seconds between runs (default 300; 0 turns the schedule off)
  AIDA_MONITOR_COOLDOWN      hours before the same alert may open another ticket (default 6)
  AIDA_MONITOR_DISK_PATHS    comma-separated mount points to watch (default "/")
  AIDA_MONITOR_DISK_PCT      alert when a disk is at least this % full (default 90)
  AIDA_MONITOR_MEM_PCT       alert when available memory drops below this % (default 10)
  AIDA_MONITOR_LOAD_FACTOR   alert when 5-minute load > CPUs x this (default 2.0)
  AIDA_MONITOR_CERT_HOSTS    comma-separated host[:port] whose TLS certificates to watch (default none)
  AIDA_MONITOR_CERT_DAYS     alert when a certificate expires within this many days (default 14)
"""
import asyncio
import os
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

AUTO_PREFIX = "[Auto-detected by AIDA monitoring]"
CLOSED_STATUSES = ("resolved", "denied", "failed")


@dataclass
class Alert:
    key: str
    check: str
    issue: str


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# Individual checks (synchronous; each returns a list of Alerts)
# ---------------------------------------------------------------------------

def check_disks(paths: list[str] | None = None, threshold_pct: float | None = None) -> list[Alert]:
    paths = paths or [p.strip() for p in os.getenv("AIDA_MONITOR_DISK_PATHS", "/").split(",") if p.strip()]
    threshold = threshold_pct if threshold_pct is not None else _env_float("AIDA_MONITOR_DISK_PCT", 90)
    alerts = []
    for path in paths:
        try:
            usage = shutil.disk_usage(path)
        except OSError:
            continue
        pct = usage.used / usage.total * 100 if usage.total else 0
        if pct >= threshold:
            alerts.append(Alert(
                key=f"disk:{path}", check="disk",
                issue=f"{AUTO_PREFIX} The disk at {path} is {pct:.0f}% full "
                      f"({usage.free / 1024**3:.1f} GB free of {usage.total / 1024**3:.1f} GB). "
                      f"Investigate what is using the space.",
            ))
    return alerts


def check_memory(threshold_pct: float | None = None, meminfo_path: str = "/proc/meminfo") -> list[Alert]:
    threshold = threshold_pct if threshold_pct is not None else _env_float("AIDA_MONITOR_MEM_PCT", 10)
    try:
        values = {}
        with open(meminfo_path) as f:
            for line in f:
                key, _, rest = line.partition(":")
                values[key] = int(rest.split()[0])
        available_pct = values["MemAvailable"] / values["MemTotal"] * 100
    except (OSError, KeyError, ValueError, ZeroDivisionError):
        return []
    if available_pct < threshold:
        return [Alert(
            key="memory", check="memory",
            issue=f"{AUTO_PREFIX} Available memory is low: {available_pct:.0f}% "
                  f"({values['MemAvailable'] / 1024**2:.1f} GB of {values['MemTotal'] / 1024**2:.1f} GB). "
                  f"The machine may be slow; find what is using memory.",
        )]
    return []


def check_load(factor: float | None = None, loadavg=None, cpus: int | None = None) -> list[Alert]:
    factor = factor if factor is not None else _env_float("AIDA_MONITOR_LOAD_FACTOR", 2.0)
    try:
        load5 = (loadavg or os.getloadavg())[1]
    except OSError:
        return []
    cpus = cpus or os.cpu_count() or 1
    if load5 > cpus * factor:
        return [Alert(
            key="load", check="load",
            issue=f"{AUTO_PREFIX} The machine is overloaded: 5-minute load average {load5:.1f} on {cpus} CPUs. "
                  f"The computer is slow; find which processes are using the CPU.",
        )]
    return []


def check_failed_services(runner=subprocess.run) -> list[Alert]:
    try:
        result = runner(["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"],
                        capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    alerts = []
    for line in (result.stdout or "").splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit.endswith(".service"):
            name = unit[: -len(".service")]
            alerts.append(Alert(
                key=f"service:{name}", check="service",
                issue=f"{AUTO_PREFIX} The service {name} has failed and is not running. "
                      f"Check its status and logs to find out why.",
            ))
    return alerts


def _cert_days_left(host: str, port: int, timeout: float = 5.0) -> float:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    return (expires - time.time()) / 86400


def check_certificates(hosts: list[str] | None = None, days: float | None = None, days_left=_cert_days_left) -> list[Alert]:
    hosts = hosts if hosts is not None else [h.strip() for h in os.getenv("AIDA_MONITOR_CERT_HOSTS", "").split(",") if h.strip()]
    days = days if days is not None else _env_float("AIDA_MONITOR_CERT_DAYS", 14)
    alerts = []
    for entry in hosts:
        host, _, port = entry.partition(":")
        port = int(port) if port.isdigit() else 443
        try:
            remaining = days_left(host, port)
        except Exception as e:
            alerts.append(Alert(
                key=f"cert:{host}:{port}", check="certificate",
                issue=f"{AUTO_PREFIX} Could not check the TLS certificate for {host}:{port} ({e}). "
                      f"The certificate may be invalid or the site unreachable.",
            ))
            continue
        if remaining < days:
            when = "has EXPIRED" if remaining < 0 else f"expires in {remaining:.0f} day(s)"
            alerts.append(Alert(
                key=f"cert:{host}:{port}", check="certificate",
                issue=f"{AUTO_PREFIX} The TLS certificate for {host}:{port} {when}. Renew it before it breaks the site.",
            ))
    return alerts


def collect_alerts() -> list[Alert]:
    alerts: list[Alert] = []
    for check in (check_disks, check_memory, check_load, check_failed_services, check_certificates):
        try:
            alerts.extend(check())
        except Exception as e:  # one broken check must not stop the others
            print(f"[Monitor] {check.__name__} failed: {e}")
    return alerts


# ---------------------------------------------------------------------------
# Running the checks and opening tickets
# ---------------------------------------------------------------------------

last_run: dict = {"checked_at": None, "alerts": [], "opened": [], "suppressed": [], "error": None}


async def _has_active_ticket(pool, alert_key: str, cooldown_hours: float) -> bool:
    async with pool.connection() as conn:
        row = await (await conn.execute(
            """
            SELECT 1 FROM aida_tickets
            WHERE alert_key = %s
              AND (status IS NULL OR status NOT IN ('resolved', 'denied', 'failed')
                   OR created_at > now() - make_interval(secs => %s))
            LIMIT 1
            """,
            (alert_key, cooldown_hours * 3600),
        )).fetchone()
    return row is not None


async def run_once(pool, open_ticket, collect=None, lock: asyncio.Lock | None = None) -> dict:
    """Run all checks; open a ticket for each new problem. `open_ticket(alert)` returns the ticket."""
    if lock is not None:
        async with lock:  # the schedule and a manual "run now" must not open the same ticket twice
            return await run_once(pool, open_ticket, collect)
    collect = collect or collect_alerts
    cooldown = _env_float("AIDA_MONITOR_COOLDOWN", 6)
    alerts = await asyncio.to_thread(collect)
    opened, suppressed = [], []
    for alert in alerts:
        if await _has_active_ticket(pool, alert.key, cooldown):
            suppressed.append(alert.key)
            continue
        ticket = await open_ticket(alert)
        opened.append({"alert_key": alert.key, "thread_id": ticket["thread_id"] if ticket else None})
    last_run.update({
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "alerts": [asdict(a) for a in alerts],
        "opened": opened,
        "suppressed": suppressed,
        "error": None,
    })
    return dict(last_run)


async def monitor_loop(pool, open_ticket, interval: float, lock: asyncio.Lock | None = None) -> None:
    """Background task started with the API. Survives individual failures."""
    while True:
        try:
            result = await run_once(pool, open_ticket, lock=lock)
            if result["opened"]:
                print(f"[Monitor] Opened {len(result['opened'])} ticket(s): {[o['alert_key'] for o in result['opened']]}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            last_run.update({"checked_at": datetime.now(timezone.utc).isoformat(), "error": str(e)})
            print(f"[Monitor] Run failed: {e}")
        await asyncio.sleep(interval)
