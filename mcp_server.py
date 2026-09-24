import os
import platform
import pwd
import re
import time
import shutil
import stat as _stat
import socket
import glob
from collections import Counter
import subprocess
import sys
import json
import tempfile

try:
    # MCP SDK v2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:
    # MCP SDK v1.x (Downgraded by langchain-mcp-adapters)
    from mcp.server.fastmcp import FastMCP

# Initialize the server
mcp = FastMCP("Aida-IT-Diagnostics")


def _run(cmd: list[str], timeout: int = 5) -> str:
    """Run a read-only diagnostic command and return its output (or a readable error)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout or "").strip()
        if result.returncode != 0:
            err = (result.stderr or "").strip()
            return f"Command {' '.join(cmd)} failed (code {result.returncode}):\n{err}\n{output}".strip()
        return output or "(no output)"
    except FileNotFoundError:
        return f"Command not available on this host: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return f"Timeout: {' '.join(cmd)} did not finish within {timeout} seconds."
    except Exception as e:
        return f"Execution Error: {str(e)}"


# ---------------------------------------------------------------------------
# Network specialist tools (read-only)
# ---------------------------------------------------------------------------

@mcp.tool()
def ping_host(hostname: str) -> str:
    """
    Pings a hostname or IP address to check network reachability and latency.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "2", "-W", "2", hostname],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return f"Success:\n{result.stdout}"
        else:
            return f"Failed with return code {result.returncode}:\n{result.stderr}\n{result.stdout}"
    except subprocess.TimeoutExpired:
        return f"Timeout: Host {hostname} did not respond within 5 seconds."
    except Exception as e:
        return f"Execution Error: {str(e)}"


@mcp.tool()
def resolve_dns(hostname: str) -> str:
    """
    Resolves a hostname to its IP addresses using the system DNS resolver.
    Use this to tell DNS failures apart from connectivity failures.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
        addresses = sorted({info[4][0] for info in infos})
        return f"{hostname} resolves to: {', '.join(addresses)}"
    except socket.gaierror as e:
        return f"DNS resolution failed for {hostname}: {e}"
    except Exception as e:
        return f"Execution Error: {str(e)}"


@mcp.tool()
def get_adapter_status() -> str:
    """
    Shows the host's network interfaces, their IP addresses and the default route.
    Use this to check whether an adapter is up and has a gateway.
    """
    interfaces = _run(["ip", "-brief", "address"])
    routes = _run(["ip", "route"])
    return f"Interfaces:\n{interfaces}\n\nRoutes:\n{routes}"


# ---------------------------------------------------------------------------
# OS diagnostics specialist tools (read-only)
# ---------------------------------------------------------------------------

@mcp.tool()
def get_system_info() -> str:
    """
    Returns OS version, uptime, CPU load averages and memory usage for the host.
    """
    lines = [f"OS: {platform.system()} {platform.release()} ({platform.machine()})"]
    try:
        with open("/proc/uptime") as f:
            seconds = float(f.read().split()[0])
        lines.append(f"Uptime: {int(seconds // 3600)}h {int(seconds % 3600 // 60)}m")
    except Exception:
        lines.append("Uptime: unavailable")
    try:
        load1, load5, load15 = os.getloadavg()
        lines.append(f"Load average (1/5/15 min): {load1:.2f} / {load5:.2f} / {load15:.2f} on {os.cpu_count()} CPUs")
    except Exception:
        lines.append("Load average: unavailable")
    try:
        meminfo = {}
        with open("/proc/meminfo") as f:
            for line in f:
                key, value = line.split(":", 1)
                meminfo[key] = int(value.strip().split()[0])  # kB
        total = meminfo["MemTotal"] / 1024 / 1024
        available = meminfo["MemAvailable"] / 1024 / 1024
        lines.append(f"Memory: {total - available:.1f} GB used of {total:.1f} GB ({available:.1f} GB available)")
    except Exception:
        lines.append("Memory: unavailable")
    return "\n".join(lines)


@mcp.tool()
def check_disk_usage(path: str = "/") -> str:
    """
    Reports total, used and free disk space for the filesystem containing the given path.
    """
    try:
        usage = shutil.disk_usage(path)
        gb = 1024 ** 3
        percent = usage.used / usage.total * 100 if usage.total else 0
        return (f"Disk usage for {path}: {usage.used / gb:.1f} GB used of {usage.total / gb:.1f} GB "
                f"({percent:.0f}% full, {usage.free / gb:.1f} GB free)")
    except Exception as e:
        return f"Execution Error: {str(e)}"


def _read_proc_cpu_ticks() -> dict[int, int]:
    """Return {pid: utime+stime clock ticks} for every process readable in /proc."""
    ticks = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat") as f:
                stat = f.read()
            # The command name is in parentheses and may contain spaces; split after it.
            fields = stat[stat.rindex(")") + 2:].split()
            ticks[int(entry)] = int(fields[11]) + int(fields[12])  # utime + stime
        except (OSError, ValueError, IndexError):
            continue
    return ticks


def _proc_details(pid: int) -> tuple[str, str, str, int]:
    """Return (user, command name, full command line, resident memory in kB) for a pid."""
    with open(f"/proc/{pid}/comm") as f:
        name = f.read().strip()
    with open(f"/proc/{pid}/cmdline", "rb") as f:
        cmdline = f.read().replace(b"\0", b" ").decode(errors="replace").strip()
    uid, rss_kb = None, 0
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("VmRSS:"):
                rss_kb = int(line.split()[1])
    try:
        user = pwd.getpwuid(uid).pw_name if uid is not None else "?"
    except KeyError:
        user = str(uid)
    return user, name, cmdline, rss_kb


@mcp.tool()
def list_top_processes(limit: int = 10) -> str:
    """
    Lists the processes using the most CPU, measured over a 1-second sample (not a lifetime average),
    with their memory usage. AIDA's own diagnostic processes are excluded.
    """
    limit = max(1, min(int(limit), 25))
    interval = 1.0
    hz = os.sysconf("SC_CLK_TCK")
    before = _read_proc_cpu_ticks()
    time.sleep(interval)
    after = _read_proc_cpu_ticks()

    try:
        with open("/proc/meminfo") as f:
            mem_total_kb = int(next(l for l in f if l.startswith("MemTotal:")).split()[1])
    except Exception:
        mem_total_kb = 0

    own_pid = os.getpid()
    rows, excluded = [], 0
    for pid, end_ticks in after.items():
        if pid not in before:
            continue  # started during the sample; no reliable measurement
        cpu = (end_ticks - before[pid]) / hz / interval * 100
        try:
            user, name, cmdline, rss_kb = _proc_details(pid)
        except (OSError, ValueError):
            continue
        # Skip AIDA's own tool processes so the agent doesn't diagnose itself
        if pid == own_pid or "mcp_server.py" in cmdline:
            excluded += 1
            continue
        mem = rss_kb / mem_total_kb * 100 if mem_total_kb else 0
        rows.append((cpu, mem, pid, user, name))

    rows.sort(reverse=True)
    lines = [f"CPU measured over {interval:.0f}s on {os.cpu_count()} CPUs (100% = one full core).",
             f"{'PID':>7}  {'USER':<12} {'%CPU':>6} {'%MEM':>6}  COMMAND"]
    for cpu, mem, pid, user, name in rows[:limit]:
        lines.append(f"{pid:>7}  {user:<12} {cpu:>6.1f} {mem:>6.1f}  {name}")
    if excluded:
        lines.append(f"({excluded} AIDA diagnostic process(es) excluded.)")
    return "\n".join(lines)


_SERVICE_NAME = re.compile(r"^[A-Za-z0-9@._-]{1,100}$")


@mcp.tool()
def check_service_status(service_name: str) -> str:
    """
    Shows whether a systemd service is running, with its most recent log lines.
    Read-only; use it before recommending a service restart.
    """
    if not _SERVICE_NAME.match(service_name or ""):
        return f"Invalid service name: {service_name!r}"
    state = _run(["systemctl", "is-active", service_name])
    details = _run(["systemctl", "status", "--no-pager", "--lines=5", service_name], timeout=10)
    return f"{service_name} is {state}\n\n{details}"


# ---------------------------------------------------------------------------
# Security specialist tools (read-only)
# ---------------------------------------------------------------------------

def _describe_bind_address(address: str) -> str:
    """Turn an ss bind address into plain words (also avoids '[::]' being read as Markdown)."""
    host = address.strip("[]").split("%")[0]
    if host in ("0.0.0.0",):
        return "all IPv4 interfaces (reachable from other machines)"
    if host in ("::", "*"):
        return "all interfaces, IPv4 and IPv6 (reachable from other machines)"
    if host.startswith("127.") or host == "::1":
        return f"localhost only ({host})"
    return f"specific address {host}"


def _listening_sockets() -> list[tuple[int, str, str, str]] | str:
    """(port, proto, where, process) for every listening socket, or an error string."""
    raw = _run(["ss", "-tulnpH"])
    if raw.startswith(("Command", "Timeout", "Execution Error")):
        return raw
    entries = set()
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        address, _, port = local.rpartition(":")
        match = re.search(r'users:\(\("([^"]+)"', line)
        process = match.group(1) if match else "unknown (owned by another user)"
        entries.add((int(port) if port.isdigit() else 0, proto, _describe_bind_address(address), process))
    return sorted(entries)


@mcp.tool()
def list_listening_ports() -> str:
    """
    Lists TCP and UDP ports the host is listening on, whether each is exposed to other machines
    or bound to localhost only, and the owning process when visible.
    """
    entries = _listening_sockets()
    if isinstance(entries, str):
        return entries
    if not entries:
        return "No listening ports found."
    lines = ["PROTO  PORT   PROCESS                          LISTENING ON"]
    for port, proto, where, process in entries:
        lines.append(f"{proto:<6} {port:<6} {process:<32} {where}")
    return "\n".join(lines)


@mcp.tool()
def list_recent_logins(limit: int = 10) -> str:
    """
    Shows the most recent user logins on the host.
    """
    limit = max(1, min(int(limit), 50))
    return _run(["last", "-n", str(limit)])


# ---------------------------------------------------------------------------
# Security health check and attack monitoring (read-only)
# ---------------------------------------------------------------------------

SEVERITY_PENALTY = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_FAILED_LOGIN = re.compile(r"(Failed password|Invalid user|authentication failure).*?(?:from|rhost=)\s*([0-9a-fA-F:.]+)")


def _sshd_settings(config_path: str = "/etc/ssh/sshd_config") -> dict[str, str] | None:
    """Effective sshd settings. sshd uses the FIRST value it sees; Include files are read where included."""
    if not os.path.exists(config_path):
        return None
    settings: dict[str, str] = {}

    def read(path: str):
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError:
            return
        for line in lines:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            key, _, value = line.partition(" ")
            key, value = key.lower(), value.strip()
            if key == "include":
                for pattern in value.split():
                    if not os.path.isabs(pattern):
                        pattern = os.path.join(os.path.dirname(config_path), pattern)
                    for included in sorted(glob.glob(pattern)):
                        read(included)
            elif key == "match":
                return  # settings after a Match block are conditional; stop at the global section
            else:
                settings.setdefault(key, value.lower())

    read(config_path)
    return settings


def _failed_logins(hours: int = 24) -> tuple[Counter, str]:
    """Count failed SSH/login attempts per source IP. Returns (counter, where the data came from)."""
    text, source = "", ""
    ok, output = _run_status(["journalctl", "--since", f"{hours} hours ago", "--no-pager", "-q",
                              "-t", "sshd", "-t", "sshd-session", "-t", "sudo", "-t", "login"], timeout=15)
    if ok:
        text, source = output, "system journal"
    else:
        for path in ("/var/log/auth.log", "/var/log/secure"):
            try:
                with open(path, errors="replace") as f:
                    text, source = f.read()[-2_000_000:], path
                break
            except OSError:
                continue
    if not source:
        return Counter(), "no readable login log (needs journal access or /var/log/auth.log)"
    counts = Counter(match.group(2) for match in _FAILED_LOGIN.finditer(text))
    return counts, source


def _suid_in_unusual_places(roots=("/tmp", "/var/tmp", "/dev/shm", "/home", "/opt", "/usr/local"),
                            time_budget: float = 5.0) -> list[str]:
    """Programs that run as their owner (setuid) in places where they normally should not exist."""
    found, deadline = [], time.time() + time_budget
    for root in roots:
        for dirpath, _dirs, files in os.walk(root, followlinks=False):
            if time.time() > deadline:
                return found
            for name in files:
                path = os.path.join(dirpath, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if _stat.S_ISREG(st.st_mode) and st.st_mode & _stat.S_ISUID:
                    found.append(path)
    return found


def run_security_checks(sshd_config: str = "/etc/ssh/sshd_config", env_file: str | None = None) -> list[dict]:
    """All security checks as a list of findings: {severity, title, detail, fix}."""
    findings: list[dict] = []

    def add(severity, title, detail, fix=""):
        findings.append({"severity": severity, "title": title, "detail": detail, "fix": fix})

    # 1. Admin accounts: any UID 0 account other than root is a classic backdoor
    try:
        with open("/etc/passwd") as f:
            uid0 = [line.split(":")[0] for line in f if line.count(":") >= 6 and line.split(":")[2] == "0"]
        extra = [u for u in uid0 if u != "root"]
        if extra:
            add("critical", "Extra accounts with full admin rights (UID 0)", ", ".join(extra),
                "Remove or re-number these accounts unless you created them on purpose.")
        else:
            add("info", "Only root has UID 0", "No hidden admin accounts found.")
    except OSError:
        add("low", "Could not read /etc/passwd", "Account check skipped.")

    # 2. Exposed services
    sockets = _listening_sockets()
    exposed = [] if isinstance(sockets, str) else [s for s in sockets if "reachable from other machines" in s[2]]
    ssh_exposed = any(port == 22 for port, *_ in exposed)
    if exposed:
        names = ", ".join(f"{proc} on {proto}/{port}" for port, proto, _where, proc in exposed[:10])
        add("medium" if len(exposed) > 3 else "low", f"{len(exposed)} service(s) reachable from other machines",
            names, "Bind services you only use locally to 127.0.0.1, or block them with a firewall.")
    else:
        add("info", "No services reachable from other machines", "Everything listens on localhost only.")

    # 3. SSH configuration
    settings = _sshd_settings(sshd_config)
    if settings is None:
        add("info", "SSH server not installed", "No sshd_config found.")
    else:
        root_login = settings.get("permitrootlogin", "prohibit-password")
        password_auth = settings.get("passwordauthentication", "yes")
        if root_login == "yes":
            add("high" if ssh_exposed else "medium", "SSH allows root to log in with a password",
                f"PermitRootLogin {root_login}", "Set 'PermitRootLogin no' in /etc/ssh/sshd_config.")
        if password_auth == "yes":
            add("high" if ssh_exposed else "low", "SSH accepts password logins",
                "PasswordAuthentication yes" + (" and SSH is reachable from other machines" if ssh_exposed else ""),
                "Use SSH keys and set 'PasswordAuthentication no'.")
        if root_login != "yes" and password_auth != "yes":
            add("info", "SSH configuration is hardened", f"PermitRootLogin {root_login}, PasswordAuthentication {password_auth}")

    # 4. Firewall
    ok, output = _run_status(["ufw", "status"], timeout=5)
    if ok and "inactive" in output.lower():
        add("medium" if exposed else "low", "Firewall (ufw) is inactive", "No host firewall rules are enforced.",
            "Enable it with 'sudo ufw default deny incoming && sudo ufw enable' (allow the ports you need first). "
            "On WSL, the Windows firewall still protects the machine.")
    elif ok:
        add("info", "Firewall (ufw) is active", output.splitlines()[0] if output else "active")
    else:
        add("low", "Firewall status unknown", "ufw is not installed or needs root to report its status.")

    # 5. Pending updates
    ok, output = _run_status(["apt", "list", "--upgradable"], timeout=30)
    if ok:
        upgradable = [l for l in output.splitlines() if "/" in l and "Listing" not in l]
        security = [l.split("/")[0] for l in upgradable if "-security" in l]
        if security:
            add("high", f"{len(security)} security update(s) pending", ", ".join(security[:15]),
                "Install with 'sudo apt update && sudo apt upgrade'.")
        elif upgradable:
            add("low", f"{len(upgradable)} non-security update(s) pending", ", ".join(l.split('/')[0] for l in upgradable[:10]),
                "Install when convenient.")
        else:
            add("info", "System packages are up to date", "No pending updates (as of the last 'apt update').")
    else:
        add("info", "Package update check skipped", "apt is not available on this system.")

    # 6. Secrets file permissions
    env_path = env_file or os.path.join(os.getcwd(), ".env")
    if os.path.exists(env_path):
        mode = os.stat(env_path).st_mode
        if mode & (_stat.S_IROTH | _stat.S_IWOTH):
            on_windows_drive = env_path.startswith("/mnt/")
            add("medium", "Secrets file is readable by other users", f"{env_path} has mode {oct(mode & 0o777)}"
                + (" (files on the Windows drive show as world-readable in WSL)" if on_windows_drive else ""),
                "Run 'chmod 600 .env'" + (" (needs the drive mounted with metadata in /etc/wsl.conf)" if on_windows_drive else "") + ".")
        else:
            add("info", "Secrets file permissions are private", f"{env_path} has mode {oct(mode & 0o777)}")

    # 7. setuid programs in unusual places
    suid = _suid_in_unusual_places()
    if suid:
        add("high", "Programs with elevated permissions in unusual folders", ", ".join(suid[:10]),
            "Check where these came from; remove them if you don't recognise them.")

    # 8. Failed logins
    counts, source = _failed_logins(24)
    total = sum(counts.values())
    if total:
        top = ", ".join(f"{ip} ({n})" for ip, n in counts.most_common(5))
        add("high" if total >= 50 else "medium" if total >= 10 else "low",
            f"{total} failed login attempt(s) in the last 24 hours", f"Top sources: {top}. Data from {source}.",
            "Repeated failures from one address suggest password guessing; block it or restrict SSH.")
    else:
        add("info", "No failed login attempts in the last 24 hours", f"Data from {source}.")

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return findings


def security_score(findings: list[dict]) -> int:
    return max(0, 100 - sum(SEVERITY_PENALTY[f["severity"]] for f in findings))


@mcp.tool()
def security_audit() -> str:
    """
    Runs a read-only security health check of this machine: admin accounts, exposed services, SSH
    hardening, firewall, pending security updates, secrets-file permissions, suspicious setuid programs
    and failed login attempts. Returns a 0-100 score and findings ordered by severity, each with a fix.
    """
    findings = run_security_checks()
    score = security_score(findings)
    lines = [f"SECURITY SCORE: {score}/100 ({sum(f['severity'] != 'info' for f in findings)} issue(s) found)"]
    for f in findings:
        lines.append(f"[{f['severity'].upper()}] {f['title']}: {f['detail']}")
        if f["fix"]:
            lines.append(f"    Fix: {f['fix']}")
    return "\n".join(lines)


@mcp.tool()
def list_failed_logins(hours: int = 24) -> str:
    """
    Counts failed login attempts (SSH password guessing, invalid users, sudo failures) per source
    IP address over the last N hours. Read-only.
    """
    hours = max(1, min(int(hours), 24 * 30))
    counts, source = _failed_logins(hours)
    if not counts:
        return f"No failed login attempts found in the last {hours} hour(s). Data from {source}."
    lines = [f"{sum(counts.values())} failed login attempt(s) in the last {hours} hour(s) (data from {source}):"]
    lines += [f"  {ip}: {n}" for ip, n in counts.most_common(20)]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remediation tools (destructive — gated by human approval in the graph)
# ---------------------------------------------------------------------------

def _run_status(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    """Run a command; return (succeeded, combined output)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = "\n".join(x.strip() for x in (result.stdout, result.stderr) if x and x.strip())
        return result.returncode == 0, output.replace("\r", "")
    except FileNotFoundError:
        return False, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout} seconds"
    except Exception as e:
        return False, str(e)


def _find_windows_ipconfig() -> str | None:
    """ipconfig.exe is reachable from WSL through Windows interop."""
    found = shutil.which("ipconfig.exe")
    if found:
        return found
    default = "/mnt/c/Windows/System32/ipconfig.exe"
    return default if os.path.exists(default) else None


@mcp.tool()
def flush_dns_cache() -> str:
    """
    Flushes the DNS caches on this machine: the Linux/WSL resolver cache (systemd-resolved) and,
    when running under WSL, the Windows DNS client cache. Changes system state, so it only runs
    after a human approves it. Reports exactly which caches were flushed and which were not.
    """
    results = []

    # 1. Linux / WSL: systemd-resolved
    if shutil.which("resolvectl"):
        ok, output = _run_status(["resolvectl", "flush-caches"])
        if not ok:
            # Needs root on most systems; try sudo without prompting for a password
            ok, sudo_output = _run_status(["sudo", "-n", "resolvectl", "flush-caches"])
            if ok:
                output = sudo_output or "flushed with sudo"
            else:
                output = (f"{output or 'permission denied'}; sudo without password not allowed "
                          f"({sudo_output or 'no output'}). To allow it, add this sudoers rule with 'sudo visudo': "
                          f"<your-user> ALL=(root) NOPASSWD: /usr/bin/resolvectl flush-caches")
        results.append(("Linux resolver cache (systemd-resolved)", ok, output))
    else:
        results.append(("Linux resolver cache (systemd-resolved)", False,
                        "resolvectl not found (systemd-resolved not in use); nothing to flush"))

    # 2. Windows DNS client cache (only when running under WSL)
    ipconfig = _find_windows_ipconfig()
    if ipconfig:
        ok, output = _run_status([ipconfig, "/flushdns"])
        results.append(("Windows DNS client cache (ipconfig /flushdns)", ok, output))

    flushed = [name for name, ok, _ in results if ok]
    lines = [f"{'FLUSHED' if ok else 'NOT FLUSHED'}: {name}" + (f" -- {detail}" if detail else "")
             for name, ok, detail in results]
    if flushed:
        header = f"SUCCESS: flushed {len(flushed)} of {len(results)} DNS cache(s)."
    else:
        header = "FAILED: no DNS cache was flushed."
    return header + "\n" + "\n".join(lines)


def _restartable_services() -> set[str]:
    """Services AIDA may restart. Set AIDA_RESTARTABLE_SERVICES in .env (comma-separated) to change."""
    raw = os.getenv("AIDA_RESTARTABLE_SERVICES", "cron,ssh,systemd-resolved,docker")
    return {name.strip() for name in raw.split(",") if name.strip()}


@mcp.tool()
def restart_service(service_name: str) -> str:
    """
    Restarts a systemd service, then checks that it came back up. Changes system state, so it only
    runs after a human approves it. Only services on AIDA's allowlist can be restarted.
    """
    allowed = _restartable_services()
    if not _SERVICE_NAME.match(service_name or "") or service_name not in allowed:
        return (f"REFUSED: {service_name!r} is not on the restart allowlist ({', '.join(sorted(allowed))}). "
                f"Nothing was restarted. Add it to AIDA_RESTARTABLE_SERVICES in .env to allow it.")

    ok, output = _run_status(["systemctl", "restart", service_name], timeout=30)
    how = "systemctl"
    if not ok:
        ok, sudo_output = _run_status(["sudo", "-n", "systemctl", "restart", service_name], timeout=30)
        how = "sudo systemctl"
        if not ok:
            return (f"FAILED: could not restart {service_name}. {output or 'permission denied'}; "
                    f"sudo without password not allowed ({sudo_output or 'no output'}). To allow it, add this "
                    f"sudoers rule with 'sudo visudo -f /etc/sudoers.d/aida': "
                    f"<your-user> ALL=(root) NOPASSWD: /usr/bin/systemctl restart {service_name}")

    time.sleep(1)
    state = _run(["systemctl", "is-active", service_name])
    if state.strip() == "active":
        return f"SUCCESS: restarted {service_name} with {how}; it is now active."
    return f"WARNING: restart command for {service_name} succeeded, but the service is now '{state.strip()}'."


@mcp.tool()
def clear_temp_files(older_than_days: int = 7) -> str:
    """
    Deletes this user's own regular files in the temp directory that have not been modified for
    older_than_days days (minimum 1). Never follows symlinks and never touches other users' files.
    Changes system state, so it only runs after a human approves it.
    """
    days = max(1, int(older_than_days))
    base = os.getenv("AIDA_TEMP_DIR") or tempfile.gettempdir()
    cutoff = time.time() - days * 86400
    uid = os.getuid()
    deleted, freed, skipped_errors = 0, 0, 0

    for root, dirs, files in os.walk(base, followlinks=False):
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
                if not _stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_mtime > cutoff:
                    continue
                os.unlink(path)
                deleted += 1
                freed += st.st_size
            except OSError:
                skipped_errors += 1

    size = f"{freed / 1024 / 1024:.1f} MB" if freed >= 1024 * 1024 else f"{freed / 1024:.1f} KB"
    result = f"SUCCESS: deleted {deleted} file(s) older than {days} day(s) from {base}, freeing {size}."
    if skipped_errors:
        result += f" {skipped_errors} file(s) could not be removed and were skipped."
    return result


# ---------------------------------------------------------------------------
# More fixes (approval-gated): privileged helper, logs, Docker, firewall, updates
# ---------------------------------------------------------------------------

def _run_privileged(cmd: list[str], timeout: int = 120) -> tuple[bool, str, str]:
    """Run a command that needs root: try directly, then `sudo -n` (never prompts). Returns (ok, output, how)."""
    ok, output = _run_status(cmd, timeout=timeout)
    if ok:
        return True, output, "directly"
    ok, sudo_output = _run_status(["sudo", "-n", *cmd], timeout=timeout)
    if ok:
        return True, sudo_output, "with sudo"
    return False, f"{output or 'permission denied'}; sudo without password not allowed ({sudo_output or 'no output'})", ""


def _sudoers_hint(command: str) -> str:
    return (f"To allow it, add this line with 'sudo visudo -f /etc/sudoers.d/aida': "
            f"<your-user> ALL=(root) NOPASSWD: {command}")


@mcp.tool()
def rotate_logs() -> str:
    """
    Forces log rotation (logrotate) so large log files are compressed and old ones removed, freeing disk
    space. Changes system state, so it only runs after a human approves it.
    """
    if not shutil.which("logrotate"):
        return "FAILED: logrotate is not installed on this machine."
    ok, output, how = _run_privileged(["logrotate", "-f", "/etc/logrotate.conf"], timeout=300)
    if ok:
        return f"SUCCESS: rotated logs {how}." + (f"\n{output[:500]}" if output and output != "(no output)" else "")
    return f"FAILED: could not rotate logs. {output}. {_sudoers_hint('/usr/sbin/logrotate -f /etc/logrotate.conf')}"


@mcp.tool()
def docker_prune() -> str:
    """
    Frees disk space used by Docker: removes stopped containers, dangling images, unused networks and build
    cache. Does NOT remove volumes (your data) or images used by any container. Only runs after approval.
    """
    if not shutil.which("docker"):
        return "FAILED: Docker is not installed or not on the PATH."
    ok, output = _run_status(["docker", "system", "prune", "-f"], timeout=600)
    if not ok:
        return f"FAILED: docker prune did not run: {output[:500]}"
    reclaimed = re.search(r"Total reclaimed space:\s*(.+)", output)
    return f"SUCCESS: Docker cleanup finished. Reclaimed {reclaimed.group(1).strip() if reclaimed else 'an unknown amount of'} space."


@mcp.tool()
def restart_container(container_name: str) -> str:
    """
    Restarts a Docker container by name, then checks it is running again. Only runs after approval.
    """
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", container_name or ""):
        return f"REFUSED: {container_name!r} is not a valid container name. Nothing was restarted."
    if not shutil.which("docker"):
        return "FAILED: Docker is not installed or not on the PATH."
    ok, names = _run_status(["docker", "ps", "-a", "--format", "{{.Names}}"], timeout=30)
    if not ok:
        return f"FAILED: could not list containers: {names[:300]}"
    if container_name not in names.split():
        return f"REFUSED: no container named {container_name!r}. Existing containers: {', '.join(names.split()[:20]) or 'none'}."
    ok, output = _run_status(["docker", "restart", container_name], timeout=120)
    if not ok:
        return f"FAILED: could not restart {container_name}: {output[:300]}"
    _ok, state = _run_status(["docker", "inspect", "-f", "{{.State.Status}}", container_name], timeout=30)
    if state.strip() == "running":
        return f"SUCCESS: restarted container {container_name}; it is running."
    return f"WARNING: restart command succeeded, but {container_name} is now '{state.strip()}'."


def _this_hosts_addresses() -> set[str]:
    ok, output = _run_status(["hostname", "-I"], timeout=5)
    return set(output.split()) if ok else set()


def _check_block_target(ip: str) -> tuple[str | None, str]:
    """Validate an address to block. Returns (error, normalised address)."""
    import ipaddress
    try:
        address = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return f"REFUSED: {ip!r} is not a valid IP address. Nothing was blocked.", ""
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return f"REFUSED: {address} is a loopback/unspecified/multicast address and must not be blocked.", ""
    if str(address) in _this_hosts_addresses():
        return f"REFUSED: {address} is one of this machine's own addresses; blocking it would cut off access.", ""
    return None, str(address)


@mcp.tool()
def block_ip(ip_address: str) -> str:
    """
    Blocks all incoming traffic from one IP address in the host firewall (ufw if installed, otherwise
    iptables). Use it against addresses that are guessing passwords or attacking the machine.
    Only runs after a human approves it. Loopback and this machine's own addresses are refused.
    """
    error, address = _check_block_target(ip_address)
    if error:
        return error
    if shutil.which("ufw"):
        cmd, hint = ["ufw", "insert", "1", "deny", "from", address], f"/usr/sbin/ufw insert 1 deny from {address}"
    elif shutil.which("iptables"):
        flag = "ip6tables" if ":" in address else "iptables"
        cmd, hint = [flag, "-I", "INPUT", "-s", address, "-j", "DROP"], f"/usr/sbin/{flag} -I INPUT -s {address} -j DROP"
    else:
        return "FAILED: no firewall tool (ufw or iptables) is installed."
    ok, output, how = _run_privileged(cmd, timeout=30)
    if ok:
        note = " Note: ufw rules only take effect while ufw is enabled." if cmd[0] == "ufw" else ""
        return f"SUCCESS: blocked incoming traffic from {address} using {cmd[0]} ({how}).{note}"
    return f"FAILED: could not block {address}. {output}. {_sudoers_hint(hint)}"


@mcp.tool()
def unblock_ip(ip_address: str) -> str:
    """
    Removes a firewall block for one IP address that was added with block_ip. Only runs after approval.
    """
    import ipaddress
    try:
        address = str(ipaddress.ip_address((ip_address or "").strip()))
    except ValueError:
        return f"REFUSED: {ip_address!r} is not a valid IP address."
    if shutil.which("ufw"):
        cmd = ["ufw", "delete", "deny", "from", address]
    elif shutil.which("iptables"):
        cmd = ["ip6tables" if ":" in address else "iptables", "-D", "INPUT", "-s", address, "-j", "DROP"]
    else:
        return "FAILED: no firewall tool (ufw or iptables) is installed."
    ok, output, how = _run_privileged(cmd, timeout=30)
    return (f"SUCCESS: removed the block on {address} ({how})." if ok
            else f"FAILED: could not unblock {address}. {output}")


_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,127}$")


def _pending_security_packages() -> list[str] | str:
    ok, output = _run_status(["apt", "list", "--upgradable"], timeout=60)
    if not ok:
        return f"apt is not available: {output[:200]}"
    return sorted({l.split("/")[0] for l in output.splitlines() if "/" in l and "-security" in l})


@mcp.tool()
def scan_vulnerabilities() -> str:
    """
    Read-only vulnerability scan: operating-system packages with pending security updates, and Python
    packages in AIDA's own environment with known vulnerabilities (via pip-audit, if installed).
    """
    lines = []
    security = _pending_security_packages()
    if isinstance(security, str):
        lines.append(f"OS packages: skipped ({security}).")
    elif security:
        lines.append(f"OS packages: {len(security)} with pending SECURITY updates: {', '.join(security[:30])}"
                     + (" ..." if len(security) > 30 else ""))
    else:
        lines.append("OS packages: no pending security updates (as of the last 'apt update').")

    ok, output = _run_status([sys.executable, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off"], timeout=300)
    if "No module named pip_audit" in output:
        lines.append("Python packages: skipped (install pip-audit with 'pip install pip-audit' to enable).")
    else:
        try:
            start = output.index("{")
            report = json.loads(output[start:output.rindex("}") + 1])
            vulnerable = [d for d in report.get("dependencies", []) if d.get("vulns")]
            if vulnerable:
                lines.append(f"Python packages: {len(vulnerable)} with known vulnerabilities:")
                for dep in vulnerable[:20]:
                    ids = ", ".join(v["id"] for v in dep["vulns"][:3])
                    fixes = sorted({f for v in dep["vulns"] for f in v.get("fix_versions", [])})
                    lines.append(f"  {dep['name']} {dep['version']}: {ids}"
                                 + (f" (fixed in {', '.join(fixes[:3])})" if fixes else " (no fix yet)"))
            else:
                lines.append(f"Python packages: no known vulnerabilities in {len(report.get('dependencies', []))} packages.")
        except (ValueError, KeyError):
            lines.append(f"Python packages: pip-audit could not complete: {output[-300:]}")
    return "\n".join(lines)


@mcp.tool()
def install_security_updates() -> str:
    """
    Installs pending operating-system SECURITY updates only (apt). Only runs after a human approves it.
    """
    packages = _pending_security_packages()
    if isinstance(packages, str):
        return f"FAILED: {packages}"
    if not packages:
        return "SUCCESS: no security updates were pending; nothing to install."
    packages = [p for p in packages if _PACKAGE_NAME.match(p)]
    ok, output, how = _run_privileged(["apt-get", "install", "-y", "--only-upgrade", *packages], timeout=1800)
    if ok:
        return f"SUCCESS: installed security updates for {len(packages)} package(s) {how}: {', '.join(packages[:30])}"
    return (f"FAILED: security updates were not installed. {output[-500:]}. "
            f"{_sudoers_hint('/usr/bin/apt-get install -y --only-upgrade *')}")


# ---------------------------------------------------------------------------
# Windows (the same PC, reached from WSL through Windows PowerShell)
# ---------------------------------------------------------------------------

from src import windows as _win

_WIN_UNAVAILABLE = ("Windows is not reachable from AIDA: {e} Windows checks only work when AIDA runs in WSL "
                    "on the Windows PC.")


def _pct_env(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


@mcp.tool()
def windows_health() -> str:
    """
    Read-only health check of the WINDOWS side of this PC (AIDA itself runs in WSL): Windows version, uptime,
    memory, every drive's free space (C:, D:...), key Windows services, Microsoft Defender, Windows Firewall
    and whether a restart is pending. Lists any problems found first.
    """
    try:
        snap = _win.snapshot()
    except _win.WindowsUnavailable as e:
        return _WIN_UNAVAILABLE.format(e=e)
    except Exception as e:
        return f"Could not read Windows health: {e}"
    found = _win.problems(snap, _pct_env("AIDA_MONITOR_DISK_PCT", 90), _pct_env("AIDA_MONITOR_MEM_PCT", 10))
    lines = [f"Windows computer {snap.get('computer')}: {snap.get('os')}, up {snap.get('uptime_hours')} hours"
             + (" (AIDA has administrator rights)" if snap.get("is_admin") else " (AIDA runs WITHOUT administrator rights)")]
    lines.append(f"PROBLEMS FOUND: {len(found)}" if found else "PROBLEMS FOUND: none")
    lines += [f"  - {text}" for _, _, text in found]
    total, free = snap.get("mem_total_mb") or 0, snap.get("mem_free_mb") or 0
    if total:
        lines.append(f"Memory: {(total - free) / 1024:.1f} GB used of {total / 1024:.1f} GB ({free / 1024:.1f} GB free)")
    for disk in snap["disks"]:
        size, free_gb = disk.get("size_gb") or 0, disk.get("free_gb") or 0
        used = (size - free_gb) / size * 100 if size else 0
        lines.append(f"Drive {disk['drive']}: {used:.0f}% full, {free_gb:.1f} GB free of {size:.1f} GB")
    for s in snap["services"]:
        lines.append(f"Service {s['name']} ({s.get('display')}): {s.get('status')}" + (f", start {s['start']}" if s.get("start") else ""))
    defender = snap.get("defender")
    if defender:
        lines.append(f"Microsoft Defender: mode {defender.get('mode') or 'unknown'}, antivirus "
                     f"{'on' if defender.get('antivirus') else 'off'}, real-time protection "
                     f"{'on' if defender.get('realtime') else 'OFF'}, definitions {defender.get('signature_age_days')} day(s) old, "
                     f"last quick scan {defender.get('quick_scan_age_days')} day(s) ago")
    else:
        lines.append("Microsoft Defender: status unavailable")
    if snap["antivirus_products"]:
        lines.append(f"Registered antivirus: {', '.join(map(str, snap['antivirus_products']))}")
    if snap["firewall"]:
        lines.append("Windows Firewall: " + ", ".join(f"{p['profile']} {'on' if p.get('enabled') else 'OFF'}" for p in snap["firewall"]))
    lines.append(f"Restart pending (updates): {'YES' if snap.get('pending_reboot') else 'no'}")
    return "\n".join(lines)


@mcp.tool()
def windows_top_processes(limit: int = 10, sort_by: str = "cpu") -> str:
    """
    Read-only: the Windows programs using the most CPU (measured over one second) or memory.
    sort_by is 'cpu' or 'memory'. CPU is percent of the whole machine.
    """
    limit = max(1, min(int(limit), 30))
    field = "mem_mb" if str(sort_by).lower().startswith("mem") else "cpu_pct"
    script = (
        "$a=@{}; Get-Process | ForEach-Object { $a[$_.Id]=$_.CPU }; Start-Sleep -Milliseconds 1000; "
        "$cores=[Environment]::ProcessorCount; "
        "$rows = Get-Process | ForEach-Object { $d = 0; if ($_.CPU -ne $null -and $a.ContainsKey($_.Id) -and $a[$_.Id] -ne $null) { $d = $_.CPU - $a[$_.Id] }; "
        "[pscustomobject]@{ name=$_.ProcessName; pid=$_.Id; cpu_pct=[math]::Round($d*100/$cores,1); mem_mb=[int][math]::Round($_.WorkingSet64/1MB) } }; "
        f"@($rows | Sort-Object {field} -Descending | Select-Object -First {limit}) | ConvertTo-Json -Compress"
    )
    try:
        rows = _win.as_list(_win.run_json(script, timeout=60))
    except _win.WindowsUnavailable as e:
        return _WIN_UNAVAILABLE.format(e=e)
    except Exception as e:
        return f"Could not list Windows processes: {e}"
    lines = [f"Top {len(rows)} Windows processes by {'memory' if field == 'mem_mb' else 'CPU'}:"]
    lines += [f"  {r.get('name')} (PID {r.get('pid')}): CPU {r.get('cpu_pct')}%, memory {r.get('mem_mb')} MB" for r in rows]
    return "\n".join(lines)


@mcp.tool()
def windows_event_errors(hours: int = 24, limit: int = 15) -> str:
    """
    Read-only: critical and error events from the Windows System and Application event logs in the last
    `hours` hours, grouped by source and event ID (most frequent first), with the latest message of each.
    """
    hours = max(1, min(int(hours), 24 * 30))
    limit = max(1, min(int(limit), 50))
    script = (
        f"$since=(Get-Date).AddHours(-{hours}); "
        "$ev = Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2; StartTime=$since} -MaxEvents 5000; "
        "$total = 0; if ($ev) { $total = @($ev).Count }; "
        f"$g = @($ev | Group-Object ProviderName,Id | Sort-Object Count -Descending | Select-Object -First {limit} | ForEach-Object {{ "
        "$l = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1; "
        "[ordered]@{ source=$l.ProviderName; id=$l.Id; log=$l.LogName; level=$l.LevelDisplayName; count=$_.Count; "
        "last=$l.TimeCreated.ToString('yyyy-MM-dd HH:mm'); message=(\"$($l.Message)\" -split \"`n\")[0].Trim() } }); "
        "[ordered]@{ total=$total; groups=$g } | ConvertTo-Json -Depth 4 -Compress"
    )
    try:
        data = _win.run_json(script, timeout=90)
    except _win.WindowsUnavailable as e:
        return _WIN_UNAVAILABLE.format(e=e)
    except Exception as e:
        return f"Could not read the Windows event logs: {e}"
    groups = _win.as_list(data.get("groups"))
    if not data.get("total"):
        return f"No critical or error events in the Windows System/Application logs in the last {hours} hour(s)."
    lines = [f"{data['total']} critical/error event(s) in the Windows System/Application logs in the last {hours} hour(s); "
             f"top {len(groups)} by frequency:"]
    for g in groups:
        lines.append(f"  {g.get('count')}x {g.get('level')} {g.get('source')} (event {g.get('id')}, {g.get('log')} log), "
                     f"last at {g.get('last')}: {str(g.get('message') or '')[:200]}")
    return "\n".join(lines)


@mcp.tool()
def windows_service_status(service_name: str) -> str:
    """Read-only: status of one Windows service by its service name (e.g. Spooler, WinDefend, wuauserv)."""
    if not _win.SERVICE_NAME.match(service_name or ""):
        return f"REFUSED: {service_name!r} is not a valid Windows service name."
    script = (
        f"$s = Get-CimInstance Win32_Service -Filter \"Name='{service_name}'\"; "
        "if (-not $s) { '{\"found\":false}' } else { [ordered]@{ found=$true; name=$s.Name; display=$s.DisplayName; state=$s.State; "
        "start=$s.StartMode; pid=$s.ProcessId; exit_code=$s.ExitCode } | ConvertTo-Json -Compress }"
    )
    try:
        data = _win.run_json(script, timeout=60)
    except _win.WindowsUnavailable as e:
        return _WIN_UNAVAILABLE.format(e=e)
    except Exception as e:
        return f"Could not read Windows service {service_name}: {e}"
    if not data.get("found"):
        return f"There is no Windows service named {service_name}."
    text = (f"Windows service {data['name']} ({data.get('display')}): {data.get('state')}, start mode {data.get('start')}"
            + (f", process ID {data['pid']}" if data.get("pid") else ""))
    if data.get("state") != "Running" and data.get("exit_code"):
        text += f", last exit code {data['exit_code']}"
    return text


@mcp.tool()
def windows_update_status() -> str:
    """
    Read-only: Windows Update status: updates waiting to install (security updates marked), the most recent
    installed update and whether a restart is pending. Can take a minute or two.
    """
    script = (
        "$r=[ordered]@{}; "
        "$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; "
        "if ($hf) { $r.last_update = \"$($hf.HotFixID) on $($hf.InstalledOn.ToString('yyyy-MM-dd'))\" }; "
        "try { $res = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\"); "
        "$r.pending = @($res.Updates | ForEach-Object { [ordered]@{ title=$_.Title; severity=\"$($_.MsrcSeverity)\"; "
        "security=[bool](@($_.Categories | Where-Object { $_.Name -match 'Security' }).Count) } }) } "
        "catch { $r.search_error = $_.Exception.Message }; "
        "$r.pending_reboot = (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'); "
        "$r | ConvertTo-Json -Depth 4 -Compress"
    )
    try:
        data = _win.run_json(script, timeout=300)
    except _win.WindowsUnavailable as e:
        return _WIN_UNAVAILABLE.format(e=e)
    except Exception as e:
        return f"Could not check Windows Update: {e}"
    pending = _win.as_list(data.get("pending"))
    lines = [f"Most recent installed update: {data.get('last_update') or 'unknown'}"]
    if data.get("search_error"):
        lines.append(f"Could not search for pending updates: {data['search_error']}")
    elif pending:
        security = [p for p in pending if p.get("security")]
        lines.append(f"{len(pending)} update(s) waiting to install, {len(security)} of them security updates:")
        lines += [f"  - {p.get('title')}" + (f" [security{', ' + p['severity'] if p.get('severity') else ''}]" if p.get("security") else "")
                  for p in pending[:25]]
        lines.append("Install them from Settings > Windows Update (AIDA does not install Windows updates itself).")
    else:
        lines.append("No updates waiting to install.")
    lines.append(f"Restart pending to finish updates: {'YES' if data.get('pending_reboot') else 'no'}")
    return "\n".join(lines)


_NOT_ADMIN_HINT = ("AIDA's Windows commands are running without administrator rights. To allow this fix, start the "
                   "terminal that runs AIDA with 'Run as administrator' (Windows Terminal: right-click > Run as "
                   "administrator), then start AIDA again; or do it yourself in Windows (services.msc / Windows Security).")


@mcp.tool()
def windows_restart_service(service_name: str) -> str:
    """
    Restarts a Windows service (by service name, e.g. Spooler for the print spooler) and checks it came back.
    Changes system state, so it only runs after a human approves it. Only services on AIDA's Windows allowlist
    can be restarted, and Windows requires administrator rights.
    """
    allowed = _win.restartable_services()
    if not _win.SERVICE_NAME.match(service_name or "") or service_name.lower() not in {a.lower() for a in allowed}:
        return (f"REFUSED: {service_name!r} is not on the Windows restart allowlist ({', '.join(allowed)}). Nothing was "
                f"restarted. Add it to AIDA_WINDOWS_RESTARTABLE_SERVICES in .env to allow it.")
    name = next(a for a in allowed if a.lower() == service_name.lower())
    script = (
        "if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("
        "[Security.Principal.WindowsBuiltInRole]::Administrator)) { 'NOT_ADMIN'; exit 0 }; "
        f"try {{ Restart-Service -Name '{name}' -Force -ErrorAction Stop; Start-Sleep -Seconds 2; "
        f"\"STATUS:$((Get-Service -Name '{name}').Status)\" }} catch {{ \"ERROR:$($_.Exception.Message -replace '\\s+', ' ')\" }}"
    )
    try:
        ok, output = _win.run(script, timeout=90)
    except _win.WindowsUnavailable as e:
        return f"FAILED: {e}"
    markers = [l.strip() for l in output.splitlines() if l.strip().startswith(("NOT_ADMIN", "STATUS:", "ERROR:"))]
    last = markers[-1] if markers else output.strip()[-300:]
    if not ok:
        return f"FAILED: could not restart the Windows service {name}: {output}"
    if last == "NOT_ADMIN":
        return f"FAILED: could not restart the Windows service {name}: administrator rights are needed. {_NOT_ADMIN_HINT}"
    if last.startswith("ERROR:"):
        return f"FAILED: Windows refused to restart {name}: {last[6:]}"
    if last == "STATUS:Running":
        return f"SUCCESS: restarted the Windows service {name}; it is now running."
    return f"WARNING: restarted the Windows service {name}, but it is now {last.replace('STATUS:', '') or 'in an unknown state'}."


_MPCMDRUN = ("$mp = Join-Path $(if ($env:ProgramFiles) { $env:ProgramFiles } else { 'C:\\Program Files' }) "
             "'Windows Defender\\MpCmdRun.exe'; if (-not (Test-Path $mp)) { 'NO_DEFENDER'; exit 0 }; ")


@mcp.tool()
def windows_defender_scan() -> str:
    """
    Starts a Microsoft Defender QUICK scan of Windows in the background. Changes system state (uses CPU for
    several minutes), so it only runs after a human approves it. Results appear in Windows Security.
    """
    script = _MPCMDRUN + "Start-Process -FilePath $mp -ArgumentList '-Scan','-ScanType','1' -WindowStyle Hidden -ErrorAction Stop; 'STARTED'"
    try:
        ok, output = _win.run(script, timeout=60)
    except _win.WindowsUnavailable as e:
        return f"FAILED: {e}"
    if ok and output.strip().endswith("STARTED"):
        return ("SUCCESS: started a Microsoft Defender quick scan in the background. It usually takes 5-15 minutes; "
                "results and anything Defender removes appear in Windows Security > Protection history.")
    if "NO_DEFENDER" in output:
        return "FAILED: Microsoft Defender's command-line scanner (MpCmdRun.exe) was not found on Windows."
    return f"FAILED: could not start the Defender scan: {output}"


@mcp.tool()
def windows_update_signatures() -> str:
    """
    Updates Microsoft Defender's virus definitions on Windows. Changes system state, so it only runs after a
    human approves it.
    """
    script = (_MPCMDRUN + "$out = & $mp -SignatureUpdate 2>&1 | Out-String; $code = $LASTEXITCODE; "
              "$s = Get-MpComputerStatus; "
              "[ordered]@{ code=$code; output=$out.Trim(); age=$(if ($s) { [int]$s.AntivirusSignatureAge } else { $null }); "
              "version=$(if ($s) { \"$($s.AntivirusSignatureVersion)\" } else { '' }) } | ConvertTo-Json -Compress")
    try:
        ok, output = _win.run(script, timeout=600)
    except _win.WindowsUnavailable as e:
        return f"FAILED: {e}"
    if "NO_DEFENDER" in output:
        return "FAILED: Microsoft Defender's command-line tool (MpCmdRun.exe) was not found on Windows."
    try:
        start = output.index("{")
        data = json.loads(output[start:])
    except ValueError:
        return f"FAILED: could not update Defender definitions: {output[:500]}"
    if data.get("code") == 0:
        return (f"SUCCESS: Microsoft Defender definitions are up to date (version {data.get('version') or 'unknown'}, "
                f"{data.get('age')} day(s) old).")
    detail = (data.get("output") or "").splitlines()[-1:] or [""]
    return f"FAILED: Defender definition update returned code {data.get('code')}: {detail[0][:300]}"


@mcp.tool()
def windows_clear_temp(older_than_days: int = 7) -> str:
    """
    Deletes the Windows user's own temp files (AppData\\Local\\Temp) not modified for older_than_days days
    (minimum 1). Skips files in use and never follows links out of the temp folder. Changes system state, so it
    only runs after a human approves it.
    """
    days = max(1, int(older_than_days))
    script = (
        "$t = [IO.Path]::GetTempPath(); $home_dir = $env:USERPROFILE; "
        "if (-not $home_dir -or -not $t.StartsWith($home_dir, [StringComparison]::OrdinalIgnoreCase)) { \"REFUSE:$t\"; exit 0 }; "
        f"$cut = (Get-Date).AddDays(-{days}); $script:n = 0; $script:bytes = 0; $script:skipped = 0; "
        "function Walk($dir) { Get-ChildItem -LiteralPath $dir -Force | ForEach-Object { "
        "if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }; "
        "if ($_.PSIsContainer) { Walk $_.FullName } elseif ($_.LastWriteTime -lt $cut) { $len = $_.Length; "
        "try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop; $script:n++; $script:bytes += $len } catch { $script:skipped++ } } } }; "
        "Walk $t; [ordered]@{ dir=$t; deleted=$script:n; mb=[math]::Round($script:bytes/1MB,1); skipped=$script:skipped } | ConvertTo-Json -Compress"
    )
    try:
        ok, output = _win.run(script, timeout=600)
    except _win.WindowsUnavailable as e:
        return f"FAILED: {e}"
    if "REFUSE:" in output:
        return f"REFUSED: the Windows temp folder ({output.split('REFUSE:', 1)[1].strip()}) is not inside the user's profile; nothing was deleted."
    try:
        data = json.loads(output[output.index("{"):])
    except ValueError:
        return f"FAILED: could not clear Windows temp files: {output[:500]}"
    return (f"SUCCESS: deleted {data['deleted']} Windows temp file(s) older than {days} day(s) from {data['dir']}, "
            f"freeing {data['mb']} MB" + (f"; skipped {data['skipped']} file(s) that are in use." if data.get("skipped") else "."))


# ---------------------------------------------------------------------------
# Runbooks: several steps, one approval
# ---------------------------------------------------------------------------

RUNBOOKS: dict[str, dict] = {
    "disk_cleanup": {
        "description": "Free disk space: clear old temp files, rotate logs, prune unused Docker data, then re-check space.",
        "steps": [("check_disk_usage", {"path": "/"}), ("clear_temp_files", {"older_than_days": 7}),
                  ("rotate_logs", {}), ("docker_prune", {}), ("check_disk_usage", {"path": "/"})],
    },
    "network_reset": {
        "description": "Fix name-resolution problems: flush DNS caches, then verify DNS and internet reachability.",
        "steps": [("flush_dns_cache", {}), ("resolve_dns", {"hostname": "google.com"}), ("ping_host", {"hostname": "8.8.8.8"})],
    },
    "security_patch": {
        "description": "Install pending security updates, then re-run the security health check.",
        "steps": [("install_security_updates", {}), ("security_audit", {})],
    },
    "windows_cleanup": {
        "description": "Free space on Windows: delete the Windows user's old temp files, then re-check Windows health.",
        "steps": [("windows_clear_temp", {"older_than_days": 7}), ("windows_health", {})],
    },
    "windows_security_refresh": {
        "description": "Update Microsoft Defender's virus definitions, then start a Defender quick scan.",
        "steps": [("windows_update_signatures", {}), ("windows_defender_scan", {})],
    },
}


def run_runbook_steps(name: str, step_functions: dict | None = None) -> str:
    runbook = RUNBOOKS.get(name)
    if not runbook:
        return f"REFUSED: unknown runbook {name!r}. Available: {', '.join(RUNBOOKS)}."
    functions = step_functions or globals()
    lines, failed_at = [], None
    for number, (tool, args) in enumerate(runbook["steps"], start=1):
        try:
            result = str(functions[tool](**args))
        except Exception as e:
            result = f"FAILED: {e}"
        first = result.strip().splitlines()[0] if result.strip() else "(no output)"
        lines.append(f"Step {number} {tool}{' ' + json.dumps(args) if args else ''}: {first[:300]}")
        if result.startswith(("FAILED", "REFUSED")):
            failed_at = number
            break
    total = len(runbook["steps"])
    if failed_at:
        header = f"FAILED: runbook {name} stopped at step {failed_at} of {total}."
    else:
        header = f"SUCCESS: runbook {name} completed all {total} steps."
    return header + "\n" + "\n".join(lines)


@mcp.tool()
def run_runbook(name: str) -> str:
    """Runs a named runbook (several fix steps under ONE approval); stops at the first failed step."""
    return run_runbook_steps(name)


# The agent picks a runbook from this description, so list them there
run_runbook.__doc__ = ("Runs a named runbook: several fix steps approved once, stopping at the first failure. "
                       "Available runbooks: " + "; ".join(f"'{k}': {v['description']}" for k, v in RUNBOOKS.items()))
try:  # keep the registered MCP tool description in sync (SDK versions differ in where it is stored)
    for registry in (getattr(getattr(mcp, "_tool_manager", None), "_tools", {}),):
        if "run_runbook" in registry:
            registry["run_runbook"].description = run_runbook.__doc__
except Exception:
    pass


# ---------------------------------------------------------------------------
# HIPAA-oriented technical safeguards self-check (read-only)
# ---------------------------------------------------------------------------

def _read(path: str) -> str:
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def run_compliance_checks() -> list[dict]:
    """Technical checks mapped to HIPAA Security Rule safeguards. status: pass | fail | unknown."""
    checks = []

    def add(safeguard, citation, status, detail, fix=""):
        checks.append({"safeguard": safeguard, "citation": citation, "status": status, "detail": detail, "fix": fix})

    on_wsl = "microsoft" in _read("/proc/version").lower()

    # Encryption at rest
    ok, output = _run_status(["lsblk", "-n", "-o", "TYPE"], timeout=10)
    if ok and "crypt" in output.split():
        add("Encryption at rest", "164.312(a)(2)(iv)", "pass", "An encrypted (LUKS) volume is in use.")
    elif on_wsl:
        add("Encryption at rest", "164.312(a)(2)(iv)", "unknown",
            "Running under WSL: disk encryption is controlled by Windows (BitLocker) and cannot be read from here.",
            "Confirm BitLocker is on in Windows Settings > Privacy & security > Device encryption.")
    else:
        add("Encryption at rest", "164.312(a)(2)(iv)", "fail", "No encrypted volume found.",
            "Encrypt disks that store patient data (LUKS / full-disk encryption).")

    no_systemd = "systemd is not running here (on WSL, enable it with systemd=true in /etc/wsl.conf)"

    # Audit controls
    ok, output = _run_status(["systemctl", "is-active", "auditd"], timeout=10)
    if "not been booted with systemd" in output or "Failed to connect to bus" in output:
        add("System audit logging (auditd)", "164.312(b)", "unknown", f"Cannot check auditd: {no_systemd}.")
    else:
        state = output.strip().splitlines()[0] if output.strip() else "not installed"
        add("System audit logging (auditd)", "164.312(b)", "pass" if state == "active" else "fail",
            f"auditd is {state}.",
            "" if state == "active" else "Install and enable auditd: 'sudo apt install auditd && sudo systemctl enable --now auditd'.")

    # Automatic logoff
    profile_text = "".join(_read(p) for p in ["/etc/profile", "/etc/bash.bashrc", *glob.glob("/etc/profile.d/*.sh")])
    tmout = re.search(r"^\s*(?:readonly\s+|export\s+)*TMOUT=(\d+)", profile_text, re.M)
    if tmout and 0 < int(tmout.group(1)) <= 900:
        add("Automatic logoff (shell sessions)", "164.312(a)(2)(iii)", "pass", f"Idle shells close after {tmout.group(1)} seconds.")
    else:
        add("Automatic logoff (shell sessions)", "164.312(a)(2)(iii)", "fail", "Idle terminal sessions never time out.",
            "Add 'readonly TMOUT=900; export TMOUT' to /etc/profile.d/autologout.sh.")

    # Password management
    defs = _read("/etc/login.defs")
    max_days = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", defs, re.M)
    pwquality = _read("/etc/security/pwquality.conf")
    minlen = re.search(r"^\s*minlen\s*=\s*(\d+)", pwquality, re.M)
    problems = []
    if not max_days or int(max_days.group(1)) > 90:
        problems.append(f"password expiry is {max_days.group(1) if max_days else 'not set'} days (recommended 90 or less)")
    if not minlen or int(minlen.group(1)) < 12:
        problems.append(f"minimum length is {minlen.group(1) if minlen else 'not enforced'} (recommended 12+)")
    add("Password management", "164.308(a)(5)(ii)(D)", "fail" if problems else "pass",
        "; ".join(problems) or "Password expiry and length rules are set.",
        "Set PASS_MAX_DAYS 90 in /etc/login.defs and minlen = 12 in /etc/security/pwquality.conf (libpam-pwquality)." if problems else "")

    # Protection from malicious software / patching
    security = _pending_security_packages()
    auto = _read("/etc/apt/apt.conf.d/20auto-upgrades")
    auto_on = 'Unattended-Upgrade "1"' in auto
    if isinstance(security, str):
        add("Security patching", "164.308(a)(5)(ii)(B)", "unknown", security)
    else:
        status = "pass" if not security and auto_on else "fail"
        detail = (f"{len(security)} security update(s) pending" if security else "No security updates pending") + \
                 (", automatic security updates are ON." if auto_on else ", automatic security updates are OFF.")
        add("Security patching", "164.308(a)(5)(ii)(B)", status, detail,
            "" if status == "pass" else "Install pending updates and run 'sudo dpkg-reconfigure -plow unattended-upgrades'.")

    # Transmission security / access
    settings = _sshd_settings()
    if settings is None:
        add("Remote access (SSH)", "164.312(e)(1)", "pass", "No SSH server installed.")
    else:
        weak = settings.get("passwordauthentication", "yes") == "yes" or settings.get("permitrootlogin") == "yes"
        add("Remote access (SSH)", "164.312(e)(1)", "fail" if weak else "pass",
            f"PasswordAuthentication {settings.get('passwordauthentication', 'yes')}, PermitRootLogin {settings.get('permitrootlogin', 'prohibit-password')}.",
            "Use key-based SSH only and disable root login." if weak else "")

    ok, output = _run_status(["ufw", "status"], timeout=5)
    if ok:
        active = "inactive" not in output.lower()
        add("Host firewall", "164.312(e)(1)", "pass" if active else "fail", output.splitlines()[0] if output else "",
            "" if active else "Enable ufw after allowing required ports.")
    else:
        add("Host firewall", "164.312(e)(1)", "unknown",
            "ufw not installed or needs root." + (" Under WSL the Windows firewall applies." if on_wsl else ""))

    # Unique user identification
    try:
        uid0 = [l.split(":")[0] for l in _read("/etc/passwd").splitlines() if l.count(":") >= 6 and l.split(":")[2] == "0"]
    except IndexError:
        uid0 = []
    add("Unique user identification", "164.312(a)(2)(i)", "fail" if len(uid0) > 1 else "pass",
        "Only root has UID 0." if len(uid0) <= 1 else f"Shared admin identities: {', '.join(uid0)}",
        "" if len(uid0) <= 1 else "Give every person their own account.")

    # Time synchronisation (needed for trustworthy audit timestamps)
    ok, output = _run_status(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=10)
    if not ok:
        add("Clock synchronisation", "164.312(b)", "unknown",
            f"Cannot check time sync: {no_systemd if 'systemd' in output or 'bus' in output else output[:120]}.")
    else:
        synced = output.strip() == "yes"
        add("Clock synchronisation", "164.312(b)", "pass" if synced else "fail", f"NTP synchronised: {output.strip()}.",
            "" if synced else "Enable time sync: 'sudo timedatectl set-ntp true'.")
    return checks


@mcp.tool()
def compliance_check(output_format: str = "text") -> str:
    """
    Read-only HIPAA-oriented technical safeguards check (encryption, audit logging, automatic logoff,
    password rules, patching, remote access, firewall, unique IDs, clock sync), each mapped to its
    Security Rule citation. This is a self-assessment aid, not a certification or legal advice.
    """
    checks = run_compliance_checks()
    if output_format == "json":
        return json.dumps(checks)
    passed = sum(c["status"] == "pass" for c in checks)
    lines = [f"COMPLIANCE CHECK: {passed}/{len(checks)} technical safeguards pass "
             "(self-assessment aid, not a certification or legal advice)."]
    for c in checks:
        lines.append(f"[{c['status'].upper()}] {c['safeguard']} ({c['citation']}): {c['detail']}")
        if c["fix"]:
            lines.append(f"    Fix: {c['fix']}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
