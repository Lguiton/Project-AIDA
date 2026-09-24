import os
import platform
import pwd
import re
import time
import shutil
import stat as _stat
import socket
import subprocess
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


@mcp.tool()
def list_listening_ports() -> str:
    """
    Lists TCP and UDP ports the host is listening on, whether each is exposed to other machines
    or bound to localhost only, and the owning process when visible.
    """
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

    if not entries:
        return "No listening ports found."
    lines = ["PROTO  PORT   PROCESS                          LISTENING ON"]
    for port, proto, where, process in sorted(entries):
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


if __name__ == "__main__":
    mcp.run()
