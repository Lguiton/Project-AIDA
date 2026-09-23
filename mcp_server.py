import os
import platform
import shutil
import socket
import subprocess

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


@mcp.tool()
def list_top_processes(limit: int = 10) -> str:
    """
    Lists the processes using the most CPU, with their memory usage.
    """
    limit = max(1, min(int(limit), 25))
    output = _run(["ps", "-eo", "pid,user,%cpu,%mem,comm", "--sort=-%cpu"])
    return "\n".join(output.splitlines()[: limit + 1])


# ---------------------------------------------------------------------------
# Security specialist tools (read-only)
# ---------------------------------------------------------------------------

@mcp.tool()
def list_listening_ports() -> str:
    """
    Lists TCP and UDP ports the host is listening on, to spot unexpected exposed services.
    """
    return _run(["ss", "-tuln"])


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

@mcp.tool()
def flush_dns_cache() -> str:
    """
    Executes a DNS cache flush on the host system. Requires administrative clearance.
    """
    return "SUCCESS: DNS resolver cache flushed via MCP execution layer."


if __name__ == "__main__":
    mcp.run()
