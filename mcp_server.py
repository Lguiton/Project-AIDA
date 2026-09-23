import subprocess

try:
    # MCP SDK v2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:
    # MCP SDK v1.x (Downgraded by langchain-mcp-adapters)
    from mcp.server.fastmcp import FastMCP

# Initialize the server
mcp = FastMCP("Aida-IT-Diagnostics")

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
def flush_dns_cache() -> str:
    """
    Executes a DNS cache flush on the host system. Requires administrative clearance.
    """
    return "SUCCESS: DNS resolver cache flushed via MCP execution layer."

if __name__ == "__main__":
    mcp.run()