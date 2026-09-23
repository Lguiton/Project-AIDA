import subprocess
from langchain_core.tools import tool

@tool
def ping_host(hostname: str) -> str:
    """
    Pings a hostname or IP address to check for network connectivity and latency.
    Always try pinging a known external IP (like 8.8.8.8) and a domain name (like google.com) 
    to differentiate between physical connection issues and DNS resolution issues.
    """
    try:
        # -c 2 limits to 2 packets, -W 2 sets a 2-second timeout per packet (Linux/WSL syntax)
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
        return f"Tool Execution Error: {str(e)}"

@tool
def get_adapter_status() -> str:
    """
    Retrieves the status of the local network adapters (Wi-Fi, Ethernet).
    Useful to check if the adapter is physically connected or disabled.
    """
    # In a real environment, this would call `ip link` or `Get-NetAdapter`. 
    # For this WSL demo, we return a simulated string indicating Wi-Fi is connected 
    # but lacking internet access (which matches our test case).
    return (
        "Adapter: wlan0\n"
        "Status: UP\n"
        "SSID: Corporate_Guest_Network\n"
        "IP Address: 192.168.1.105\n"
        "Gateway: 192.168.1.1\n"
        "Note: Connected to local gateway, but external routing unavailable."
    )

# List of tools to bind to our agent
network_tools = [ping_host, get_adapter_status]
