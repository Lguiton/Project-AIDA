from langchain_core.tools import tool

@tool
def flush_dns_cache() -> str:
    """
    Executes a DNS flush on the host machine. 
    Highly destructive if run concurrently with DNS updates. Requires approval.
    """
    # Simulated destructive action
    return "SUCCESS: DNS resolver cache flushed."

remediation_tools = [flush_dns_cache]
