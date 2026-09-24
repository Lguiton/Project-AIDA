import re

from langchain_core.messages import ToolMessage
from langchain_core.prompts import ChatPromptTemplate
from src.graph.state import AidaState

_FAILURE = re.compile(r"\b(REFUSED|FAILED):")


def _latest_tool_failed(messages) -> bool:
    """True if any tool result since the last AI message reports REFUSED or FAILED."""
    for message in reversed(messages):
        if not isinstance(message, ToolMessage):
            break
        if _FAILURE.search(str(message.content)):
            return True
    return False


async def remediate_specialist_node(state: AidaState, llm, tools) -> dict:
    messages = state.get("messages", [])
    system_prompt = (
        "You are the Remediation Specialist. Your job is to execute fixes the user asks for, using your tools: "
        "flush_dns_cache (flush DNS caches), restart_service (restart an allowlisted systemd service; pass the exact "
        "service name), clear_temp_files (delete the user's own old temp files; pass older_than_days if the user "
        "gives an age), rotate_logs, docker_prune (free Docker disk space), restart_container (by name), "
        "block_ip / unblock_ip (firewall one IP address, e.g. one that is guessing passwords), "
        "install_security_updates, and run_runbook (several steps under one approval; prefer a runbook when the "
        "request matches one, e.g. 'free up disk space' -> disk_cleanup, 'fix DNS/internet' -> network_reset, "
        "'patch this machine' -> security_patch). "
        "For WINDOWS (AIDA runs in WSL on a Windows PC): windows_restart_service (allowlisted Windows service by service "
        "name, e.g. 'Spooler' for the print spooler), windows_defender_scan (Defender quick scan), windows_update_signatures "
        "(update Defender virus definitions), windows_clear_temp (the Windows user's old temp files), and the runbooks "
        "windows_cleanup ('free up space on Windows/C: drive') and windows_security_refresh ('update Defender and scan'). "
        "'clear temp files' without saying Windows means the Linux clear_temp_files. "
        "Every tool call is shown to a human operator who must approve it before it runs. "
        "Do not ask the user to confirm: the operator's approval step IS the confirmation, so call the tool right away. "
        "Use sensible defaults instead of asking questions: the usual service name for a service the user names "
        "(e.g. 'cron' for the cron service) and older_than_days=7 for temp files unless the user gives an age. "
        "Call only the tool that matches the request; if no tool fits, explain what you can do instead. "
        "After a tool runs, report its result accurately: say exactly what was and was not done, "
        "and pass on any instructions it gives for fixing a failure. Never claim success the tool did not report."
    )
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), ("placeholder", "{messages}")])
    
    # Bind the dynamically injected tools
    agent_llm = llm.bind_tools(tools)
    response = await (prompt | agent_llm).ainvoke({"messages": messages})
    # A reply with no pending tool calls is the specialist's final answer.
    # If the tool itself refused or failed, the ticket is "failed", not "resolved".
    if getattr(response, "tool_calls", None):
        status = "in_progress"
    elif _latest_tool_failed(messages):
        status = "failed"
    elif not any(isinstance(m, ToolMessage) for m in messages):
        # Answered without running any fix (e.g. asked a question): nothing was resolved
        status = "needs_info"
    else:
        status = "resolved"
    return {"messages": [response], "current_specialist": "remediate", "ticket_status": status}
