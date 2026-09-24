"""A scripted stand-in for the OpenAI chat model, so tests are fast, free and deterministic."""
import itertools

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.runnables import RunnableLambda

_ids = itertools.count()

# (keyword in the user's issue) -> (specialist, tool to call or None)
SCRIPT = [
    ("dns", "remediate", "flush_dns_cache", {}),
    ("temp", "remediate", "clear_temp_files", {"older_than_days": 1}),
    ("restart", "remediate", "restart_service", {"service_name": "definitely-not-allowed"}),
    ("slow", "os_diag", "get_system_info", {}),
    ("ports", "security", "list_listening_ports", {}),
    ("reach", "network", "resolve_dns", {"hostname": "localhost"}),
    ("bsod", "knowledge", None, {}),
    ("vague fix", "remediate", None, {}),  # remediation that answers without running a tool
]


def _plan(text: str):
    text = text.lower()
    for keyword, specialist, tool, args in SCRIPT:
        if keyword in text:
            return specialist, tool, args
    return "human_escalation", None, {}


def _first_human_text(messages) -> str:
    for message in messages:
        if message.type == "human":
            return message.content
    return ""


def _messages(value):
    return value.to_messages() if hasattr(value, "to_messages") else value.get("messages", [])


def _respond(value):
    messages = _messages(value)
    last = messages[-1]
    if isinstance(last, ToolMessage):
        return AIMessage(content=f"Tool result: {last.content}")
    specialist, tool, args = _plan(_first_human_text(messages))
    if tool:
        return AIMessage(content="", tool_calls=[{"name": tool, "args": args, "id": f"call_{next(_ids)}"}])
    return AIMessage(content=f"{specialist} answer")


class FakeChatModel(RunnableLambda):
    """Implements the three ways AIDA uses the model: `prompt | llm`, bind_tools, with_structured_output."""

    def __init__(self):
        super().__init__(_respond)

    def bind_tools(self, tools, **kwargs):
        return RunnableLambda(_respond)

    def with_structured_output(self, schema, **kwargs):
        return RunnableLambda(lambda value: schema(destination=_plan(_first_human_text(_messages(value)))[0]))
