import operator
from typing import Annotated, Any, Literal, TypedDict
from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages

class AidaState(TypedDict):
    """
    Unified state machine for Project AIDA. 
    LangGraph passes this state dict to every node and edge function.
    """
    # add_messages reducer appends new messages rather than overwriting the list
    messages: Annotated[list[AnyMessage], add_messages]
    
    # Overwritten on update: Tracks which agent currently owns the task
    current_specialist: Literal["network", "knowledge", "os_diag", "security", "remediate", "human_escalation", "triage"]
    
    # operator.add reducer appends new tool executions (lists of dicts) to the history
    tool_history: Annotated[list[dict[str, Any]], operator.add]
    
    # Overwritten on update: Holds the specific command/script awaiting human approval
    pending_remediation_payload: dict[str, Any] | None
    
    # Overwritten on update: Tracks Human-in-the-Loop (HITL) gate status
    human_approval_status: Literal["pending", "approved", "rejected", "none"]
    
    # Overwritten on update: Global lifecycle of the user's issue
    ticket_status: Literal["open", "in_progress", "resolved", "escalated"]