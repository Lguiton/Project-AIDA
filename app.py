import hmac
import os
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# API Configuration
API_BASE = "http://127.0.0.1:8006/api"
API_URL = f"{API_BASE}/tickets"
# Shared key the backend requires on every /api call (AIDA_API_KEY in .env)
API_HEADERS = {"X-AIDA-Key": os.getenv("AIDA_API_KEY", "")}

st.set_page_config(page_title="Eivanta Labs | Project AIDA", layout="wide")


def require_login():
    """Operator login. The password is AIDA_UI_PASSWORD in .env; the page stops here until it is entered."""
    password = os.getenv("AIDA_UI_PASSWORD", "")
    if not password:
        st.error("AIDA_UI_PASSWORD is not set. Add it to .env and restart Streamlit.")
        st.stop()
    if st.session_state.get("authenticated"):
        return

    st.title("🛡️ Project AIDA Command Center")
    with st.form("login_form"):
        entered = st.text_input("Operator password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        if hmac.compare_digest(entered.encode(), password.encode()):
            st.session_state.authenticated = True
            st.rerun()
        time.sleep(1)  # slow down password guessing
        st.error("Incorrect password.")
    st.stop()


require_login()

with st.sidebar:
    if st.button("Sign out"):
        st.session_state.authenticated = False
        st.rerun()
    if not API_HEADERS["X-AIDA-Key"]:
        st.warning("AIDA_API_KEY is not set in .env, so the backend will reject requests.")

# Timestamps are stored in UTC; show them in this time zone (override with AIDA_TIMEZONE in .env)
try:
    DISPLAY_TZ = ZoneInfo(os.getenv("AIDA_TIMEZONE", "America/Los_Angeles"))
except Exception:
    DISPLAY_TZ = None  # fall back to the machine's local time zone


def format_timestamp(value):
    """Convert an ISO timestamp from the API (UTC) to readable local time, e.g. 'Sep 23, 5:08 PM PDT'."""
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local = dt.astimezone(DISPLAY_TZ) if DISPLAY_TZ else dt.astimezone()
        return f"{local:%b} {local.day}, {local.hour % 12 or 12}:{local:%M %p %Z}"
    except ValueError:
        return value


def fetch_tickets():
    """Tickets come from the backend (Postgres), so they survive restarts of either app."""
    try:
        response = requests.get(API_URL, params={"limit": 50}, headers=API_HEADERS, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Could not load tickets from the backend: {e}")
        return None


def fetch_metrics():
    try:
        response = requests.get(f"{API_BASE}/metrics", headers=API_HEADERS, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def submit_ticket(issue_text):
    try:
        response = requests.post(API_URL, json={"issue": issue_text}, headers=API_HEADERS, timeout=300)
        if response.status_code == 200:
            return True
        st.error(f"Backend returned {response.status_code}: {response.text}")
    except Exception as e:
        st.error(f"Failed to connect to backend: {e}")
    return False


def forget_ticket(thread_id):
    """Take a ticket's answer out of the knowledge base (for answers that should not be reused)."""
    try:
        response = requests.post(f"{API_URL}/{thread_id}/forget", headers=API_HEADERS, timeout=30)
        if response.status_code != 200:
            st.error(f"Could not remove ticket from the knowledge base ({response.status_code}): {response.text}")
    except Exception as e:
        st.error(f"Could not remove ticket from the knowledge base: {e}")


def decide_ticket(thread_id, approved):
    """Send the operator's decision on a pending remediation (approve runs it, deny closes the ticket)."""
    action = "Approval" if approved else "Denial"
    try:
        response = requests.post(f"{API_URL}/{thread_id}/approve", json={"approved": approved}, headers=API_HEADERS, timeout=300)
        if response.status_code == 200:
            if approved:
                st.success(f"Ticket {thread_id[:8]} approved and executed.")
            else:
                st.info(f"Ticket {thread_id[:8]} denied. No action was taken.")
        else:
            st.error(f"{action} failed ({response.status_code}): {response.text}")
    except Exception as e:
        st.error(f"{action} failed: {e}")


# --- UI Layout ---
st.title("🛡️ Project AIDA Command Center")
st.markdown("Autonomous IT Operations Help Desk")

# Top KPI Metrics (placeholder; filled at the end of the script so counts include this run's changes)
kpi_area = st.container()

st.divider()

# Main Workspace
left_pane, right_pane = st.columns([1, 1.5])

with left_pane:
    st.subheader("Submit New Issue")
    with st.form("ticket_form", clear_on_submit=True):
        issue_input = st.text_area("Describe the IT problem:", height=100, placeholder="e.g., I'm getting a BSOD with SYSTEM_SERVICE_EXCEPTION...")
        submitted = st.form_submit_button("Deploy Agent")

        if submitted and issue_input:
            with st.spinner("Cognitive Router analyzing..."):
                if submit_ticket(issue_input):
                    st.success("Ticket dispatched to specialist node.")

with right_pane:
    st.subheader("Ticket Queue")
    tickets = fetch_tickets()

    if tickets is None:
        pass  # error already shown
    elif not tickets:
        st.info("No tickets yet.")
    else:
        for ticket in tickets:
            thread_id = ticket["thread_id"]
            created = format_timestamp(ticket.get("created_at"))
            specialist = (ticket.get("current_specialist") or "unknown").upper()
            is_open = ticket.get("status") not in ("resolved", "denied") or ticket.get("requires_approval")
            with st.expander(f"Ticket {thread_id[:8]} - Specialist: {specialist} - {created}", expanded=bool(is_open)):
                st.markdown(f"**Issue:** {ticket.get('issue')}")
                st.markdown(f"**Status:** `{ticket.get('status')}`")
                st.markdown(f"**Agent Response:**\n{ticket.get('last_message') or ''}")
                if ticket.get("learned"):
                    st.caption("📚 Added to the knowledge base for future tickets.")
                    if st.button("Remove from knowledge base", key=f"forget_{thread_id}"):
                        forget_ticket(thread_id)
                        st.rerun()

                # Human-in-the-Loop Gateway
                if ticket.get("requires_approval"):
                    st.warning("⚠️ SECURITY GATEWAY: Agent is requesting permission to execute a destructive tool.")
                    approve_col, deny_col, _ = st.columns([1, 1, 2])
                    if approve_col.button("Approve Remediation", key=f"approve_{thread_id}", type="primary"):
                        decide_ticket(thread_id, approved=True)
                        time.sleep(1)
                        st.rerun()
                    if deny_col.button("Deny", key=f"deny_{thread_id}"):
                        decide_ticket(thread_id, approved=False)
                        time.sleep(1)
                        st.rerun()

# Render KPI metrics last, after any ticket submission/approval in this run
with kpi_area:
    metrics = fetch_metrics()
    col1, col2, col3, col4 = st.columns(4)
    if metrics is None:
        col1.metric("AI Agents", "—", "Backend offline", delta_color="off")
        col2.metric("Tickets", "—")
        col3.metric("Vector DB", "—")
        col4.metric("Pending Approvals", "—")
    else:
        col1.metric("AI Agents", str(metrics["agent_count"]), "Online", help=", ".join(metrics["agents"]))
        tickets_delta = f"{metrics['tickets_resolved']} resolved"
        if metrics.get("tickets_denied"):
            tickets_delta += f", {metrics['tickets_denied']} denied"
        col2.metric("Tickets", str(metrics["tickets_total"]), tickets_delta, delta_color="off")
        if metrics["kb_online"]:
            kb_delta = f"{metrics['kb_records']} Records"
            if metrics.get("tickets_learned"):
                kb_delta += f" ({metrics['tickets_learned']} learned)"
            col3.metric("Vector DB", "Online", kb_delta, help="Seeded tickets plus tickets AIDA resolved and learned from")
        else:
            col3.metric("Vector DB", "Not seeded", "Run src/kb/setup.py", delta_color="off")

        pending_count = metrics["pending_approvals"]
        col4.metric("Pending Approvals", str(pending_count), "- Action Required" if pending_count > 0 else "Clear", delta_color="normal" if pending_count > 0 else "off")
