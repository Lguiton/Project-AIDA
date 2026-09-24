import streamlit as st
import requests
import time

# API Configuration
API_BASE = "http://127.0.0.1:8006/api"
API_URL = f"{API_BASE}/tickets"

st.set_page_config(page_title="Eivanta Labs | Project AIDA", layout="wide")


def fetch_tickets():
    """Tickets come from the backend (Postgres), so they survive restarts of either app."""
    try:
        response = requests.get(API_URL, params={"limit": 50}, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Could not load tickets from the backend: {e}")
        return None


def fetch_metrics():
    try:
        response = requests.get(f"{API_BASE}/metrics", timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def submit_ticket(issue_text):
    try:
        response = requests.post(API_URL, json={"issue": issue_text}, timeout=300)
        if response.status_code == 200:
            return True
        st.error(f"Backend returned {response.status_code}: {response.text}")
    except Exception as e:
        st.error(f"Failed to connect to backend: {e}")
    return False


def approve_ticket(thread_id):
    try:
        response = requests.post(f"{API_URL}/{thread_id}/approve", json={"approved": True}, timeout=300)
        if response.status_code == 200:
            st.success(f"Ticket {thread_id[:8]} approved and executed.")
        else:
            st.error(f"Approval failed ({response.status_code}): {response.text}")
    except Exception as e:
        st.error(f"Approval failed: {e}")


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
            created = (ticket.get("created_at") or "")[:16].replace("T", " ")
            specialist = (ticket.get("current_specialist") or "unknown").upper()
            is_open = ticket.get("status") != "resolved" or ticket.get("requires_approval")
            with st.expander(f"Ticket {thread_id[:8]} - Specialist: {specialist} - {created}", expanded=bool(is_open)):
                st.markdown(f"**Issue:** {ticket.get('issue')}")
                st.markdown(f"**Status:** `{ticket.get('status')}`")
                st.markdown(f"**Agent Response:**\n{ticket.get('last_message') or ''}")

                # Human-in-the-Loop Gateway
                if ticket.get("requires_approval"):
                    st.warning("⚠️ SECURITY GATEWAY: Agent is requesting permission to execute a destructive tool.")
                    if st.button("Approve Remediation", key=f"btn_{thread_id}", type="primary"):
                        approve_ticket(thread_id)
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
        col2.metric("Tickets", str(metrics["tickets_total"]), f"{metrics['tickets_resolved']} resolved", delta_color="off")
        if metrics["kb_online"]:
            col3.metric("Vector DB", "Online", f"{metrics['kb_records']} Records")
        else:
            col3.metric("Vector DB", "Not seeded", "Run src/kb/setup.py", delta_color="off")

        pending_count = metrics["pending_approvals"]
        col4.metric("Pending Approvals", str(pending_count), "- Action Required" if pending_count > 0 else "Clear", delta_color="normal" if pending_count > 0 else "off")
