import streamlit as st
import requests
import time

# API Configuration
API_URL = "http://127.0.0.1:8006/api/tickets"

st.set_page_config(page_title="Eivanta Labs | Project AIDA", layout="wide")

# Initialize session state to track tickets during the session
if "active_tickets" not in st.session_state:
    st.session_state.active_tickets = {}

def submit_ticket(issue_text):
    try:
        response = requests.post(API_URL, json={"issue": issue_text})
        if response.status_code == 200:
            data = response.json()
            st.session_state.active_tickets[data["thread_id"]] = data
            return True
    except Exception as e:
        st.error(f"Failed to connect to backend: {e}")
    return False

def approve_ticket(thread_id):
    try:
        response = requests.post(f"{API_URL}/{thread_id}/approve", json={"approved": True})
        if response.status_code == 200:
            st.success(f"Ticket {thread_id[:8]} approved and executed.")
            # Refresh the ticket status
            res = requests.get(f"{API_URL}/{thread_id}")
            if res.status_code == 200:
                st.session_state.active_tickets[thread_id] = res.json()
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
    st.subheader("Active Ticket Queue")
    
    if not st.session_state.active_tickets:
        st.info("No active tickets in current session.")
    else:
        for thread_id, ticket_data in reversed(st.session_state.active_tickets.items()):
            with st.expander(f"Ticket {thread_id[:8]} - Specialist: {ticket_data.get('current_specialist', 'Unknown').upper()}", expanded=True):
                
                st.markdown(f"**Status:** `{ticket_data.get('status')}`")
                st.markdown(f"**Agent Response:**\n{ticket_data.get('last_message')}")
                
                # Human-in-the-Loop Gateway
                if ticket_data.get("requires_approval"):
                    st.warning("⚠️ SECURITY GATEWAY: Agent is requesting permission to execute a destructive tool.")
                    if st.button("Approve Remediation", key=f"btn_{thread_id}", type="primary"):
                        approve_ticket(thread_id)
                        time.sleep(1)
                        st.rerun()

# Render KPI metrics last, after any ticket submission/approval in this run
with kpi_area:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Active Agents", "4", "Online")
    col2.metric("Tickets Processed", str(len(st.session_state.active_tickets)), "Session")
    col3.metric("Vector DB", "Online", "3 Records")

    pending_count = sum(1 for t in st.session_state.active_tickets.values() if t.get("requires_approval"))
    col4.metric("Pending Approvals", str(pending_count), "- Action Required" if pending_count > 0 else "Clear", delta_color="inverse" if pending_count > 0 else "off")
