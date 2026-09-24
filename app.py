import hmac
import os
import re
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# API Configuration
API_BASE = os.getenv("AIDA_API_URL", "http://127.0.0.1:8006/api")
API_URL = f"{API_BASE}/tickets"
# Shared key the backend requires on every /api call (AIDA_API_KEY in .env)
API_KEY = os.getenv("AIDA_API_KEY", "")

st.set_page_config(page_title="Eivanta Labs | Project AIDA", layout="wide")


def auth_headers():
    """API key for the backend plus the signed-in user's session token."""
    headers = {"X-AIDA-Key": API_KEY}
    if st.session_state.get("token"):
        headers["X-AIDA-User-Token"] = st.session_state.token
    return headers


def sign_out(message=None):
    for key in ("token", "username", "role"):
        st.session_state.pop(key, None)
    if message:
        st.session_state.login_message = message


def require_login():
    """Username + password sign-in through the API. The page stops here until the user is signed in."""
    if not API_KEY:
        st.error("AIDA_API_KEY is not set. Add it to .env and restart Streamlit.")
        st.stop()
    if st.session_state.get("token"):
        return

    st.title("🛡️ Project AIDA Command Center")
    if st.session_state.get("login_message"):
        st.info(st.session_state.pop("login_message"))
    with st.form("login_form"):
        username = st.text_input("Username", value="admin")
        entered = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        try:
            response = requests.post(f"{API_BASE}/auth/login", json={"username": username, "password": entered},
                                     headers={"X-AIDA-Key": API_KEY}, timeout=15)
        except Exception as e:
            st.error(f"Could not reach the AIDA backend: {e}")
            st.stop()
        if response.status_code == 200:
            data = response.json()
            st.session_state.token, st.session_state.username, st.session_state.role = data["token"], data["username"], data["role"]
            st.rerun()
        st.error(response.json().get("detail", "Sign-in failed.") if response.headers.get("content-type", "").startswith("application/json") else "Sign-in failed.")
    st.stop()


require_login()
ROLE = st.session_state.role
CAN_APPROVE = ROLE in ("approver", "admin")
IS_ADMIN = ROLE == "admin"

with st.sidebar:
    st.write(f"Signed in as **{st.session_state.username}** ({ROLE})")
    if st.button("Sign out"):
        sign_out()
        st.rerun()

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
        response = requests.get(API_URL, params={"limit": 50}, headers=auth_headers(), timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"Could not load tickets from the backend: {e}")
        return None


def fetch_metrics():
    try:
        response = requests.get(f"{API_BASE}/metrics", headers=auth_headers(), timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def submit_ticket(issue_text):
    try:
        response = requests.post(API_URL, json={"issue": issue_text}, headers=auth_headers(), timeout=300)
        if response.status_code == 200:
            return True
        st.error(f"Backend returned {response.status_code}: {response.text}")
    except Exception as e:
        st.error(f"Failed to connect to backend: {e}")
    return False


def forget_ticket(thread_id):
    """Take a ticket's answer out of the knowledge base (for answers that should not be reused)."""
    try:
        response = requests.post(f"{API_URL}/{thread_id}/forget", headers=auth_headers(), timeout=30)
        if response.status_code != 200:
            st.error(f"Could not remove ticket from the knowledge base ({response.status_code}): {response.text}")
    except Exception as e:
        st.error(f"Could not remove ticket from the knowledge base: {e}")


def api_call(method, path, error_label, **kwargs):
    """Call the backend; show an error and return None on failure."""
    try:
        response = requests.request(method, f"{API_BASE}{path}", headers=auth_headers(), timeout=kwargs.pop("timeout", 60), **kwargs)
        if response.status_code == 200:
            return response.json()
        if response.status_code == 401 and st.session_state.get("token"):
            sign_out("Your session ended. Please sign in again.")
            st.rerun()
        detail = response.json().get("detail") if response.headers.get("content-type", "").startswith("application/json") else response.text
        st.error(f"{error_label}: {detail}")
    except Exception as e:
        st.error(f"{error_label}: {e}")
    return None


def decide_ticket(thread_id, approved):
    """Send the operator's decision on a pending remediation (approve runs it, deny closes the ticket)."""
    action = "Approval" if approved else "Denial"
    try:
        response = requests.post(f"{API_URL}/{thread_id}/approve", json={"approved": approved}, headers=auth_headers(), timeout=300)
        if response.status_code == 200:
            if approved:
                st.success(f"Ticket {thread_id[:8]} approved and executed.")
            else:
                st.info(f"Ticket {thread_id[:8]} denied. No action was taken.")
        else:
            st.error(f"{action} failed ({response.status_code}): {response.text}")
    except Exception as e:
        st.error(f"{action} failed: {e}")


# Sidebar actions run before the ticket list is loaded, so their results show immediately
with st.sidebar:
    st.divider()
    st.subheader("Quick actions")
    if CAN_APPROVE and st.button("Run health checks now", help="Disk, memory, load, failed services and certificates. Opens tickets for new problems."):
        with st.spinner("Checking the machine..."):
            result = api_call("POST", "/monitor/run", "Health checks failed", timeout=600)
        if result is not None:
            st.success(f"{len(result.get('alerts', []))} problem(s) found, {len(result.get('opened', []))} new ticket(s) opened.")
    if st.button("Run security health check", help="Scored security audit of this machine (read-only)."):
        with st.spinner("Security specialist auditing..."):
            done = api_call("POST", "/tickets", "Security check failed",
                            json={"issue": "Run a full security health check of this machine."}, timeout=300)
        if done is not None:
            st.success("Security report added to the ticket queue.")

RUNBOOKS = api_call("GET", "/runbooks", "Could not load runbooks") or {}

# --- UI Layout ---
st.title("🛡️ Project AIDA Command Center")
st.markdown("Autonomous IT Operations Help Desk")

# Top KPI Metrics (placeholder; filled at the end of the script so counts include this run's changes)
kpi_area = st.container()

st.divider()

tab_names = (["Tickets"] + (["Monitoring & Audit", "Reports"] if CAN_APPROVE else [])
             + (["Users & Notifications", "Maintenance"] if IS_ADMIN else []))
tabs = dict(zip(tab_names, st.tabs(tab_names)))
tickets_tab = tabs["Tickets"]
audit_tab = tabs.get("Monitoring & Audit")
reports_tab = tabs.get("Reports")
admin_tab = tabs.get("Users & Notifications")
maintenance_tab = tabs.get("Maintenance")

# Main Workspace
with tickets_tab:
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
                is_open = ticket.get("status") not in ("resolved", "denied", "failed") or ticket.get("requires_approval")
                origin = {"monitor": "🤖 Auto-detected · ", "schedule": "🗓️ Scheduled · "}.get(ticket.get("source"), "")
                with st.expander(f"{origin}Ticket {thread_id[:8]} - Specialist: {specialist} - {created}", expanded=bool(is_open)):
                    st.markdown(f"**Issue:** {ticket.get('issue')}")
                    st.markdown(f"**Status:** `{ticket.get('status')}`")
                    st.markdown(f"**Agent Response:**\n{ticket.get('last_message') or ''}")
                    if ticket.get("learned"):
                        st.caption("📚 Added to the knowledge base for future tickets.")
                        if CAN_APPROVE and st.button("Remove from knowledge base", key=f"forget_{thread_id}"):
                            forget_ticket(thread_id)
                            st.rerun()

                    # Human-in-the-Loop Gateway
                    if ticket.get("requires_approval"):
                        st.warning("⚠️ SECURITY GATEWAY: Agent is requesting permission to execute a destructive tool.")
                        if not CAN_APPROVE:
                            st.caption("Waiting for an approver. Your role can submit tickets but not approve fixes.")
                            continue
                        runbook = re.search(r"run_runbook` with \{'name': '([a-z_]+)'\}", ticket.get("last_message") or "")
                        if runbook and RUNBOOKS.get(runbook.group(1)):
                            steps = RUNBOOKS[runbook.group(1)]["steps"]
                            st.caption("Runbook steps: " + " → ".join(steps))
                        approve_col, deny_col, _ = st.columns([1, 1, 3])
                        if approve_col.button("Approve", key=f"approve_{thread_id}", type="primary"):
                            decide_ticket(thread_id, approved=True)
                            time.sleep(1)
                            st.rerun()
                        if deny_col.button("Deny", key=f"deny_{thread_id}"):
                            decide_ticket(thread_id, approved=False)
                            time.sleep(1)
                            st.rerun()

if audit_tab is not None:
    with audit_tab:
        monitor_col, audit_col = st.columns([1, 1.5])
        with monitor_col:
            st.subheader("Proactive monitoring")
            status = api_call("GET", "/monitor/status", "Could not load monitoring status")
            if status:
                if status["enabled"]:
                    st.caption(f"Checks run every {status['interval_seconds'] / 60:.0f} minute(s) and open tickets for new problems.")
                else:
                    st.caption("Scheduled checks are off (AIDA_MONITOR_INTERVAL=0). Use 'Run health checks now'.")
                if status.get("checked_at"):
                    st.write(f"Last run: {format_timestamp(status['checked_at'])}")
                    if status.get("error"):
                        st.error(f"Last run failed: {status['error']}")
                    elif not status["alerts"]:
                        st.success("All checks passed.")
                    opened_keys = {o["alert_key"] for o in status.get("opened", [])}
                    for alert in status["alerts"]:
                        note = "new ticket opened" if alert["key"] in opened_keys else "already has a ticket"
                        st.warning(f"**{alert['check']}**: {alert['issue'].split('] ', 1)[-1]} _({note})_")
                else:
                    st.info("No checks have run yet since the API started.")

        with audit_col:
            st.subheader("Audit log")
            st.caption("Every ticket, approval, denial, executed fix and knowledge change. "
                       "Entries are hash-chained, so any later edit is detectable.")
            if st.button("Verify audit log integrity"):
                result = api_call("GET", "/audit/verify", "Could not verify the audit log")
                if result:
                    (st.success if result["ok"] else st.error)(result["message"])
            entries = api_call("GET", "/audit", "Could not load the audit log", params={"limit": 200})
            if entries:
                st.dataframe(
                    [{
                        "#": e["id"],
                        "Time": format_timestamp(e["ts"]),
                        "Who": e["actor"],
                        "Action": e["action"],
                        "Ticket": (e["thread_id"] or "")[:8],
                        "Details": ", ".join(f"{k}: {v}" for k, v in (e["details"] or {}).items()),
                    } for e in entries],
                    hide_index=True, width="stretch",
                )
            elif entries is not None:
                st.info("No audit entries yet.")

if admin_tab is not None:
    with admin_tab:
        users_col, notify_col = st.columns([1.3, 1])
        with users_col:
            st.subheader("Users")
            st.caption("Requesters submit tickets. Approvers also approve or deny fixes and see the audit log. Admins also manage users.")
            user_list = api_call("GET", "/users", "Could not load users")
            if user_list:
                st.dataframe(
                    [{"User": u["username"], "Role": u["role"], "Status": "disabled" if u["disabled"] else "active",
                      "Created": format_timestamp(u["created_at"])} for u in user_list],
                    hide_index=True, width="stretch",
                )
            with st.form("add_user", clear_on_submit=True):
                st.markdown("**Add a user**")
                new_name = st.text_input("Username")
                new_role = st.selectbox("Role", ["requester", "approver", "admin"])
                new_password = st.text_input("Temporary password (10+ characters)", type="password")
                if st.form_submit_button("Add user") and new_name:
                    if api_call("POST", "/users", "Could not add user",
                                json={"username": new_name, "password": new_password, "role": new_role}) is not None:
                        st.success(f"Added {new_name.strip().lower()} as {new_role}.")
            if user_list:
                with st.form("change_user"):
                    st.markdown("**Change a user**")
                    target = st.selectbox("User", [u["username"] for u in user_list])
                    change_role = st.selectbox("New role", ["(no change)", "requester", "approver", "admin"])
                    change_state = st.selectbox("Account", ["(no change)", "enable", "disable"])
                    change_password = st.text_input("New password (leave blank to keep)", type="password")
                    if st.form_submit_button("Save changes"):
                        body = {}
                        if change_role != "(no change)":
                            body["role"] = change_role
                        if change_state != "(no change)":
                            body["disabled"] = change_state == "disable"
                        if change_password:
                            body["password"] = change_password
                        if body and api_call("POST", f"/users/{target}", "Could not update user", json=body) is not None:
                            st.success(f"Updated {target}.")

        with notify_col:
            st.subheader("Notifications")
            status = api_call("GET", "/notify/status", "Could not load notification settings")
            if status:
                channels = []
                if status["webhooks"]:
                    channels.append(f"{status['webhooks']} webhook(s)")
                if status["email"]:
                    channels.append("email")
                if channels:
                    st.write("Sending to: " + ", ".join(channels))
                    st.caption("Events: " + ", ".join(e.replace("_", " ") for e in status["events"]))
                else:
                    st.info("No channels configured. Add AIDA_NOTIFY_WEBHOOK_URLS (Slack, Teams or Discord) "
                            "and/or the AIDA_SMTP_* email settings to .env, then restart the API.")
                if st.button("Send test notification"):
                    result = api_call("POST", "/notify/test", "Test notification failed", timeout=60)
                    if result:
                        for r in result["results"]:
                            (st.success if r["ok"] else st.error)(f"{r['channel']}: {'delivered' if r['ok'] else r['error']}")
                if status["recent"]:
                    st.markdown("**Recent deliveries**")
                    st.dataframe(
                        [{"Time": format_timestamp(r["at"]), "Event": r["event"], "Channel": r["channel"],
                          "Result": "delivered" if r["ok"] else f"failed: {r['error']}"} for r in status["recent"]],
                        hide_index=True, width="stretch",
                    )

if reports_tab is not None:
    with reports_tab:
        days = st.selectbox("Period", [7, 30, 90, 365], index=1, format_func=lambda d: f"Last {d} days")
        report = api_call("GET", "/reports/summary", "Could not load the report", params={"days": days})
        if report:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Tickets", report["total"], f"{report['auto_detected']} auto-detected", delta_color="off")
            c2.metric("Resolved without a person",
                      f"{report['hands_free_rate']}%" if report["hands_free_rate"] is not None else "—",
                      f"{report['hands_free_resolved']} of {report['audited_resolved']} resolved", delta_color="off",
                      help="Resolved tickets that needed no approval. Counts tickets created since the audit log was added.")
            c3.metric("Median wait for approval",
                      f"{report['median_approval_wait_minutes']} min" if report["median_approval_wait_minutes"] is not None else "—",
                      f"{report['approvals']} approved, {report['denials']} denied", delta_color="off")
            c4.metric("Estimated hours saved", report["estimated_hours_saved"],
                      f"at {report['minutes_saved_per_ticket']:g} min per resolved ticket", delta_color="off",
                      help="Estimate: resolved tickets × AIDA_MINUTES_SAVED_PER_TICKET (set in .env).")
            chart_col, table_col = st.columns([1.4, 1])
            with chart_col:
                st.markdown("**Tickets per day**")
                if report["by_day"]:
                    st.bar_chart({row["day"]: row["n"] for row in report["by_day"]}, color="#10b981",
                                 x_label="Day", y_label="Tickets")
                else:
                    st.caption("No tickets in this period.")
                st.markdown("**Tickets by specialist**")
                if report["by_specialist"]:
                    st.bar_chart({row["name"]: row["n"] for row in report["by_specialist"]}, color="#10b981",
                                 horizontal=True, x_label="Tickets", y_label="Specialist")
            with table_col:
                st.markdown("**Outcome**")
                st.dataframe([{"Status": r["name"], "Tickets": r["n"]} for r in report["by_status"]],
                             hide_index=True, width="stretch")
                st.markdown("**Recurring problems**")
                recurring = ([{"Problem": r["name"], "Times": r["n"]} for r in report["recurring_alerts"]]
                             + [{"Problem": r["name"][:80], "Times": r["n"]} for r in report["recurring_issues"]])
                if recurring:
                    st.dataframe(recurring, hide_index=True, width="stretch")
                else:
                    st.caption("Nothing recurring yet.")

        st.divider()
        st.subheader("Compliance evidence report")
        st.caption("HIPAA-oriented technical safeguards, the security health check, audit-log integrity and access "
                   "activity in one document. A self-assessment aid, not a certification or legal advice.")
        if st.button("Generate compliance report"):
            with st.spinner("Checking safeguards..."):
                compliance = api_call("GET", "/reports/compliance", "Could not build the compliance report",
                                      params={"days": days}, timeout=300)
            if compliance:
                st.session_state.compliance = compliance
        compliance = st.session_state.get("compliance")
        if compliance:
            passed = sum(c["status"] == "pass" for c in compliance["checks"])
            st.write(f"**{passed} of {len(compliance['checks'])} technical safeguards pass.** "
                     f"Audit log: {'intact ✅' if compliance['audit']['ok'] else 'ALTERED ❌'}")
            icons = {"pass": "✅ Pass", "fail": "❌ Fail", "unknown": "❔ Unknown"}
            st.dataframe([{"Status": icons.get(c["status"], c["status"]), "Safeguard": c["safeguard"],
                           "Citation": "§" + c["citation"], "Finding": c["detail"], "Fix": c["fix"]}
                          for c in compliance["checks"]], hide_index=True, width="stretch")
            st.download_button("Download report (Markdown)", compliance["markdown"],
                               file_name="aida-compliance-report.md", mime="text/markdown")

if maintenance_tab is not None:
    with maintenance_tab:
        st.subheader("Scheduled maintenance")
        st.caption("Runbooks that run automatically at a set time. Creating a schedule approves its runs in advance; "
                   "every run is recorded in the audit log and appears in the ticket queue.")
        schedules = api_call("GET", "/schedules", "Could not load schedules") or []
        for sched in schedules:
            with st.container(border=True):
                st.markdown(f"**{sched['name']}** — runbook `{sched['runbook']}`, {sched['description']} "
                            f"({'enabled' if sched['enabled'] else 'paused'}; created by {sched['created_by']})")
                info = []
                if sched.get("next_run_at"):
                    info.append(f"Next run: {format_timestamp(sched['next_run_at'])}")
                if sched.get("last_run_at"):
                    info.append(f"Last run: {format_timestamp(sched['last_run_at'])} ({sched['last_status']})")
                if info:
                    st.caption(" · ".join(info))
                b1, b2, b3, _ = st.columns([1, 1, 1, 3])
                if b1.button("Run now", key=f"run_{sched['id']}"):
                    with st.spinner("Running..."):
                        result = api_call("POST", f"/schedules/{sched['id']}/run", "Run failed", timeout=1800)
                    if result:
                        (st.success if result["status"] == "resolved" else st.error)(result["result"].splitlines()[0])
                if b2.button("Pause" if sched["enabled"] else "Resume", key=f"toggle_{sched['id']}"):
                    api_call("POST", f"/schedules/{sched['id']}", "Update failed", json={"enabled": not sched["enabled"]})
                    st.rerun()
                if b3.button("Delete", key=f"delete_{sched['id']}"):
                    api_call("POST", f"/schedules/{sched['id']}/delete", "Delete failed")
                    st.rerun()
        if not schedules:
            st.info("No schedules yet.")

        with st.form("new_schedule", clear_on_submit=True):
            st.markdown("**New schedule**")
            name = st.text_input("Name", placeholder="Weekly disk cleanup")
            runbook = st.selectbox("Runbook", list(RUNBOOKS) or ["disk_cleanup"],
                                   format_func=lambda r: f"{r} — {RUNBOOKS.get(r, {}).get('description', '')}")
            frequency = st.radio("How often", ["weekly", "daily"], horizontal=True)
            weekday = st.selectbox("Day (weekly only)", ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"])
            at_time = st.text_input("Time (24-hour, your time zone)", value="02:00")
            if st.form_submit_button("Create schedule") and name:
                if api_call("POST", "/schedules", "Could not create schedule", json={
                    "name": name, "runbook": runbook, "frequency": frequency,
                    "weekday": weekday if frequency == "weekly" else None, "at_time": at_time,
                }) is not None:
                    st.success(f"Scheduled '{name}'.")
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
        if metrics.get("tickets_auto"):
            tickets_delta += f", {metrics['tickets_auto']} auto"
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
