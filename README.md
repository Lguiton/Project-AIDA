# Project AIDA

Autonomous IT Operations Help Desk by Eivanta Labs. Describe an IT problem in the dashboard and AIDA routes it to a specialist agent that investigates your machine with real diagnostic tools. Anything that changes the system waits for an operator to approve or deny it.

## How it works

- **Dashboard** (`app.py`, Streamlit): operator login, submit issues, approve/deny fixes, live metrics.
- **API** (`main.py`, FastAPI on port 8006): runs the LangGraph workflow; every `/api` call needs the `X-AIDA-Key` header.
- **Agents** (`src/graph/`): a triage router plus network, OS diagnostics, security, remediation and knowledge-base specialists.
- **Tools** (`mcp_server.py`, MCP): read-only diagnostics run freely; `flush_dns_cache`, `restart_service` (allowlisted services only) and `clear_temp_files` run only after approval.
- **Proactive monitoring** (`src/monitor.py`): checks disk, memory, load, failed services and TLS certificates on a schedule and opens its own tickets (one per problem).
- **Security health check**: a scored, read-only audit (admin accounts, exposed services, SSH hardening, firewall, pending security updates, secrets-file permissions, suspicious setuid programs, failed logins).
- **Audit log** (`src/audit.py`): every ticket, approval, denial, executed fix and knowledge change, hash-chained and append-only so tampering is detectable.
- **Users and roles** (`src/users.py`): requesters submit tickets, approvers approve fixes and see the audit log, admins manage users. The first user, `admin`, gets the password from `AIDA_UI_PASSWORD`.
- **Notifications** (`src/notify.py`): Slack, Teams or Discord webhooks and/or email when approval is needed, a problem is detected, a fix fails or a ticket needs a human.
- **Fixes behind approval**: DNS flush, service and container restarts, temp-file cleanup, log rotation, Docker cleanup, blocking/unblocking an attacking IP, installing security updates, and **runbooks** (several steps under one approval: `disk_cleanup`, `network_reset`, `security_patch`).
- **Attack monitoring**: repeated failed logins from one address open a ticket that proposes blocking it.
- **Vulnerability scan**: pending OS security updates plus known-vulnerable Python packages (pip-audit).
- **Scheduled maintenance** (`src/scheduler.py`): admins schedule runbooks daily or weekly; each run is audited and ticketed.
- **Reports** (`src/reports.py`): tickets over time, share resolved without a person, approval wait times, recurring problems, estimated hours saved, and a downloadable **compliance evidence report** mapped to HIPAA Security Rule technical safeguards (a self-assessment aid, not a certification).
- **Memory** (Postgres + pgvector via `docker-compose.yml`): tickets and agent history survive restarts; resolved tickets are added to the knowledge base so similar issues are answered from history.

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then fill in OPENAI_API_KEY, AIDA_API_KEY, AIDA_UI_PASSWORD
docker compose up -d        # Postgres + pgvector on localhost:55432
python -m src.kb.setup      # seed the knowledge base (first time)
```

## Run

```bash
uvicorn main:app --port 8006     # terminal 1
streamlit run app.py             # terminal 2, then open http://localhost:8501
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

Tests use a fake AI model and fake embeddings (no OpenAI calls), a separate `aida_test` database, and never change your system. API tests are skipped if Postgres is not running.

## Roadmap

- **Multiple machines**: run `mcp_server.py` on each server (for example over SSH, which MCP's stdio transport supports as `ssh host python mcp_server.py`) and connect them all to one AIDA, with machine-prefixed tools and a machine picker on each ticket.
- **Approve from your phone**: needs the dashboard published behind HTTPS with sign-in (e.g. a reverse proxy or tunnel); notifications would then carry a one-tap approval link.
