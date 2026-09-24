# Project AIDA

Autonomous IT Operations Help Desk by Eivanta Labs. Describe an IT problem in the dashboard and AIDA routes it to a specialist agent that investigates your machine with real diagnostic tools. Anything that changes the system waits for an operator to approve or deny it.

## How it works

- **Dashboard** (`app.py`, Streamlit): operator login, submit issues, approve/deny fixes, live metrics.
- **API** (`main.py`, FastAPI on port 8006): runs the LangGraph workflow; every `/api` call needs the `X-AIDA-Key` header.
- **Agents** (`src/graph/`): a triage router plus network, OS diagnostics, security, remediation and knowledge-base specialists.
- **Tools** (`mcp_server.py`, MCP): read-only diagnostics run freely; `flush_dns_cache`, `restart_service` (allowlisted services only) and `clear_temp_files` run only after approval.
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
