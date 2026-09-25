#!/usr/bin/env bash
# Start everything AIDA needs, in order, with one command:
#
#     ./start_aida.sh          (from the project-aida folder, in Ubuntu/WSL)
#
#   1. Docker (the snap Docker inside Ubuntu), if it isn't running
#   2. The database container, then waits until Postgres accepts connections
#   3. The API (port 8006), then waits until it answers
#   4. The dashboard (port 8501)
# Press Ctrl+C in this window to stop the API and the dashboard (the database keeps running).
# Logs: logs/api.log and logs/dashboard.log
set -uo pipefail
cd "$(dirname "$0")"

say() { printf '\n== %s\n' "$*"; }
fail() { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }

if [ ! -x venv/bin/python ]; then
    fail "No virtual environment at ./venv. Create it once: python3 -m venv venv && venv/bin/pip install -r requirements.txt"
fi
for port in 8006 8501; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
        fail "Something is already using port $port (AIDA may already be running in another window). Stop it first."
    fi
done

# ---- 1. Docker ----------------------------------------------------------------------
say "Docker"
if ! docker info >/dev/null 2>&1; then
    echo "   Docker is not running; starting it (you may be asked for your Ubuntu password)..."
    sudo snap start docker >/dev/null 2>&1 || sudo systemctl start docker >/dev/null 2>&1 || true
    for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
    docker info >/dev/null 2>&1 || fail "Docker did not start. Try: sudo snap start docker   (then run this again)"
fi
echo "   OK"

# ---- 2. Database --------------------------------------------------------------------
say "Database"
docker compose up -d >/dev/null || fail "docker compose up -d failed (run it by hand to see why)."
for i in $(seq 1 60); do
    if docker compose exec -T pgvector pg_isready -U aida >/dev/null 2>&1; then break; fi
    [ "$i" -eq 60 ] && fail "The database did not become ready within 60 seconds. See: docker compose logs --tail 30"
    sleep 1
done
echo "   OK (Postgres on 127.0.0.1:55432)"

# ---- 3. API ---------------------------------------------------------------------------
mkdir -p logs
say "API (port 8006)"
venv/bin/python -m uvicorn main:app --port 8006 > logs/api.log 2>&1 &
API_PID=$!
DASH_PID=""
cleanup() {
    say "Stopping the API and the dashboard"
    [ -n "$DASH_PID" ] && kill "$DASH_PID" 2>/dev/null
    kill "$API_PID" 2>/dev/null
    wait 2>/dev/null
    echo "   Stopped. (The database keeps running; stop it with: docker compose stop)"
}
trap cleanup INT TERM EXIT
for i in $(seq 1 180); do
    if grep -q "Project AIDA API Ready" logs/api.log 2>/dev/null; then break; fi
    if ! kill -0 "$API_PID" 2>/dev/null; then
        tail -n 15 logs/api.log
        trap - EXIT
        fail "The API stopped while starting (last lines of logs/api.log above)."
    fi
    [ "$i" -eq 180 ] && fail "The API did not start within 3 minutes. See logs/api.log"
    sleep 1
done
echo "   OK"

# ---- 4. Dashboard -----------------------------------------------------------------------
say "Dashboard (port 8501)"
venv/bin/python -m streamlit run app.py --server.port 8501 --server.headless true > logs/dashboard.log 2>&1 &
DASH_PID=$!
for i in $(seq 1 60); do
    if (exec 3<>/dev/tcp/127.0.0.1/8501) 2>/dev/null; then break; fi
    if ! kill -0 "$DASH_PID" 2>/dev/null; then
        tail -n 15 logs/dashboard.log
        fail "The dashboard stopped while starting (last lines of logs/dashboard.log above)."
    fi
    [ "$i" -eq 60 ] && fail "The dashboard did not start within 60 seconds. See logs/dashboard.log"
    sleep 1
done
echo "   OK"

cat <<'READY'

AIDA is running.
   Dashboard:  http://localhost:8501
   API:        http://127.0.0.1:8006
Leave this window open. Press Ctrl+C here to stop AIDA.
READY

# Keep running until Ctrl+C, and notice if either part stops on its own
while kill -0 "$API_PID" 2>/dev/null && kill -0 "$DASH_PID" 2>/dev/null; do sleep 5; done
echo
kill -0 "$API_PID" 2>/dev/null || { echo "The API stopped unexpectedly. Last lines of logs/api.log:"; tail -n 15 logs/api.log; }
kill -0 "$DASH_PID" 2>/dev/null || { echo "The dashboard stopped unexpectedly. Last lines of logs/dashboard.log:"; tail -n 15 logs/dashboard.log; }
exit 1
