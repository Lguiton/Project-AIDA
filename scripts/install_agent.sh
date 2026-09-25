#!/usr/bin/env bash
# Install (or update) AIDA's agent on another machine so AIDA can look after it over SSH.
#
#   scripts/install_agent.sh user@host [ssh-port]
#
# Needs: SSH key login with AIDA's key (~/.ssh/aida_ed25519) already working, and Python 3.10+ there.
# Windows PCs: run scripts/setup_windows_pc.ps1 on that PC first (SSH server + WSL shell + AIDA's key).
# Copies only the tool server (no database, no AI key, no .env) into ~/aida-agent and installs the
# `mcp` package into its own virtual environment. Run it again after updating AIDA to update the agent.
set -euo pipefail

target="${1:?usage: scripts/install_agent.sh user@host [ssh-port]}"
port="${2:-22}"
case "$target" in -*) echo "invalid target: $target" >&2; exit 1;; esac
cd "$(dirname "$0")/.."

ssh_opts=(-p "$port" -o BatchMode=yes -o ConnectTimeout=10)
key="${AIDA_SSH_KEY:-$HOME/.ssh/aida_ed25519}"
if [ -f "$key" ]; then ssh_opts+=(-i "$key" -o IdentitiesOnly=yes); fi  # the same key AIDA uses

echo "1/3 Checking SSH and Python on $target ..."
ssh "${ssh_opts[@]}" -- "$target" 'python3 -c "import sys; assert sys.version_info >= (3, 10), sys.version" && mkdir -p ~/aida-agent/src' \
  || { echo "Could not log in, or Python 3.10+ is missing there. Test with: ssh -i $key -p $port $target" >&2; exit 1; }

echo "2/3 Copying the AIDA agent ..."
tar -cf - mcp_server.py src/__init__.py src/monitor.py src/windows.py \
  | ssh "${ssh_opts[@]}" -- "$target" 'tar -xf - -C ~/aida-agent'

echo "3/3 Installing its Python package (mcp) ..."
ssh "${ssh_opts[@]}" -- "$target" \
  'cd ~/aida-agent && { [ -x venv/bin/python ] || python3 -m venv venv; } && venv/bin/pip install -q --upgrade pip "mcp>=1.2"' \
  || { echo "Setting up Python there failed. On that machine's Ubuntu run once: sudo apt install -y python3-venv" >&2; exit 1; }

cat <<DONE

Done. In AIDA's dashboard: Users & Notifications > Machines > Add a machine, with
  SSH target:      $target
  SSH port:        $port
  Remote command:  ~/aida-agent/venv/bin/python ~/aida-agent/mcp_server.py
then click "Test connection".
To give that machine its own settings (e.g. which services AIDA may restart), put them in front:
  env AIDA_RESTARTABLE_SERVICES=nginx,cron ~/aida-agent/venv/bin/python ~/aida-agent/mcp_server.py
Fixes that need root use sudo there without a password prompt; the tools print the exact sudoers line.
DONE
