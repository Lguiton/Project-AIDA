"""Daily database backup: backup_database tool (fake pg_dump / docker, so no real database is touched)."""
import os

import mcp_server
from tests.test_phase7_tools import fake_bin


def test_backup_via_docker_keeps_newest(tmp_path, monkeypatch):
    backups = tmp_path / "backups"
    backups.mkdir()
    for day in range(1, 5):  # older backups, plus an unrelated file that must never be touched
        (backups / f"aida_kb_2026-09-0{day}_020000.dump").write_bytes(b"PGDMP old")
    (backups / "notes.txt").write_text("keep me")
    monkeypatch.setenv("AIDA_BACKUP_DIR", str(backups))
    monkeypatch.setenv("AIDA_DB_URI", "postgresql://aida:pw@localhost:55432/aida_kb")
    log = tmp_path / "docker.log"
    fake_bin(tmp_path, monkeypatch, {
        "pg_dump": "exit 1",  # e.g. an older pg_dump than the server: falls back to docker
        "docker": f'echo "$*" >> {log}; case "$1" in ps) echo project-aida-pgvector-1;; exec) printf "PGDMP backup-data";; esac',
    })
    result = mcp_server.backup_database(keep=3)
    assert result.startswith("SUCCESS") and "using docker" in result and "removed 2 older" in result
    names = sorted(os.listdir(backups))
    assert "notes.txt" in names and len([n for n in names if n.endswith(".dump")]) == 3
    assert "exec project-aida-pgvector-1 pg_dump -U aida -d aida_kb -Fc" in log.read_text()
    assert "publish=55432" in log.read_text()
    assert not [n for n in names if n.endswith(".partial")]


def test_backup_rejects_invalid_output_and_reports_why(tmp_path, monkeypatch):
    monkeypatch.setenv("AIDA_BACKUP_DIR", str(tmp_path / "b"))
    fake_bin(tmp_path, monkeypatch, {
        "pg_dump": 'echo "server version mismatch" >&2; exit 1',
        "docker": 'case "$1" in ps) echo db;; exec) echo "not a backup";; esac',
    })
    result = mcp_server.backup_database()
    assert result.startswith("FAILED") and "server version mismatch" in result
    assert os.listdir(tmp_path / "b") == []  # no half-written or invalid file is left behind


def test_database_backup_runbook_exists():
    assert mcp_server.RUNBOOKS["database_backup"]["steps"] == [("backup_database", {"keep": 14})]
