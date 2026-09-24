"""Streamlit dashboard against a real running API (fake AI model): sign-in and role-based screens."""
import socket
import threading
import time
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "app.py")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_api(test_db, temp_dir_for_tools, monkeypatch):
    import uvicorn
    from langchain_core.embeddings import DeterministicFakeEmbedding

    import main
    import src.kb.store as store
    from tests.fakes import FakeChatModel

    monkeypatch.setattr(main, "ChatOpenAI", lambda **kwargs: FakeChatModel())
    monkeypatch.setattr(store, "embeddings_factory", lambda: DeterministicFakeEmbedding(size=16))
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(main.app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 60
    while not server.started:
        assert time.time() < deadline, "API did not start"
        time.sleep(0.2)
    monkeypatch.setenv("AIDA_API_URL", f"http://127.0.0.1:{port}/api")
    yield f"http://127.0.0.1:{port}/api"
    server.should_exit = True
    thread.join(timeout=30)


def sign_in(username, password):
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.text_input[0].set_value(username)
    at.text_input[1].set_value(password)
    at.button[0].click().run()
    return at


def test_dashboard_requires_login(monkeypatch):
    monkeypatch.setenv("AIDA_API_URL", "http://127.0.0.1:9/api")  # backend not needed to show the form
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert [t.label for t in at.text_input] == ["Username", "Password"]
    assert not at.tabs


def test_backend_down_shows_a_clear_error(monkeypatch):
    monkeypatch.setenv("AIDA_API_URL", "http://127.0.0.1:9/api")
    at = sign_in("admin", "test-password")
    assert any("Could not reach the AIDA backend" in e.value for e in at.error)


def test_wrong_password_is_rejected(live_api):
    at = sign_in("admin", "wrong")
    assert any("Incorrect username or password" in e.value for e in at.error)
    assert not at.tabs


def test_admin_sees_every_tab(live_api):
    at = sign_in("admin", "test-password")
    assert not at.exception
    assert [t.label for t in at.tabs] == ["Tickets", "Monitoring & Audit", "Reports", "Users & Notifications", "Maintenance"]
    assert any("Signed in as **admin** (admin)" in m.value for m in at.sidebar.markdown)


def test_requester_sees_only_tickets_and_cannot_approve(live_api):
    import requests
    headers = {"X-AIDA-Key": "test-api-key"}
    requests.post(f"{live_api}/users", json={"username": "rita", "password": "requester-pass", "role": "requester"}, headers=headers)
    at = sign_in("rita", "requester-pass")
    at.text_area[0].input("please flush my dns")
    [b for b in at.button if b.label == "Deploy Agent"][0].click().run()

    assert [t.label for t in at.tabs] == ["Tickets"]
    assert not any(b.label == "Approve" for b in at.button)
    assert any("Waiting for an approver" in c.value for c in at.caption)
    assert not any(b.label == "Run health checks now" for b in at.button)
