"""Streamlit dashboard: the login gate (no backend needed)."""
from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "app.py")


def test_dashboard_requires_login():
    at = AppTest.from_file(APP, default_timeout=30).run()
    assert not at.exception
    assert [t.label for t in at.text_input] == ["Operator password"]
    assert not any("Ticket Queue" in h.value for h in at.subheader)


def test_wrong_password_is_rejected():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input[0].input("wrong")
    at.button[0].click().run()
    assert any("Incorrect password" in e.value for e in at.error)
    assert not at.session_state["authenticated"] if "authenticated" in at.session_state else True


def test_correct_password_opens_dashboard():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input[0].input("test-password")
    at.button[0].click().run()
    assert not at.exception
    assert any("Ticket Queue" in h.value for h in at.subheader)
