"""Sign-in, roles and account management."""
import pytest

from src import users
from tests.conftest import login, make_user

pytestmark = pytest.mark.usefixtures("test_db")


@pytest.fixture(autouse=True)
def reset_lockouts():
    users._failures.clear()
    yield
    users._failures.clear()


def test_first_admin_is_created_from_env_password(api_client):
    with api_client() as client:
        headers = login(client, "admin", "test-password")
        assert client.get("/api/auth/me", headers=headers).json() == {"username": "admin", "role": "admin"}


def test_wrong_password_and_lockout(api_client):
    with api_client() as client:
        for _ in range(users.MAX_FAILED_LOGINS):
            assert client.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401
        # Even the right password is refused while locked out
        assert client.post("/api/auth/login", json={"username": "admin", "password": "test-password"}).status_code == 429
        failed = [e for e in client.get("/api/audit").json() if e["action"] == "auth.login_failed"]
        assert len(failed) >= users.MAX_FAILED_LOGINS


def test_requester_can_submit_but_not_approve(api_client):
    with api_client() as client:
        carol = make_user(client, "carol", "requester")
        dave = make_user(client, "dave", "approver")

        ticket = client.post("/api/tickets", json={"issue": "please flush my dns"}, headers=carol).json()
        assert ticket["requires_approval"]

        denied = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": True}, headers=carol)
        assert denied.status_code == 403
        assert client.get("/api/audit", headers=carol).status_code == 403
        assert client.post("/api/monitor/run", headers=carol).status_code == 403
        assert client.get("/api/users", headers=carol).status_code == 403

        ok = client.post(f"/api/tickets/{ticket['thread_id']}/approve", json={"approved": False}, headers=dave)
        assert ok.status_code == 200
        assert client.get("/api/users", headers=dave).status_code == 403  # approvers can't manage users

        entries = client.get("/api/audit", params={"thread_id": ticket["thread_id"]}, headers=dave).json()
        actors = {e["action"]: e["actor"] for e in entries}
        assert actors["ticket.created"] == "carol" and actors["remediation.denied"] == "dave"


def test_disabled_account_is_locked_out_immediately(api_client):
    with api_client() as client:
        erin = make_user(client, "erin", "approver")
        assert client.get("/api/tickets", headers=erin).status_code == 200
        client.post("/api/users/erin", json={"disabled": True})
        assert client.get("/api/tickets", headers=erin).status_code == 401  # existing session rejected
        assert client.post("/api/auth/login", json={"username": "erin", "password": "correct-horse-1"}).status_code == 401


def test_role_change_applies_to_existing_session(api_client):
    with api_client() as client:
        frank = make_user(client, "frank", "approver")
        client.post("/api/users/frank", json={"role": "requester"})
        assert client.get("/api/audit", headers=frank).status_code == 403


def test_forged_or_tampered_tokens_are_rejected(api_client):
    with api_client() as client:
        token = login(client, "admin", "test-password")["X-AIDA-User-Token"]
        payload, signature = token.rsplit(".", 1)
        tampered = payload + "." + ("0" if signature[0] != "0" else "1") + signature[1:]
        assert client.get("/api/tickets", headers={"X-AIDA-User-Token": tampered}).status_code == 401
        assert client.get("/api/tickets", headers={"X-AIDA-User-Token": "garbage"}).status_code == 401


def test_cannot_remove_last_admin(api_client):
    with api_client() as client:
        response = client.post("/api/users/admin", json={"role": "approver"})
        assert response.status_code == 400 and "last active admin" in response.text
        make_user(client, "grace", "admin")
        assert client.post("/api/users/admin", json={"disabled": True}).status_code == 200
        assert client.post("/api/users/admin", json={"disabled": False}).status_code == 200


def test_password_rules_and_duplicates(api_client):
    with api_client() as client:
        short = client.post("/api/users", json={"username": "hank", "password": "short", "role": "requester"})
        assert short.status_code == 400
        bad_role = client.post("/api/users", json={"username": "hank", "password": "long-enough-1", "role": "root"})
        assert bad_role.status_code == 400
        assert client.post("/api/users", json={"username": "Hank", "password": "long-enough-1", "role": "requester"}).status_code == 200
        assert client.post("/api/users", json={"username": "hank", "password": "long-enough-1", "role": "requester"}).status_code == 409
        login(client, "HANK", "long-enough-1")  # usernames are case-insensitive


def test_passwords_are_hashed_not_stored():
    stored = users.hash_password("s3cret-password")
    assert "s3cret" not in stored and stored.startswith("pbkdf2_sha256$")
    assert users.verify_password("s3cret-password", stored)
    assert not users.verify_password("wrong", stored)
