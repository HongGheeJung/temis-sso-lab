import uuid

from fastapi.testclient import TestClient

from temis_sso.application.auth import mailbox
from temis_sso.main import create_app
from temis_sso.tokens import codec

client = TestClient(create_app())


def test_users_me_uses_active_database_identity() -> None:
    email = f"{uuid.uuid4().hex}@mail.test"
    password = "correct horse battery"
    created = client.post("/auth/register", json={"email": email, "password": password}).json()
    client.post("/auth/verify", json={"token": mailbox[(email, "verify")]})
    token = client.post("/auth/login", json={"email": email, "password": password}).json()[
        "access_token"
    ]
    assert client.get("/users/me", headers={"Authorization": f"Bearer {token}"}).json() == {
        "user_id": created["user_id"]
    }


def test_missing_invalid_and_deleted_identities_are_rejected() -> None:
    assert client.get("/users/me").status_code == 401
    assert client.get("/users/me", headers={"Authorization": "Bearer invalid"}).status_code == 401
    unknown = codec.issue_access("deleted-user")
    assert (
        client.get("/users/me", headers={"Authorization": f"Bearer {unknown}"}).status_code == 404
    )
