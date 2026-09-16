import concurrent.futures
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from temis_sso.application.auth import mailbox
from temis_sso.keyring import KeyRing
from temis_sso.main import create_app
from temis_sso.tokens import RingTokenCodec, codec

client = TestClient(create_app())


def registered_login() -> dict[str, str]:
    email = f"{uuid.uuid4().hex}@mail.test"
    password = "correct horse battery"
    client.post("/auth/register", json={"email": email, "password": password})
    client.post("/auth/verify", json={"token": mailbox[(email, "verify")]})
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()


def test_key_identity_is_stable_and_jwks_is_public_only() -> None:
    second = RingTokenCodec(codec.ring)
    assert codec.kid == second.kid
    assert "d" not in client.get("/.well-known/jwks.json").json()["keys"][0]


def test_missing_key_fails_fast(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not published"):
        KeyRing(tmp_path).verification_key("missing")


def test_access_token_reaches_current_user() -> None:
    body = registered_login()
    response = client.get("/users/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert response.status_code == 200


def test_refresh_rotation_is_atomic_under_race() -> None:
    first = registered_login()

    def rotate() -> int:
        return client.post(
            "/auth/refresh", json={"refresh_token": first["refresh_token"]}
        ).status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        statuses = sorted(executor.map(lambda _: rotate(), range(2)))
    assert statuses == [200, 401]
