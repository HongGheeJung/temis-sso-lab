import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from temis_sso.application.auth import mailbox
from temis_sso.main import create_app
from temis_sso.persistence import OneTimeToken, UserRepository, session_scope

client = TestClient(create_app())


def new_identity() -> tuple[str, str, str]:
    email = f"{uuid.uuid4().hex}@mail.test"
    password = "correct horse battery"
    response = client.post("/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201
    return email, password, mailbox[(email, "verify")]


def test_pending_user_must_verify_before_login() -> None:
    email, password, token = new_identity()
    assert (
        client.post("/auth/login", json={"email": email, "password": password}).status_code == 403
    )
    assert client.post("/auth/verify", json={"token": token}).status_code == 204
    assert client.post("/auth/verify", json={"token": token}).status_code == 400
    assert (
        client.post("/auth/login", json={"email": email, "password": password}).status_code == 200
    )


def test_password_is_hashed_and_reset_token_is_one_time() -> None:
    email, _, verify_token = new_identity()
    client.post("/auth/verify", json={"token": verify_token})
    client.post("/auth/password-reset/request", json={"email": email})
    reset = mailbox[(email, "reset")]
    payload = {"token": reset, "password": "a different safe passphrase"}
    assert client.post("/auth/password-reset/confirm", json=payload).status_code == 204
    assert client.post("/auth/password-reset/confirm", json=payload).status_code == 400


def test_three_failures_lock_account_until_expiry() -> None:
    email, password, verify_token = new_identity()
    client.post("/auth/verify", json={"token": verify_token})
    bad = {"email": email, "password": "incorrect password"}
    for _ in range(3):
        assert client.post("/auth/login", json=bad).status_code == 401
    assert (
        client.post("/auth/login", json={"email": email, "password": password}).status_code == 401
    )

    async def expire_lock() -> None:
        async with session_scope() as session:
            user = await UserRepository(session).by_email(email)
            assert user is not None
            user.locked_until = datetime.now(UTC) - timedelta(seconds=1)

    asyncio.run(expire_lock())
    assert (
        client.post("/auth/login", json={"email": email, "password": password}).status_code == 200
    )


def test_unknown_reset_request_has_same_public_response() -> None:
    response = client.post("/auth/password-reset/request", json={"email": "absent@mail.test"})
    assert response.status_code == 202
    assert response.json() == {"status": "accepted"}


@pytest.mark.asyncio
async def test_expired_verification_token_is_rejected() -> None:
    email, _, raw = new_identity()
    async with session_scope() as session:
        token = await session.scalar(
            select(OneTimeToken).where(
                OneTimeToken.user_id == (await UserRepository(session).by_email(email)).id
            )
        )
        token.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert client.post("/auth/verify", json={"token": raw}).status_code == 400
