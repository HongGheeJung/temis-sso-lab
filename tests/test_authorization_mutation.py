import uuid

import pytest
from fastapi.testclient import TestClient

from temis_sso.api.auth import issue_bundle
from temis_sso.application.admin import bootstrap_admin, change_role, suspend_user
from temis_sso.config import settings
from temis_sso.main import create_app
from temis_sso.persistence import UserRepository, UserRole, session_scope


async def active_user(role: str = "user") -> str:
    async with session_scope() as session:
        user = await UserRepository(session).create(f"{uuid.uuid4().hex}@mail.test")
        user.status = "active"
        session.add(UserRole(user_id=user.id, role=role))
        return user.id


@pytest.mark.asyncio
async def test_role_change_bumps_version_and_revokes_refresh() -> None:
    actor = await active_user()
    await bootstrap_admin(actor)
    target = await active_user()
    bundle = await issue_bundle(target)
    async with session_scope() as session:
        before = (await UserRepository(session).by_id(target)).authz_version
    await change_role(actor, target, "reviewer", True)
    async with session_scope() as session:
        after = (await UserRepository(session).by_id(target)).authz_version
    assert after == before + 1
    response = TestClient(create_app()).post(
        "/auth/refresh", json={"refresh_token": bundle.refresh_token}
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_status_endpoint_rejects_stale_or_suspended_subject() -> None:
    actor = await active_user()
    await bootstrap_admin(actor)
    target = await active_user()
    bundle = await issue_bundle(target)
    version = int(codec_claim(bundle.access_token, "authz_version"))
    client = TestClient(create_app())
    headers = {"X-Status-Key": settings.status_service_key}
    assert (
        client.post(
            "/auth/status", json={"user_id": target, "authz_version": version}, headers=headers
        ).json()["active"]
        is True
    )
    await suspend_user(actor, target, "security review")
    assert (
        client.post(
            "/auth/status", json={"user_id": target, "authz_version": version}, headers=headers
        ).json()["active"]
        is False
    )
    assert (
        client.post("/auth/status", json={"user_id": target, "authz_version": version}).status_code
        == 401
    )


def codec_claim(token: str, name: str) -> object:
    from temis_sso.tokens import codec

    return codec.verify_access(token)[name]
