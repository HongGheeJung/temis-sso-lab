import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from temis_sso.application.admin import approve_user, bootstrap_admin, redact
from temis_sso.application.auth import mailbox
from temis_sso.main import create_app
from temis_sso.persistence import AuditLog, UserRepository, UserRole, session_scope

client = TestClient(create_app())
password = "correct horse battery"


def register(active: bool = False) -> tuple[str, str]:
    email = f"{uuid.uuid4().hex}@mail.test"
    response = client.post("/auth/register", json={"email": email, "password": password})
    user_id = response.json()["user_id"]
    if active:
        client.post("/auth/verify", json={"token": mailbox[(email, "verify")]})
    return user_id, email


def login(email: str) -> dict[str, str]:
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()


def new_admin() -> tuple[str, dict[str, str], dict[str, str]]:
    user_id, email = register()
    asyncio.run(bootstrap_admin(user_id))
    bundle = login(email)
    return user_id, bundle, {"Authorization": f"Bearer {bundle['access_token']}"}


def test_approval_role_and_audit_are_atomic() -> None:
    _, _, headers = new_admin()
    target_id, _ = register()
    assert client.post(f"/admin/users/{target_id}/approve", headers=headers).status_code == 200

    async def verify() -> None:
        async with session_scope() as session:
            assert (await UserRepository(session).by_id(target_id)).status == "active"
            assert await session.get(UserRole, {"user_id": target_id, "role": "user"})
            assert await session.scalar(
                select(AuditLog).where(
                    AuditLog.target_id == target_id, AuditLog.action == "user.approved"
                )
            )

    asyncio.run(verify())


def test_suspension_rejects_stale_access_and_refresh_sessions() -> None:
    _, _, headers = new_admin()
    target_id, email = register(active=True)
    bundle = login(email)
    response = client.post(
        f"/admin/users/{target_id}/suspend", json={"reason": "access review"}, headers=headers
    )
    assert response.status_code == 200
    assert (
        client.get(
            "/users/me", headers={"Authorization": f"Bearer {bundle['access_token']}"}
        ).status_code
        == 403
    )
    assert (
        client.post("/auth/refresh", json={"refresh_token": bundle["refresh_token"]}).status_code
        == 401
    )


def test_self_actions_are_blocked() -> None:
    admin_id, _, headers = new_admin()
    assert (
        client.post(
            f"/admin/users/{admin_id}/suspend", json={"reason": "self test"}, headers=headers
        ).status_code
        == 409
    )
    assert client.delete(f"/admin/users/{admin_id}/roles/admin", headers=headers).status_code == 409
    assert (
        client.post(f"/admin/users/{admin_id}/revoke-sessions", headers=headers).status_code == 409
    )


def test_stale_admin_jwt_is_rejected_after_db_role_revocation() -> None:
    first_id, _, first_headers = new_admin()
    _, _, second_headers = new_admin()
    assert (
        client.delete(f"/admin/users/{first_id}/roles/admin", headers=second_headers).status_code
        == 204
    )
    target_id, _ = register()
    assert (
        client.post(f"/admin/users/{target_id}/approve", headers=first_headers).status_code == 403
    )


@pytest.mark.asyncio
async def test_transaction_rolls_back_on_failure() -> None:
    actor_id, actor_email = register()
    await bootstrap_admin(actor_id)
    assert login(actor_email)["access_token"]
    target_id, _ = register()
    with pytest.raises(RuntimeError, match="simulated"):
        await approve_user(actor_id, target_id, fail_for_test=True)
    async with session_scope() as session:
        assert (await UserRepository(session).by_id(target_id)).status == "pending"
        assert (
            await session.scalar(
                select(AuditLog).where(
                    AuditLog.target_id == target_id, AuditLog.action == "user.approved"
                )
            )
            is None
        )


def test_audit_redaction_removes_secret_material() -> None:
    assert redact(
        {"access_token": "opaque", "reason": "Bearer sensitive-value", "safe": "role change"}
    ) == {"access_token": "[REDACTED]", "reason": "[REDACTED]", "safe": "role change"}
