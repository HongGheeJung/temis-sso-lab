from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from temis_sso.persistence import AuditLog, RefreshGrant, User, UserRole, session_scope


class AdminRequiredError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class SelfActionError(Exception):
    pass


def redact(details: dict[str, Any]) -> dict[str, Any]:
    hidden = ("password", "token", "secret", "authorization")
    sanitized: dict[str, Any] = {}
    for key, value in details.items():
        sensitive_key = any(word in key.lower() for word in hidden)
        sensitive_value = isinstance(value, str) and any(
            marker in value.lower() for marker in ("bearer ", "token=", "password=")
        )
        sanitized[key] = "[REDACTED]" if sensitive_key or sensitive_value else value
    return sanitized


async def _assert_admin(session: AsyncSession, actor_id: str) -> User:
    actor = await session.get(User, actor_id)
    role = await session.get(UserRole, {"user_id": actor_id, "role": "admin"})
    if actor is None or actor.status != "active" or role is None:
        raise AdminRequiredError
    return actor


async def _audit(
    session: AsyncSession,
    actor_id: str,
    target_id: str,
    action: str,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditLog(
            actor_id=actor_id, target_id=target_id, action=action, details=redact(details or {})
        )
    )


async def _invalidate_authorization(session: AsyncSession, target: User) -> None:
    target.authz_version += 1
    await session.execute(
        update(RefreshGrant)
        .where(RefreshGrant.user_id == target.id, RefreshGrant.consumed_at.is_(None))
        .values(consumed_at=datetime.now(UTC))
    )


async def bootstrap_admin(user_id: str) -> None:
    async with session_scope() as session:
        user = await session.get(User, user_id)
        if user is None:
            raise UserNotFoundError
        user.status = "active"
        await session.merge(UserRole(user_id=user_id, role="admin"))
        await _invalidate_authorization(session, user)


async def approve_user(actor_id: str, target_id: str, fail_for_test: bool = False) -> User:
    async with session_scope() as session:
        await _assert_admin(session, actor_id)
        target = await session.get(User, target_id, with_for_update=True)
        if target is None:
            raise UserNotFoundError
        target.status = "active"
        await session.execute(
            delete(UserRole).where(UserRole.user_id == target_id, UserRole.role == "pending")
        )
        await session.merge(UserRole(user_id=target_id, role="user"))
        await _invalidate_authorization(session, target)
        await _audit(session, actor_id, target_id, "user.approved")
        if fail_for_test:
            raise RuntimeError("simulated audit boundary failure")
        await session.flush()
        return target


async def suspend_user(actor_id: str, target_id: str, reason: str) -> User:
    if actor_id == target_id:
        raise SelfActionError
    async with session_scope() as session:
        await _assert_admin(session, actor_id)
        target = await session.get(User, target_id, with_for_update=True)
        if target is None:
            raise UserNotFoundError
        target.status = "suspended"
        await _invalidate_authorization(session, target)
        await _audit(session, actor_id, target_id, "user.suspended", {"reason": reason})
        return target


async def change_role(actor_id: str, target_id: str, role: str, grant: bool) -> None:
    if actor_id == target_id and role == "admin" and not grant:
        raise SelfActionError
    async with session_scope() as session:
        await _assert_admin(session, actor_id)
        target = await session.get(User, target_id, with_for_update=True)
        if target is None:
            raise UserNotFoundError
        if grant:
            await session.merge(UserRole(user_id=target_id, role=role))
            action = "role.granted"
        else:
            await session.execute(
                delete(UserRole).where(UserRole.user_id == target_id, UserRole.role == role)
            )
            action = "role.revoked"
        await _invalidate_authorization(session, target)
        await _audit(session, actor_id, target_id, action, {"role": role})


async def revoke_sessions(actor_id: str, target_id: str) -> None:
    if actor_id == target_id:
        raise SelfActionError
    async with session_scope() as session:
        await _assert_admin(session, actor_id)
        target = await session.get(User, target_id, with_for_update=True)
        if target is None:
            raise UserNotFoundError
        await _invalidate_authorization(session, target)
        await _audit(session, actor_id, target_id, "sessions.revoked")


async def require_current_admin(user_id: str) -> None:
    async with session_scope() as session:
        await _assert_admin(session, user_id)
