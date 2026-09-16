import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from temis_sso.persistence import OneTimeToken, UserRepository, session_scope
from temis_sso.security import hash_password, verify_password


class DuplicateEmailError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class VerificationRequiredError(Exception):
    pass


class InvalidOneTimeTokenError(Exception):
    pass


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: str
    email: str


mailbox: dict[tuple[str, str], str] = {}


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def _issue_one_time(user_id: str, email: str, purpose: str) -> None:
    raw = secrets.token_urlsafe(32)
    async with session_scope() as session:
        session.add(
            OneTimeToken(
                digest=_digest(raw),
                user_id=user_id,
                purpose=purpose,
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
    mailbox[(email, purpose)] = raw


async def register(email: str, password: str) -> AuthenticatedUser:
    try:
        async with session_scope() as session:
            user = await UserRepository(session).create(email, hash_password(password))
            identity = AuthenticatedUser(user.id, user.email)
        await _issue_one_time(identity.user_id, identity.email, "verify")
        return identity
    except IntegrityError as error:
        raise DuplicateEmailError from error


async def authenticate(email: str, password: str) -> AuthenticatedUser:
    outcome: AuthenticatedUser | None = None
    error: Exception | None = None
    async with session_scope() as session:
        user = await UserRepository(session).by_email(email)
        now = datetime.now(UTC)
        if (
            user is None
            or user.password_hash is None
            or user.locked_until
            and user.locked_until > now
        ):
            error = InvalidCredentialsError()
        elif not verify_password(user.password_hash, password):
            user.failed_logins += 1
            if user.failed_logins >= 3:
                user.locked_until = now + timedelta(minutes=5)
            error = InvalidCredentialsError()
        elif user.status == "pending":
            error = VerificationRequiredError()
        elif user.status != "active":
            error = InvalidCredentialsError()
        else:
            user.failed_logins = 0
            user.locked_until = None
            outcome = AuthenticatedUser(user.id, user.email)
    if error:
        raise error
    assert outcome is not None
    return outcome


async def consume_one_time(raw: str, purpose: str) -> str:
    async with session_scope() as session:
        token = await session.scalar(
            select(OneTimeToken)
            .where(OneTimeToken.digest == _digest(raw), OneTimeToken.purpose == purpose)
            .with_for_update()
        )
        if token is None or token.consumed_at is not None or token.expires_at <= datetime.now(UTC):
            raise InvalidOneTimeTokenError
        token.consumed_at = datetime.now(UTC)
        return token.user_id


async def verify_email(raw: str) -> None:
    user_id = await consume_one_time(raw, "verify")
    async with session_scope() as session:
        user = await UserRepository(session).by_id(user_id)
        if user is None:
            raise InvalidOneTimeTokenError
        user.status = "active"


async def request_password_reset(email: str) -> None:
    async with session_scope() as session:
        user = await UserRepository(session).by_email(email)
        identity = None if user is None else AuthenticatedUser(user.id, user.email)
    if identity:
        await _issue_one_time(identity.user_id, identity.email, "reset")


async def reset_password(raw: str, password: str) -> None:
    user_id = await consume_one_time(raw, "reset")
    async with session_scope() as session:
        user = await UserRepository(session).by_id(user_id)
        if user is None:
            raise InvalidOneTimeTokenError
        user.password_hash = hash_password(password)
        user.failed_logins = 0
        user.locked_until = None
