import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from temis_sso.keyring import KeyRing
from temis_sso.persistence import RefreshGrant, User

ISSUER = "https://auth.lab.invalid"
AUDIENCE = "temis-lab"
ROLE_CLAIM = "https://temis.lab/roles"


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class RingTokenCodec:
    def __init__(self, ring: KeyRing) -> None:
        self.ring = ring

    @property
    def kid(self) -> str:
        return self.ring.active_kid()

    def issue_access(
        self,
        user_id: str,
        roles: list[str] | None = None,
        audience: str = AUDIENCE,
        *,
        client_id: str = "temis-web",
        scopes: list[str] | None = None,
        authz_version: int = 1,
    ) -> str:
        now = datetime.now(UTC)
        return self.ring.sign_claims(
            {
                "iss": ISSUER,
                "aud": audience,
                "sub": user_id,
                "azp": client_id,
                "scope": " ".join(scopes or ["profile:read"]),
                ROLE_CLAIM: roles or [],
                "authz_version": authz_version,
                "auth_time": int(now.timestamp()),
                "iat": now,
                "exp": now + timedelta(minutes=10),
            }
        )

    def verify_access(self, token: str, audience: str = AUDIENCE) -> dict[str, object]:
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if header.get("alg") != "RS256" or not isinstance(kid, str):
                raise jwt.InvalidTokenError("RS256 kid required")
            return cast(
                dict[str, object],
                jwt.decode(
                    token,
                    self.ring.verification_key(kid),
                    algorithms=["RS256"],
                    issuer=ISSUER,
                    audience=audience,
                    options={"require": ["iss", "aud", "sub", "exp"]},
                ),
            )
        except ValueError as error:
            raise jwt.InvalidTokenError("signing key is retired") from error

    def jwk(self) -> dict[str, str]:
        active = self.kid
        return next(key for key in self.ring.jwks()["keys"] if key["kid"] == active)

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return self.ring.jwks()


def _load_codec(root: Path = Path("var/keyring")) -> RingTokenCodec:
    ring = KeyRing(root)
    if not ring.jwks()["keys"]:
        first = ring.publish()
        ring.activate(first)
    return RingTokenCodec(ring)


codec = _load_codec()


async def issue_refresh(session: AsyncSession, user_id: str, audience: str = AUDIENCE) -> str:
    raw = secrets.token_urlsafe(48)
    session.add(
        RefreshGrant(
            digest=token_digest(raw),
            user_id=user_id,
            audience=audience,
            expires_at=datetime.now(UTC) + timedelta(days=14),
        )
    )
    await session.flush()
    return raw


async def rotate_refresh(session: AsyncSession, raw: str) -> tuple[str, str, str] | None:
    result = await session.execute(
        update(RefreshGrant)
        .where(
            RefreshGrant.digest == token_digest(raw),
            RefreshGrant.consumed_at.is_(None),
            RefreshGrant.expires_at > datetime.now(UTC),
            RefreshGrant.user_id.in_(select(User.id).where(User.status == "active")),
        )
        .values(consumed_at=datetime.now(UTC))
        .returning(RefreshGrant.user_id, RefreshGrant.audience)
    )
    row = result.one_or_none()
    if row is None:
        return None
    user_id, audience = row
    return user_id, audience, await issue_refresh(session, user_id, audience)


async def revoke_refresh(session: AsyncSession, raw: str) -> bool:
    result = await session.execute(
        update(RefreshGrant)
        .where(RefreshGrant.digest == token_digest(raw), RefreshGrant.consumed_at.is_(None))
        .values(consumed_at=datetime.now(UTC))
    )
    return bool(getattr(result, "rowcount", 0))
