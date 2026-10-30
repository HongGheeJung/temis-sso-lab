"""Shared social account mapping and safe lab callback responses."""

import secrets

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from temis_sso.api.auth import issue_bundle
from temis_sso.config import settings
from temis_sso.external_idp.external_accounts import (
    ExternalIdentityLink,
    ExternalIdentityLinkRepository,
)
from temis_sso.external_idp.models import ExternalIdentity
from temis_sso.persistence import User, UserRepository, UserRole


class RevokeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_token: str = Field(min_length=1, max_length=8192, repr=False)


def require_provider(provider: str) -> None:
    client_id = getattr(
        settings, "kakao_rest_api_key" if provider == "kakao" else f"{provider}_client_id"
    )
    secret = getattr(settings, f"{provider}_client_secret")
    if not client_id or (provider != "kakao" and not secret):
        raise HTTPException(503, "Social login provider is not configured")


async def resolve_social_user(session: AsyncSession, identity: ExternalIdentity) -> str:
    links = ExternalIdentityLinkRepository(session)
    existing = await links.resolve(identity.provider, identity.subject)
    if existing:
        user = await session.get(User, existing)
        if user is None or user.status != "active":
            raise HTTPException(401, "Account is not active")
        return existing
    users = UserRepository(session)
    # Email attributes never authorize merging an existing local account.
    email = identity.email
    if not email or await users.by_email(email):
        email = f"{secrets.token_hex(24)}@{identity.provider}.lab.invalid"
    user = await users.create(email)
    user.status = "active"
    session.add(UserRole(user_id=user.id, role="user"))
    session.add(
        ExternalIdentityLink(provider=identity.provider, subject=identity.subject, user_id=user.id)
    )
    await session.flush()
    return user.id


async def require_owned_link(
    session: AsyncSession, user_id: str, identity: ExternalIdentity
) -> ExternalIdentityLink:
    link = await session.scalar(
        select(ExternalIdentityLink)
        .where(
            ExternalIdentityLink.provider == identity.provider,
            ExternalIdentityLink.subject == identity.subject,
            ExternalIdentityLink.user_id == user_id,
        )
        .with_for_update()
    )
    if link is None:
        raise HTTPException(403, "Provider token does not belong to your linked account")
    return link


async def login_result(user_id: str, cookie_name: str) -> JSONResponse:
    bundle = await issue_bundle(user_id, audience="lab-client")
    response = JSONResponse(
        bundle.model_dump(),
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
        },
    )
    response.delete_cookie(
        cookie_name, secure=settings.oauth_cookie_secure, httponly=True, samesite="lax"
    )
    return response
