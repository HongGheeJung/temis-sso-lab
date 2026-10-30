"""Naver OAuth routes with one-use state and verified unlink ownership."""

import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Cookie, Depends, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

from temis_sso.api.social import (
    RevokeInput,
    login_result,
    provider_tokens,
    require_owned_link,
    require_provider,
    resolve_social_user,
    social_subject,
)
from temis_sso.config import settings
from temis_sso.external_idp.naver import NaverAdapter
from temis_sso.external_idp.registry import ProviderRegistry
from temis_sso.external_idp.security import FlowStore
from temis_sso.persistence import session_scope

router = APIRouter(prefix="/oauth/naver", tags=["naver-oauth"])
naver_flow_store = FlowStore(ttl_seconds=300)


def _adapter(http: httpx.AsyncClient) -> NaverAdapter:
    registry = ProviderRegistry()
    registry.register(
        "naver",
        NaverAdapter(
            client_id=settings.naver_client_id,
            client_secret=settings.naver_client_secret,
            http=http,
        ),
    )
    return registry.get("naver")  # type: ignore[return-value]


@router.get("/login")
async def naver_login() -> RedirectResponse:
    require_provider("naver")
    binding = secrets.token_urlsafe(32)
    async with httpx.AsyncClient(timeout=5.0) as http:
        flow = naver_flow_store.issue(settings.naver_redirect_uri, int(time.time()), binding)
        auth = _adapter(http).authorization_request(flow)
    response = RedirectResponse(f"{auth.url}?{urlencode(auth.parameters)}", status_code=303)
    response.set_cookie(
        "naver_browser_binding",
        binding,
        httponly=True,
        secure=settings.oauth_cookie_secure,
        samesite="lax",
        max_age=300,
    )
    return response


@router.get("/callback")
async def naver_callback(
    state: str, code: str, naver_browser_binding: str | None = Cookie(None)
) -> JSONResponse:
    require_provider("naver")
    if not naver_browser_binding:
        raise HTTPException(400, "Security browser binding cookie is missing")
    try:
        naver_flow_store.consume(state, int(time.time()), naver_browser_binding)
        async with httpx.AsyncClient(timeout=5.0) as http, session_scope() as session:
            adapter = _adapter(http)
            access_token = await adapter.exchange_code(code, state)
            identity = await adapter.fetch_identity(access_token)
            user_id = await resolve_social_user(session, identity)
    except ValueError as error:
        raise HTTPException(401, "Invalid OAuth callback") from error
    except (httpx.HTTPError, RuntimeError, KeyError) as error:
        raise HTTPException(502, "Social login provider is unavailable") from error
    result = await login_result(user_id, "naver_browser_binding")
    provider_tokens.put("naver", user_id, access_token)
    return result


@router.post("/revoke", status_code=204)
async def naver_revoke(payload: RevokeInput, user_id: str = Depends(social_subject)) -> None:
    require_provider("naver")
    access_token = provider_tokens.get("naver", user_id)
    try:
        async with httpx.AsyncClient(timeout=5.0) as http, session_scope() as session:
            adapter = _adapter(http)
            identity = await adapter.fetch_identity(access_token)
            link = await require_owned_link(session, user_id, identity)
            if not await adapter.revoke(access_token):
                raise HTTPException(502, "Provider rejected revocation")
            await session.delete(link)
            await session.flush()
    except (ValueError, httpx.HTTPError, RuntimeError, KeyError) as error:
        raise HTTPException(502, "Provider revocation failed") from error
    provider_tokens.discard("naver", user_id)
