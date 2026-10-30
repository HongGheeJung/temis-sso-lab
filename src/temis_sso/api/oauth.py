import secrets
import time
from urllib.parse import parse_qs, urlencode

import httpx
import jwt
from fastapi import APIRouter, Cookie, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from temis_sso.api.auth import TokenBundle, issue_bundle
from temis_sso.api.social import login_result, require_provider, resolve_social_user
from temis_sso.client_policy import client_by_id, require_client
from temis_sso.config import settings
from temis_sso.external_idp.callback import GoogleCallbackService, JwksCache
from temis_sso.external_idp.external_accounts import (
    ExternalIdentityLinkRepository,
)
from temis_sso.external_idp.google import GoogleOidcAdapter
from temis_sso.external_idp.security import FlowStore
from temis_sso.external_idp.sessions import SessionStore
from temis_sso.fake_provider import FakeOAuthProvider
from temis_sso.oauth_state import OAuthTransaction, pkce_challenge, state_store
from temis_sso.persistence import UserRepository, UserRole, session_scope

router = APIRouter(prefix="/oauth", tags=["oauth"])
provider = FakeOAuthProvider(state_store)


flow_store = FlowStore(ttl_seconds=300)
jwks_cache = JwksCache()
idp_session_store = SessionStore()


class TokenRequest(BaseModel):
    grant_type: str
    client_id: str
    redirect_uri: str
    code: str
    code_verifier: str = Field(min_length=43, max_length=128)


async def _oauth_user(provider_subject: str, default_role: str) -> str:
    email = f"{provider_subject}@oauth.lab.invalid"
    async with session_scope() as session:
        repository = UserRepository(session)
        user = await repository.by_email(email)
        if user is None:
            user = await repository.create(email)
            user.status = "active"
            session.add(UserRole(user_id=user.id, role=default_role))
        return user.id


@router.get("/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    state: str = Query(min_length=16, max_length=256),
    response_type: str = "code",
    code_challenge: str = Query(min_length=43, max_length=128),
    code_challenge_method: str = "S256",
) -> RedirectResponse:
    if response_type != "code" or code_challenge_method != "S256":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "authorization code with S256 required")
    try:
        require_client(client_id, redirect_uri)
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    provider_state = await state_store.begin(
        OAuthTransaction(client_id, redirect_uri, code_challenge, "lab-provider", state)
    )
    return RedirectResponse(
        f"/oauth/fake-provider/authorize?{urlencode({'state': provider_state})}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/fake-provider/authorize")
async def fake_authorize(state: str, account: str = "learner") -> RedirectResponse:
    try:
        provider_code = await provider.authorize(state, account)
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    query = urlencode({"state": state, "code": provider_code})
    return RedirectResponse(
        f"/oauth/provider/callback?{query}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/provider/callback")
async def provider_callback(state: str, code: str) -> RedirectResponse:
    transaction = await state_store.consume_oauth(state)
    provider_result = await provider.exchange(code)
    if (
        transaction is None
        or provider_result is None
        or provider_result["state"] != state
        or provider_result["provider"] != transaction.provider
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid oauth transaction")
    policy = require_client(transaction.client_id, transaction.redirect_uri)
    user_id = await _oauth_user(provider_result["provider_subject"], policy.default_role)
    auth_code = await state_store.put(
        "authorization-code",
        {
            "user_id": user_id,
            "client_id": policy.client_id,
            "redirect_uri": transaction.redirect_uri,
            "code_challenge": transaction.code_challenge,
        },
        60,
    )
    query = urlencode({"code": auth_code, "state": transaction.client_state})
    return RedirectResponse(
        f"{transaction.redirect_uri}?{query}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/token", response_model=TokenBundle)
async def token(request: Request, response: Response) -> TokenBundle:

    form = parse_qs((await request.body()).decode(), strict_parsing=True)
    try:
        payload = TokenRequest(**{key: values[0] for key, values in form.items()})
    except (ValueError, KeyError) as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid token request") from error
    grant = await state_store.take("authorization-code", payload.code)
    valid = (
        payload.grant_type == "authorization_code"
        and grant is not None
        and grant["client_id"] == payload.client_id
        and grant["redirect_uri"] == payload.redirect_uri
        and pkce_challenge(payload.code_verifier) == grant["code_challenge"]
    )
    if not valid or grant is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid authorization code")
    policy = client_by_id(payload.client_id)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return await issue_bundle(grant["user_id"], policy.audience)


@router.get("/google/login")
async def google_login() -> RedirectResponse:
    require_provider("google")
    binding = secrets.token_urlsafe(32)
    try:
        async with httpx.AsyncClient(timeout=5.0) as http:
            adapter = GoogleOidcAdapter(
                settings.google_client_id, settings.google_client_secret, http
            )
            metadata = await adapter.discover()
            flow = flow_store.issue(settings.google_redirect_uri, int(time.time()), binding)
            auth = adapter.authorization_request(metadata, flow)
    except (ValueError, httpx.HTTPError) as error:
        raise HTTPException(502, "Social login provider is unavailable") from error
    response = RedirectResponse(f"{auth.url}?{urlencode(auth.parameters)}", status_code=303)
    response.set_cookie(
        "idp_browser_binding",
        binding,
        httponly=True,
        secure=settings.oauth_cookie_secure,
        samesite="lax",
        max_age=300,
    )
    return response


@router.get("/google/callback")
async def google_callback(
    state: str, code: str, idp_browser_binding: str | None = Cookie(None)
) -> JSONResponse:
    require_provider("google")
    if not idp_browser_binding:
        raise HTTPException(400, "Security browser binding cookie is missing")
    try:
        async with session_scope() as session, httpx.AsyncClient(timeout=5.0) as http:
            service = GoogleCallbackService(
                adapter=GoogleOidcAdapter(
                    settings.google_client_id, settings.google_client_secret, http
                ),
                flows=flow_store,
                links=ExternalIdentityLinkRepository(session),
                sessions=idp_session_store,
                http=http,
                jwks=jwks_cache,
            )
            identity = await service.authenticate_identity(
                state, code, int(time.time()), idp_browser_binding
            )
            user_id = await resolve_social_user(session, identity)
    except (ValueError, jwt.PyJWTError) as error:
        raise HTTPException(401, "Invalid OAuth callback") from error
    except (httpx.HTTPError, RuntimeError, KeyError) as error:
        raise HTTPException(502, "Social login provider is unavailable") from error
    return await login_result(user_id, "idp_browser_binding")
