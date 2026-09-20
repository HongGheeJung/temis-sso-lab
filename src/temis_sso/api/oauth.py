import secrets
import time
from urllib.parse import parse_qs, urlencode

import httpx
from fastapi import APIRouter, Cookie, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from temis_sso.api.auth import TokenBundle, issue_bundle
from temis_sso.client_policy import client_by_id, require_client
from temis_sso.config import settings
from temis_sso.external_idp.callback import GoogleCallbackService, JwksCache, verify_google_id_token
from temis_sso.external_idp.external_accounts import (
    ExternalIdentityLink,
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

async def _google_oauth_user(session, identity) -> str:
    user_repo = UserRepository(session)
    links_repo = ExternalIdentityLinkRepository(session)
    existing_link = await links_repo.get(identity.provider, identity.subject)
    
    if existing_link:
        return existing_link.user_id

    target_email = identity.email or f"{identity.subject}@google.lab.invalid"
    user = await user_repo.by_email(target_email)
    
    if user is None:
        user = await user_repo.create(target_email)
        user.status = "active"
        session.add(UserRole(user_id=user.id, role="user"))
        await session.flush()
    
    session.add(ExternalIdentityLink(
        provider=identity.provider,
        subject=identity.subject,
        user_id=user.id
    ))
    await session.flush()
    
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

    browser_binding = secrets.token_urlsafe(32)

    http_client = httpx.AsyncClient(timeout=5.0)
    adapter = GoogleOidcAdapter(settings.google_client_id, settings.google_client_secret, http_client)
    metadata = await adapter.discover()    
    redirect_uri = "http://localhost:8000/oauth/google/callback"
        
    flow = flow_store.issue(
        redirect_uri=redirect_uri,
        now=int(time.time()),
        browser_binding=browser_binding
    )
 
    auth_request = adapter.authorization_request(metadata, flow)       
    target_url = f"{auth_request.url}?{urlencode(auth_request.parameters)}"       
    
    response = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)    
    response.set_cookie(
        key="idp_browser_binding",
        value=browser_binding,
        httponly=True,
        secure=False, 
        samesite="lax",
        max_age=300
    )
    return response




@router.get("/google/callback")
async def google_callback(state: str, code: str, idp_browser_binding: str | None = Cookie(None)) -> RedirectResponse:
    if not idp_browser_binding:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security browser binding cookie is missing"
        )
        
    async with session_scope() as session, httpx.AsyncClient(timeout=5.0) as http_client:
        links_repo = ExternalIdentityLinkRepository(session)
        adapter = GoogleOidcAdapter(settings.google_client_id, settings.google_client_secret, http_client)
        
        callback_service = GoogleCallbackService(
            adapter=adapter, flows=flow_store, links=links_repo,
            sessions=idp_session_store, http=http_client, jwks=jwks_cache
        )
        
        try:
            internal_session_id = await callback_service.finish_callback(
                state=state, code=code, now=int(time.time()), browser_binding=idp_browser_binding
            )
            user_id = idp_session_store.resolve(internal_session_id)
            
        except ValueError as error:
            if "not linked" not in str(error):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error))
                
            flow_data = flow_store._flows.get(state)
            if not flow_data:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid state token")
            
            metadata = await adapter.discover()
            encoded_id_token = await adapter.exchange_code(metadata, code, flow_data)
            
            identity = await verify_google_id_token(
                encoded_id_token, metadata, http_client, adapter.client_id, 
                flow_data.nonce, jwks_cache, now=int(time.time()) + 60
            )
            
            user_id = await _google_oauth_user(session, identity)
            flow_store._flows.pop(state, None)
            
        except (RuntimeError, httpx.HTTPError, KeyError) as core_error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"OAuth callback processing failed: {core_error!s}"
            )

    token_bundle = await issue_bundle(user_id, audience="lab-client")
    
    query = urlencode({
        "access_token": token_bundle.access_token,
        "refresh_token": token_bundle.refresh_token,
        "token_type": token_bundle.token_type
    })
    
    Redirect_url = f"http://localhost:8000/docs?{query}"
    return RedirectResponse(url=Redirect_url, status_code=status.HTTP_303_SEE_OTHER)