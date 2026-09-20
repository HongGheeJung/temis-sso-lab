import secrets
import time
from typing import Annotated
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Cookie, HTTPException, status, Depends, Query
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer
from sqlalchemy import select

from temis_sso.api.auth import issue_bundle
from temis_sso.config import settings
from temis_sso.external_idp.external_accounts import (
    ExternalIdentityLink,
    ExternalIdentityLinkRepository,
)
from temis_sso.external_idp.naver import NaverAdapter
from temis_sso.external_idp.security import FlowStore
from temis_sso.persistence import UserRepository, UserRole, session_scope


from temis_sso.api.users import current_subject

bearer_scheme = HTTPBearer(auto_error=False) 

router = APIRouter(prefix="/oauth/naver", tags=["naver-oauth"])

naver_flow_store = FlowStore(ttl_seconds=300)

async def _naver_oauth_user(session, identity) -> str:
    user_repo = UserRepository(session)
    links_repo = ExternalIdentityLinkRepository(session)    
    existing_link = await links_repo.resolve(identity.provider, identity.subject)

    if existing_link:
        return existing_link

    target_email = identity.email or f"{identity.subject}@naver.lab.invalid"
    
    if await user_repo.by_email(target_email):
        target_email = f"{identity.subject}.changed@naver.lab.invalid"

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

@router.get("/login")
async def naver_login() -> RedirectResponse:
    browser_binding = secrets.token_urlsafe(32)
    http_client = httpx.AsyncClient(timeout=5.0)
    adapter = NaverAdapter(settings.naver_client_id, settings.naver_client_secret, http_client)

    flow = naver_flow_store.issue(
        redirect_uri="http://localhost:8000/oauth/naver/callback",
        now=int(time.time()),
        browser_binding=browser_binding,
    )

    auth_request = adapter.authorization_request(flow)
    target_url = f"{auth_request.url}?{urlencode(auth_request.parameters)}"

    response = RedirectResponse(url=target_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="naver_browser_binding",
        value=browser_binding,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=300,
    )
    return response

@router.get("/callback")
async def naver_callback(state: str, code: str, naver_browser_binding: str | None = Cookie(None)) -> RedirectResponse:
    if not naver_browser_binding:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Security browser binding cookie is missing"
        )
        
    async with session_scope() as session, httpx.AsyncClient(timeout=5.0) as http_client:
        adapter = NaverAdapter(settings.naver_client_id, settings.naver_client_secret, http_client)
        
        try:
            naver_flow_store.consume(state, now=int(time.time()), browser_binding=naver_browser_binding)
        except ValueError as error:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(error))
            
        try:
            access_token = await adapter.exchange_code(code, state)
            identity = await adapter.fetch_identity(access_token)
            user_id = await _naver_oauth_user(session, identity)
            
        except ValueError as core_error:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(core_error))
        except (RuntimeError, httpx.HTTPError, KeyError) as system_error:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"OAuth callback processing failed internally: {system_error!s}"
            )

    token_bundle = await issue_bundle(user_id, audience="lab-client")
    
    query = urlencode({
        "access_token": token_bundle.access_token,
        "refresh_token": token_bundle.refresh_token,
        "token_type": token_bundle.token_type
    })
    
    redirect_url = f"http://localhost:8000/docs?{query}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)




@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def naver_revoke(
    user_id: str = Depends(current_subject),
    access_token: str = Query(..., description="철회할 네이버의 access_token")
) -> None:
    async with session_scope() as session:
        links_repo = ExternalIdentityLinkRepository(session)
        
        statement = select(ExternalIdentityLink).where(
            ExternalIdentityLink.provider == "naver",
            ExternalIdentityLink.user_id == user_id
        )
        link_record = await session.scalar(statement)
        
        if not link_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Linked Naver account identity not found for this user."
            )
            
        async with httpx.AsyncClient(timeout=5.0) as http_client:
            adapter = NaverAdapter(settings.naver_client_id, settings.naver_client_secret, http_client)
            success = await adapter.revoke(access_token)
            
            if not success:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="Fail-closed: Naver identity provider rejected the revocation request."
                )
        
        await session.delete(link_record)
        await session.flush()