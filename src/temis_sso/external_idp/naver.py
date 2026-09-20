from typing import Any

import httpx

from temis_sso.external_idp.models import AuthorizationRequest, ExternalFlow, ExternalIdentity


class NaverAdapter:
    authorize_url = "https://nid.naver.com/oauth2.0/authorize"
    token_url = "https://nid.naver.com/oauth2.0/token"
    profile_url = "https://openapi.naver.com/v1/nid/me"
    revoke_url = "https://nid.naver.com/oauth2.0/revoke"


    def __init__(self, client_id: str, client_secret: str, http: httpx.AsyncClient) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = http
        
    def authorization_request(self, flow: ExternalFlow) -> AuthorizationRequest:
        return AuthorizationRequest(
            url=self.authorize_url,
            parameters={
                "client_id": self.client_id,
                "redirect_uri": flow.redirect_uri,
                "response_type": "code",
                "scope": "email profile",
                "state": flow.state,
            },
        )

    async def exchange_code(self, code: str, state: str) -> str:
        response = await self.http.post(
            self.token_url,
            data={
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": code,
                "state": state,
            },
            headers={"Accept": "application/json"}
        )
        response.raise_for_status()

        payload = response.json()
        if "error" in payload:
            raise ValueError(f"Naver token endpoint rejected: {payload.get('error')}")

        token = payload.get("access_token")
        if not token:
            raise ValueError("Token response is missing access_token")
        return str(token)

    async def fetch_identity(self, access_token: str) -> ExternalIdentity:
        response = await self.http.get(
            self.profile_url,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()

        data = response.json()
        resultcode = data.get("resultcode")
        
        if resultcode != "00":
            raise ValueError(f"provider rejected: resultcode={resultcode}")

        naver_response = data.get("response", {})
        subject = naver_response.get("id")
        
        if not subject or not str(subject).strip():
            raise ValueError("response.id")

        email = naver_response.get("email")
        
        return ExternalIdentity(
            provider="naver",
            subject=str(subject),
            email=email if isinstance(email, str) else None,
            email_verified=False
        )

    async def revoke(self, access_token: str) -> bool:       
        response = await self.http.post(
            self.revoke_url,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "token": access_token,
                "token_type_hint": "access_token",
            }
        )
        response.raise_for_status()
        return response.status_code == 200