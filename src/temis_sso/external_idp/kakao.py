from typing import Any

import httpx
import jwt

from temis_sso.external_idp.models import (
    AuthorizationRequest,
    ExternalFlow,
    ExternalIdentity,
)


class KakaoAdapter:
    authorization_endpoint = "https://kauth.kakao.com/oauth/authorize"
    token_endpoint = "https://kauth.kakao.com/oauth/token"
    profile_endpoint = "https://kapi.kakao.com/v2/user/me"
    logout_endpoint = "https://kapi.kakao.com/v1/user/logout"
    unlink_endpoint = "https://kapi.kakao.com/v1/user/unlink"

    def __init__(self, client_id: str, http: httpx.AsyncClient, client_secret: str | None = None) -> None:
        self.client_id = client_id
        self.http = http
        self.client_secret = client_secret

    def authorization_request(self, flow: ExternalFlow) -> AuthorizationRequest:
        return AuthorizationRequest(
            self.authorization_endpoint,
            {
                "client_id": self.client_id,
                "redirect_uri": flow.redirect_uri,
                "response_type": "code",
                "state": flow.state,
                "code_challenge": flow.code_challenge,
                "code_challenge_method": "S256",
            },
        )


    async def exchange_code(self, code: str, flow: ExternalFlow) -> str:
        
        data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "redirect_uri": flow.redirect_uri,
            "code": code,
            "code_verifier": flow.code_verifier,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret

        response = await self.http.post(
            self.token_endpoint, 
            data=data,
            headers={"Accept": "application/json"}  # 추가해도 무방하며 통일감을 줍니다.
        )
        response.raise_for_status()

        payload = response.json()
        if "error" in payload:
            raise ValueError(f"Kakao token endpoint rejected: {payload.get('error')}")

        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise ValueError("Kakao token response is missing access_token")
            
        return token

    async def fetch_identity(self, access_token: str) -> ExternalIdentity:
        response = await self.http.get(
            self.profile_endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        raw_subject = payload.get("id")
        if not isinstance(raw_subject, int) or isinstance(raw_subject, bool):
            raise ValueError("Kakao REST id is missing")  # noqa: TRY004
        account = payload.get("kakao_account")
        account = account if isinstance(account, dict) else {}
        usable_email = (
            account.get("email_needs_agreement") is False
            and account.get("is_email_valid") is True
            and account.get("is_email_verified") is True
            and isinstance(account.get("email"), str)
        )
        email = account.get("email") if usable_email else None
        return ExternalIdentity(
            provider="kakao",
            subject=str(raw_subject),
            email=email if isinstance(email, str) else None,
            email_verified=usable_email,
        )

    async def _account_operation(self, endpoint: str, access_token: str) -> bool:
        """로그아웃 및 연동 해제를 처리하는 공통 비동기 유틸리티 함수입니다."""
        response = await self.http.post(
            endpoint, headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
        return response.status_code == 200
    
    async def logout(self, access_token: str) -> bool:
        """카카오 로그아웃 엔드포인트를 호출하여 세션을 유지한 채 토큰만 만료합니다."""
        return await self._account_operation(self.logout_endpoint, access_token)

    async def unlink(self, access_token: str) -> bool:
        """카카오 연동 해제 엔드포인트를 호출하여 사용자 공급자 연결을 완전히 철회합니다."""
        return await self._account_operation(self.unlink_endpoint, access_token)




class KakaoOidcAdapter:
    issuer = "https://kauth.kakao.com"
    jwks_uri = "https://kauth.kakao.com/.well-known/jwks.json"

    def __init__(self, client_id: str, http: httpx.AsyncClient) -> None:
        self.client_id = client_id
        self.http = http

    async def verify(self, encoded_id_token: str, expected_nonce: str) -> ExternalIdentity:
        unverified_header = jwt.get_unverified_header(encoded_id_token)
        kid = unverified_header.get("kid")
        if not kid:
            raise ValueError("invalid")

        jwks_res = await self.http.get(self.jwks_uri)
        jwks_res.raise_for_status()
        jwks_data = jwks_res.json()
        keys = jwks_data.get("keys", [])

        target_jwk = next((k for k in keys if k.get("kid") == kid), None)
        if not target_jwk:
            raise ValueError("invalid")

        public_key = jwt.PyJWK.from_dict(target_jwk).key

        try:
            claims = jwt.decode(
                encoded_id_token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                options={"verify_signature": True, "require": ["exp", "iat", "iss", "aud", "sub"]}
            )
        except jwt.PyJWTError as e:
            raise ValueError("invalid") from e

        if claims.get("iss") != self.issuer:
            raise ValueError("invalid")

        if claims.get("nonce") != expected_nonce:
            raise ValueError("nonce")

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ValueError("invalid")

        email = claims.get("email")
        return ExternalIdentity(
            provider="kakao",
            subject=subject,
            email=email if isinstance(email, str) else None,
            email_verified=claims.get("email_verified") is True
        )