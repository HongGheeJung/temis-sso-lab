import httpx

from temis_sso.external_idp.models import (
    AuthorizationRequest,
    ExternalFlow,
    ProviderMetadata,
)


class GoogleOidcAdapter:
    discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
    expected_issuer = "https://accounts.google.com"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        http: httpx.AsyncClient,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = http

    async def discover(self) -> ProviderMetadata:
        response = await self.http.get(self.discovery_url)
        response.raise_for_status()
        raw_json = response.json()
        
        metadata = ProviderMetadata(
            issuer=str(raw_json.get("issuer", "")),
            authorization_endpoint=str(raw_json.get("authorization_endpoint", "")),
            token_endpoint=str(raw_json.get("token_endpoint", "")),
            userinfo_endpoint=str(raw_json.get("userinfo_endpoint", "")),
            revocation_endpoint=str(raw_json.get("revocation_endpoint", "")),
            jwks_uri=str(raw_json.get("jwks_uri", ""))
        )
        
        if metadata.issuer != self.expected_issuer:
            raise ValueError("discovery issuer mismatch")
        return metadata

    def authorization_request(
        self, metadata: ProviderMetadata, flow: ExternalFlow
    ) -> AuthorizationRequest:
        return AuthorizationRequest(
            url=metadata.authorization_endpoint,
            parameters={
                "client_id": self.client_id,
                "redirect_uri": flow.redirect_uri,
                "response_type": "code",
                "scope": "openid email profile",
                "state": flow.state,
                "nonce": flow.nonce,
                "code_challenge": flow.code_challenge,
                "code_challenge_method": "S256",
            },
        )

    async def exchange_code(self, metadata: ProviderMetadata, code: str, flow: ExternalFlow) -> str:
        response = await self.http.post(
            metadata.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": flow.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code_verifier": flow.code_verifier,
            },
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        if "no-store" not in response.headers.get("Cache-Control", "").lower():
            raise ValueError("token response must be marked no-store")
        payload = response.json()
        token = payload.get("id_token")
        if not isinstance(token, str) or not token:
            raise ValueError("token response is missing id_token")
        return token
