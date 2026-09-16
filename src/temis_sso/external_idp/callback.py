import re
from typing import Any

import httpx
import jwt
from jwt.exceptions import InvalidAudienceError, InvalidIssuerError, InvalidTokenError

from temis_sso.external_idp.external_accounts import ExternalIdentityLinkRepository
from temis_sso.external_idp.google import GoogleOidcAdapter
from temis_sso.external_idp.models import ExternalIdentity, ProviderMetadata
from temis_sso.external_idp.security import FlowStore
from temis_sso.external_idp.sessions import SessionStore


class JwksCache:
    def __init__(self) -> None:
        self._entries: dict[str, tuple[int, list[dict[str, Any]]]] = {}

    async def _refresh(
        self, metadata: ProviderMetadata, http: httpx.AsyncClient, now: int
    ) -> list[dict[str, Any]]:
        response = await http.get(metadata.jwks_uri)
        response.raise_for_status()
        keys = [item for item in response.json().get("keys", []) if isinstance(item, dict)]
        match = re.search(r"(?:^|,)\s*max-age=(\d+)", response.headers.get("Cache-Control", ""))
        ttl = int(match.group(1)) if match else 0
        self._entries[metadata.jwks_uri] = (now + ttl, keys)
        return keys

    async def key(
        self,
        metadata: ProviderMetadata,
        http: httpx.AsyncClient,
        kid: str,
        now: int,
    ) -> dict[str, Any]:
        entry = self._entries.get(metadata.jwks_uri)
        cache_is_fresh = entry is not None and now < entry[0]
        if entry is not None and cache_is_fresh:
            keys = entry[1]
        else:
            keys = await self._refresh(metadata, http, now)
        key = next((item for item in keys if item.get("kid") == kid), None)
        if key is None and cache_is_fresh:
            keys = await self._refresh(metadata, http, now)
            key = next((item for item in keys if item.get("kid") == kid), None)
        if key is None:
            raise ValueError("ID token signing key is unknown")
        return key


async def verify_google_id_token(
    encoded: str,
    metadata: ProviderMetadata,
    http: httpx.AsyncClient,
    audience: str,
    expected_nonce: str,
    cache: JwksCache,
    now: int,
) -> ExternalIdentity:
    header = jwt.get_unverified_header(encoded)
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ValueError("ID token algorithm or kid is invalid")
    jwk = await cache.key(metadata, http, header["kid"], now)
    try:
        claims: dict[str, Any] = jwt.decode(
            encoded,
            jwt.PyJWK.from_dict(jwk).key,
            algorithms=["RS256"],
            audience=audience,
            issuer=metadata.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )
    except InvalidIssuerError as error:
        raise ValueError("ID token issuer mismatch") from error
    except InvalidAudienceError as error:
        raise ValueError("ID token audience mismatch") from error
    except InvalidTokenError as error:
        raise ValueError("invalid ID token") from error
    if claims.get("nonce") != expected_nonce:
        raise ValueError("ID token nonce mismatch")
    if isinstance(claims.get("aud"), list) and claims.get("azp") != audience:
        raise ValueError("ID token authorized party mismatch")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("ID token subject is missing")
    email = claims.get("email")
    return ExternalIdentity(
        "google",
        subject,
        email if isinstance(email, str) else None,
        claims.get("email_verified") is True,
    )


class GoogleCallbackService:
    def __init__(
        self,
        adapter: GoogleOidcAdapter,
        flows: FlowStore,
        links: ExternalIdentityLinkRepository,
        sessions: SessionStore,
        http: httpx.AsyncClient,
        jwks: JwksCache,
    ) -> None:
        self.adapter = adapter
        self.flows = flows
        self.links = links
        self.sessions = sessions
        self.http = http
        self.jwks = jwks

    async def finish_callback(self, state: str, code: str, now: int, browser_binding: str) -> str:
        flow = self.flows.consume(state, now, browser_binding)
        metadata = await self.adapter.discover()
        encoded = await self.adapter.exchange_code(metadata, code, flow)
        identity = await verify_google_id_token(
            encoded,
            metadata,
            self.http,
            self.adapter.client_id,
            flow.nonce,
            self.jwks,
            now,
        )
        user_id = await self.links.resolve(identity.provider, identity.subject)
        if user_id is None:
            raise ValueError("external identity is not linked")
        return self.sessions.issue(user_id)

    async def revoke(self, metadata: ProviderMetadata, provider_token: str) -> bool:
        response = await self.http.post(
            metadata.revocation_endpoint, data={"token": provider_token}
        )
        return response.is_success
