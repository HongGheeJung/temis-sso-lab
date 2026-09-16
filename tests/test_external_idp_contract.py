import asyncio
import hashlib
from base64 import urlsafe_b64encode
from typing import Any, cast

import httpx
import pytest

from temis_sso.external_idp.google import GoogleOidcAdapter
from temis_sso.external_idp.models import AuthorizationRequest, ProviderMetadata
from temis_sso.external_idp.security import FlowStore


def test_provider_metadata_rejects_non_https_endpoints() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        ProviderMetadata(
            issuer="https://accounts.google.test",
            authorization_endpoint="http://accounts.google.test/auth",
            token_endpoint="https://accounts.google.test/token",
            userinfo_endpoint="https://accounts.google.test/userinfo",
            revocation_endpoint="https://accounts.google.test/revoke",
            jwks_uri="https://accounts.google.test/jwks",
        )


def test_flow_store_consumes_state_once_and_checks_ttl() -> None:
    store = FlowStore(ttl_seconds=60)
    flow = store.issue(
        "https://client.lab.invalid/callback", now=100, browser_binding="browser-binding-123"
    )
    assert store.consume(flow.state, now=159, browser_binding="browser-binding-123") == flow
    with pytest.raises(ValueError, match="unknown or already used"):
        store.consume(flow.state, now=159, browser_binding="browser-binding-123")
    expired = store.issue(
        "https://client.lab.invalid/callback", now=200, browser_binding="browser-binding-123"
    )
    with pytest.raises(ValueError, match="expired"):
        store.consume(expired.state, now=261, browser_binding="browser-binding-123")
    bound = store.issue(
        "https://client.lab.invalid/callback", now=300, browser_binding="browser-binding-123"
    )
    with pytest.raises(ValueError, match="browser binding"):
        store.consume(bound.state, now=301, browser_binding="other-browser-456")
    assert store.consume(bound.state, now=301, browser_binding="browser-binding-123") == bound


def test_flow_store_requires_non_empty_browser_binding() -> None:
    store = FlowStore()
    issue = cast(Any, store.issue)
    with pytest.raises(TypeError):
        issue("https://client.lab.invalid/callback", now=100)
    with pytest.raises(ValueError, match="browser binding"):
        store.issue("https://client.lab.invalid/callback", now=100, browser_binding="")


def test_pkce_challenge_is_s256() -> None:
    store = FlowStore()
    flow = store.issue(
        "https://client.lab.invalid/callback", now=100, browser_binding="browser-binding-123"
    )
    expected = urlsafe_b64encode(hashlib.sha256(flow.code_verifier.encode()).digest()).rstrip(b"=")
    assert flow.code_challenge == expected.decode()


def test_google_discovery_and_authorization_request_use_security_parameters() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/.well-known/openid-configuration"
        return httpx.Response(
            200,
            json={
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
                "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
                "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            },
        )

    async def scenario() -> AuthorizationRequest:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            adapter = GoogleOidcAdapter(
                client_id="local-google-client",
                client_secret="local-google-fixture-secret",
                http=client,
            )
            metadata = await adapter.discover()
            flow = FlowStore().issue(
                "https://client.lab.invalid/callback",
                now=100,
                browser_binding="browser-binding-123",
            )
            return adapter.authorization_request(metadata, flow)

    request = asyncio.run(scenario())
    assert request.parameters["state"]
    assert request.parameters["nonce"]
    assert request.parameters["code_challenge_method"] == "S256"
    assert request.parameters["scope"] == "openid email profile"
    assert "client_secret" not in request.parameters


def test_discovery_rejects_issuer_mismatch() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "issuer": "https://attacker.lab.invalid",
                "authorization_endpoint": "https://accounts.google.com/auth",
                "token_endpoint": "https://accounts.google.com/token",
                "userinfo_endpoint": "https://accounts.google.com/userinfo",
                "revocation_endpoint": "https://accounts.google.com/revoke",
                "jwks_uri": "https://accounts.google.com/jwks",
            },
        )

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            adapter = GoogleOidcAdapter(
                "local-google-client",
                "local-google-fixture-secret",
                client,
            )
            await adapter.discover()

    with pytest.raises(ValueError, match="issuer mismatch"):
        asyncio.run(scenario())


def test_google_code_exchange_binds_redirect_and_pkce_and_requires_no_store() -> None:
    captured: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(dict(httpx.QueryParams(request.content.decode())))
        return httpx.Response(
            200,
            headers={"Cache-Control": "no-store"},
            json={"id_token": "signed-id-token"},
        )

    async def scenario() -> str:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            adapter = GoogleOidcAdapter(
                "local-google-client",
                "local-google-fixture-secret",
                client,
            )
            flow = FlowStore().issue(
                "https://client.lab.invalid/callback",
                now=100,
                browser_binding="browser-binding-123",
            )
            metadata = ProviderMetadata(
                issuer="https://accounts.google.test",
                authorization_endpoint="https://accounts.google.test/auth",
                token_endpoint="https://accounts.google.test/token",
                userinfo_endpoint="https://accounts.google.test/userinfo",
                revocation_endpoint="https://accounts.google.test/revoke",
                jwks_uri="https://accounts.google.test/jwks",
            )
            result = await adapter.exchange_code(metadata, "authorization-code", flow)
            assert captured["redirect_uri"] == flow.redirect_uri
            assert captured["code_verifier"] == flow.code_verifier
            assert captured["client_secret"] == "local-google-fixture-secret"
            return result

    assert asyncio.run(scenario()) == "signed-id-token"
