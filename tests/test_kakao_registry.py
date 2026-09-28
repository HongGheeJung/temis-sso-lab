import asyncio
import json

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from temis_sso.external_idp.google import GoogleOidcAdapter
from temis_sso.external_idp.kakao import KakaoAdapter, KakaoOidcAdapter
from temis_sso.external_idp.naver import NaverAdapter
from temis_sso.external_idp.registry import ProviderRegistry
from temis_sso.external_idp.security import FlowStore

KAKAO_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
KAKAO_JWK = json.loads(RSAAlgorithm.to_jwk(KAKAO_PRIVATE_KEY.public_key()))
KAKAO_JWK["kid"] = "kakao-key-1"


def test_kakao_maps_numeric_id_and_consented_verified_email() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": 4242,
                "kakao_account": {
                    "has_email": True,
                    "email_needs_agreement": False,
                    "is_email_valid": True,
                    "is_email_verified": True,
                    "email": "learner@lab.invalid",
                },
            },
        )

    async def scenario() -> tuple[str, str | None, bool]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            identity = await KakaoAdapter("local-kakao-client", client).fetch_identity("token")
            return identity.subject, identity.email, identity.email_verified

    assert asyncio.run(scenario()) == ("4242", "learner@lab.invalid", True)


def test_kakao_authorize_and_token_exchange_bind_pkce() -> None:
    captured: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(dict(httpx.QueryParams(request.content.decode())))
        return httpx.Response(200, json={"access_token": "kakao-access"})

    async def scenario() -> str:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            adapter = KakaoAdapter("local-kakao-client", client, "local-kakao-fixture-secret")
            flow = FlowStore().issue(
                "https://client.lab.invalid/callback",
                now=100,
                browser_binding="browser-binding-123",
            )
            request = adapter.authorization_request(flow)
            assert request.url == "https://kauth.kakao.com/oauth/authorize"
            assert request.parameters["code_challenge_method"] == "S256"
            result = await adapter.exchange_code("code-1", flow)
            assert captured["code_verifier"] == flow.code_verifier
            assert captured["client_secret"] == "local-kakao-fixture-secret"
            return result

    assert asyncio.run(scenario()) == "kakao-access"


@pytest.mark.parametrize(
    "account",
    [
        {"has_email": False},
        {
            "has_email": True,
            "email_needs_agreement": True,
            "email": "hidden@lab.invalid",
        },
        {
            "has_email": True,
            "email_needs_agreement": False,
            "is_email_valid": False,
            "email": "bad@lab.invalid",
        },
    ],
)
def test_kakao_email_requires_availability_consent_and_validity(
    account: dict[str, object],
) -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 4242, "kakao_account": account})

    async def scenario() -> tuple[str | None, bool]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            identity = await KakaoAdapter("local-kakao-client", client).fetch_identity("token")
            return identity.email, identity.email_verified

    assert asyncio.run(scenario()) == (None, False)


def test_kakao_rest_rejects_sub_and_oidc_verifies_rs256_claims() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v2/user/me":
            return httpx.Response(200, json={"sub": "kakao-sub-7", "kakao_account": {}})
        return httpx.Response(200, json={"keys": [KAKAO_JWK]})

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(ValueError, match="id"):
                await KakaoAdapter("local-kakao-client", client).fetch_identity("token")
            verifier = KakaoOidcAdapter("local-kakao-client", client)
            claims = {
                "iss": "https://kauth.kakao.com",
                "aud": "local-kakao-client",
                "sub": "kakao-sub-7",
                "nonce": "nonce-123",
                "iat": 1_700_000_000,
                "exp": 2_000_000_000,
            }
            encoded = jwt.encode(
                claims,
                KAKAO_PRIVATE_KEY,
                algorithm="RS256",
                headers={"kid": "kakao-key-1"},
            )
            assert (await verifier.verify(encoded, "nonce-123")).subject == "kakao-sub-7"
            with pytest.raises(ValueError, match="nonce"):
                await verifier.verify(encoded, "wrong-nonce")
            claims["iss"] = "https://attacker.lab.invalid"
            forged = jwt.encode(
                claims,
                KAKAO_PRIVATE_KEY,
                algorithm="RS256",
                headers={"kid": "kakao-key-1"},
            )
            with pytest.raises(ValueError, match="invalid"):
                await verifier.verify(forged, "nonce-123")

    asyncio.run(scenario())


def test_kakao_logout_and_unlink_are_distinct_operations() -> None:
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json={"id": 4242})

    async def scenario() -> tuple[bool, bool]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            adapter = KakaoAdapter("local-kakao-client", client)
            return await adapter.logout("token"), await adapter.unlink("token")

    assert asyncio.run(scenario()) == (True, True)
    assert paths == ["/v1/user/logout", "/v1/user/unlink"]


def test_registry_refuses_duplicate_names_and_unknown_provider() -> None:
    registry = ProviderRegistry()
    registry.register("naver", object())
    with pytest.raises(ValueError, match="already registered"):
        registry.register("naver", object())
    with pytest.raises(KeyError, match="unknown provider"):
        registry.get("unknown")


def test_registry_holds_google_naver_and_kakao_without_exposing_secrets() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    async def scenario() -> tuple[str, ...]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            registry = ProviderRegistry()
            registry.register(
                "google",
                GoogleOidcAdapter(
                    "google-id",
                    "google-fixture-secret",
                    client,
                ),
            )
            registry.register("naver", NaverAdapter("naver-id", "naver-secret", client))
            registry.register("kakao", KakaoAdapter("kakao-id", client))
            return registry.names()

    assert asyncio.run(scenario()) == ("google", "kakao", "naver")
