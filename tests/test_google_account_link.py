import asyncio
import json
from uuid import uuid4

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy.exc import IntegrityError

from temis_sso.external_idp.callback import GoogleCallbackService, JwksCache, verify_google_id_token
from temis_sso.external_idp.external_accounts import (
    ConfirmedAccountLinkService,
    ExternalIdentityLinkRepository,
)
from temis_sso.external_idp.google import GoogleOidcAdapter
from temis_sso.external_idp.models import ExternalIdentity, ProviderMetadata
from temis_sso.external_idp.security import FlowStore
from temis_sso.external_idp.sessions import SessionStore
from temis_sso.persistence import UserRepository, session_scope

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_JWK = json.loads(RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key()))
PUBLIC_JWK["kid"] = "google-key-1"


def metadata() -> ProviderMetadata:
    return ProviderMetadata(
        issuer="https://accounts.google.com",
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
        revocation_endpoint="https://oauth2.googleapis.com/revoke",
        jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    )


def token(*, omit: str | None = None, **overrides: object) -> str:
    claims: dict[str, object] = {
        "iss": "https://accounts.google.com",
        "aud": "local-google-client",
        "sub": "google-123",
        "nonce": "nonce-123",
        "iat": 1_700_000_000,
        "exp": 2_000_000_000,
        "email": "learner@lab.invalid",
        "email_verified": True,
    }
    claims.update(overrides)
    if omit is not None:
        claims.pop(omit)
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": "google-key-1"})


async def verify(encoded: str, keys: list[dict[str, object]] | None = None) -> ExternalIdentity:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Cache-Control": "public, max-age=300"},
            json={"keys": keys if keys is not None else [PUBLIC_JWK]},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        return await verify_google_id_token(
            encoded, metadata(), client, "local-google-client", "nonce-123", JwksCache(), 100
        )


def test_google_id_token_validates_rs256_jwks_and_all_boundary_claims() -> None:
    assert asyncio.run(verify(token())) == ExternalIdentity(
        "google", "google-123", "learner@lab.invalid", True
    )


@pytest.mark.parametrize(
    ("claim", "value", "message"),
    [
        ("iss", "https://attacker.lab.invalid", "issuer"),
        ("aud", "other-client", "audience"),
        ("nonce", "wrong", "nonce"),
    ],
)
def test_google_id_token_rejects_boundary_mismatch(claim: str, value: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        asyncio.run(verify(token(**{claim: value})))


def test_google_id_token_rejects_unknown_kid_and_algorithm_confusion() -> None:
    with pytest.raises(ValueError, match="signing key is unknown"):
        asyncio.run(verify(token(), keys=[]))
    hs_token = jwt.encode(
        {"sub": "google-123", "exp": 2_000_000_000},
        "local-fixture-signing-material-long-enough",
        algorithm="HS256",
        headers={"kid": "google-key-1"},
    )
    with pytest.raises(ValueError, match="algorithm"):
        asyncio.run(verify(hs_token))


def test_jwks_cache_honors_max_age_and_refreshes_unknown_kid_once() -> None:
    calls = 0

    async def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, headers={"Cache-Control": "public, max-age=300"}, json={"keys": [PUBLIC_JWK]}
        )

    async def scenario() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            cache = JwksCache()
            assert (await cache.key(metadata(), client, "google-key-1", 100))["kid"]
            assert (await cache.key(metadata(), client, "google-key-1", 200))["kid"]
            with pytest.raises(ValueError, match="unknown"):
                await cache.key(metadata(), client, "rotated-key", 200)

    asyncio.run(scenario())
    assert calls == 2


@pytest.mark.parametrize("missing", ["exp", "sub", "nonce"])
def test_google_id_token_requires_security_claims(missing: str) -> None:
    with pytest.raises(ValueError, match="invalid ID token"):
        asyncio.run(verify(token(omit=missing)))


def test_google_id_token_rejects_expired_and_checks_azp_for_multiple_audiences() -> None:
    with pytest.raises(ValueError, match="invalid ID token"):
        asyncio.run(verify(token(exp=1)))
    with pytest.raises(ValueError, match="authorized party"):
        asyncio.run(verify(token(aud=["local-google-client", "other"], azp="other")))
    assert (
        asyncio.run(
            verify(token(aud=["local-google-client", "other"], azp="local-google-client"))
        ).subject
        == "google-123"
    )


@pytest.mark.asyncio
async def test_account_link_requires_confirmation_and_rolls_back_subject_collision() -> None:
    subject = f"subject-{uuid4()}"
    identity = ExternalIdentity("google", subject, "learner@lab.invalid", True)
    async with session_scope() as database:
        first = await UserRepository(database).create(f"first-{uuid4()}@lab.invalid")
        second = await UserRepository(database).create(f"second-{uuid4()}@lab.invalid")
        service = ConfirmedAccountLinkService(ExternalIdentityLinkRepository(database))
        with pytest.raises(ValueError, match="authenticated"):
            await service.link("", identity, confirmed=True)
        with pytest.raises(ValueError, match="confirmation"):
            await service.link(first.id, identity, confirmed=False)
        await service.link(first.id, identity, confirmed=True)
        first_id, second_id = first.id, second.id
    async with session_scope() as database:
        repository = ExternalIdentityLinkRepository(database)
        service = ConfirmedAccountLinkService(repository)
        with pytest.raises(IntegrityError):
            await service.link(second_id, identity, confirmed=True)
        await database.rollback()
        assert await repository.resolve("google", subject) == first_id


@pytest.mark.asyncio
async def test_callback_orchestrates_security_and_persistent_link_before_session() -> None:
    flows = FlowStore()
    flow = flows.issue(
        "https://client.lab.invalid/callback",
        now=100,
        browser_binding="browser-binding-123",
    )
    subject = f"callback-subject-{uuid4()}"
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=metadata().__dict__)
        if request.url.path == "/token":
            return httpx.Response(
                200,
                headers={"Cache-Control": "no-store"},
                json={"id_token": token(nonce=flow.nonce, sub=subject)},
            )
        if request.url.path == "/oauth2/v3/certs":
            return httpx.Response(
                200,
                headers={"Cache-Control": "public, max-age=300"},
                json={"keys": [PUBLIC_JWK]},
            )
        return httpx.Response(200)

    async with session_scope() as database:
        user = await UserRepository(database).create(f"callback-{uuid4()}@lab.invalid")
        links = ExternalIdentityLinkRepository(database)
        await ConfirmedAccountLinkService(links).link(
            user.id,
            ExternalIdentity("google", subject, "learner@lab.invalid", True),
            confirmed=True,
        )
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            sessions = SessionStore()
            service = GoogleCallbackService(
                GoogleOidcAdapter("local-google-client", "local-google-fixture-secret", client),
                flows,
                links,
                sessions,
                client,
                JwksCache(),
            )
            session = await service.finish_callback(
                flow.state,
                "authorization-code",
                101,
                "browser-binding-123",
            )
            assert sessions.resolve(session) == user.id
            assert await service.revoke(metadata(), "provider-access-token")
    assert calls == [
        "/.well-known/openid-configuration",
        "/token",
        "/oauth2/v3/certs",
        "/revoke",
    ]


@pytest.mark.asyncio
async def test_external_identity_link_is_persisted_in_auth_database() -> None:
    async with session_scope() as session:
        user = await UserRepository(session).create(f"external-{uuid4()}@lab.invalid")
        links = ExternalIdentityLinkRepository(session)
        subject = f"subject-{uuid4()}"
        await ConfirmedAccountLinkService(links).link(
            user.id,
            ExternalIdentity("google", subject, None, False),
            confirmed=True,
        )
        assert await links.resolve("google", subject) == user.id
