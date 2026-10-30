"""Isolated regression tests; no running Postgres, Redis or real provider required."""

import json
import time
from contextlib import asynccontextmanager
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from temis_sso.api import kakao_oauth, naver_oauth, oauth, social
from temis_sso.api.auth import TokenBundle
from temis_sso.config import Settings, settings
from temis_sso.external_idp.external_accounts import ExternalIdentityLink
from temis_sso.external_idp.models import ExternalIdentity
from temis_sso.persistence import Base, User, UserRepository
from temis_sso.tokens import codec


@pytest_asyncio.fixture
async def lab(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def sessions():
        async with factory() as session, session.begin():
            yield session

    for module in (oauth, kakao_oauth, naver_oauth, social):
        monkeypatch.setattr(module, "session_scope", sessions)
    monkeypatch.setattr(social, "provider_tokens", social.ProviderTokenStore())
    monkeypatch.setattr(naver_oauth, "provider_tokens", social.provider_tokens)
    monkeypatch.setattr(kakao_oauth, "provider_tokens", social.provider_tokens)
    for name in (
        "google_client_id",
        "google_client_secret",
        "naver_client_id",
        "naver_client_secret",
        "kakao_rest_api_key",
        "kakao_client_secret",
    ):
        monkeypatch.setattr(settings, name, "test-credential")

    async def bundle(user_id, audience):
        return TokenBundle(
            user_id=user_id, access_token="local-access", refresh_token="local-refresh"
        )

    monkeypatch.setattr(social, "issue_bundle", bundle)
    app = FastAPI()
    for module in (oauth, kakao_oauth, naver_oauth):
        app.include_router(module.router)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://localhost:8000"
    ) as client:
        client.headers["Authorization"] = "Bearer " + codec.issue_access(
            "owner", audience="lab-client"
        )
        yield client, sessions
    await engine.dispose()


def providers(monkeypatch, handler):
    original = httpx.AsyncClient
    clients = []

    def factory(**kwargs):
        client = original(transport=httpx.MockTransport(handler), **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return clients


@pytest.mark.parametrize("provider", ["google", "naver", "kakao"])
async def test_first_and_repeat_login_consume_once_and_never_redirect_tokens(
    lab, monkeypatch, provider
):
    client, sessions = lab
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    key["kid"] = "review-key"
    nonce = ""
    calls = []
    oauth.jwks_cache._entries.clear()

    def handler(request):
        calls.append(request.url.path)
        if "openid-configuration" in request.url.path:
            return httpx.Response(
                200,
                json={
                    "issuer": "https://accounts.google.com",
                    "authorization_endpoint": "https://accounts.google.com/authorize",
                    "token_endpoint": "https://oauth2.googleapis.com/token",
                    "userinfo_endpoint": "https://openidconnect.googleapis.com/userinfo",
                    "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
                    "jwks_uri": "https://www.googleapis.com/jwks",
                },
            )
        if request.url.path == "/jwks":
            return httpx.Response(200, json={"keys": [key]})
        if request.url.path.endswith("/token"):
            if provider == "google":
                now = int(time.time())
                encoded = jwt.encode(
                    {
                        "iss": "https://accounts.google.com",
                        "aud": "test-credential",
                        "sub": "42",
                        "nonce": nonce,
                        "iat": now,
                        "exp": now + 300,
                    },
                    private,
                    algorithm="RS256",
                    headers={"kid": "review-key"},
                )
                return httpx.Response(
                    200, json={"id_token": encoded}, headers={"Cache-Control": "no-store"}
                )
            return httpx.Response(200, json={"access_token": "provider-access"})
        return httpx.Response(
            200,
            json={"resultcode": "00", "response": {"id": "42"}}
            if provider == "naver"
            else {"id": 42},
        )

    clients = providers(monkeypatch, handler)
    user_ids = []
    for _ in range(2):
        start = await client.get(f"/oauth/{provider}/login")
        assert start.status_code == 303
        params = parse_qs(urlsplit(start.headers["location"]).query)
        nonce = params.get("nonce", [""])[0]
        state = params["state"][0]
        callback = f"/oauth/{provider}/callback?state={state}&code=one-use-code"
        result = await client.get(callback)
        assert result.status_code == 200, result.text
        assert "location" not in result.headers
        assert result.headers["cache-control"] == "no-store"
        assert result.json()["access_token"] == "local-access"
        user_ids.append(result.json()["user_id"])
        if provider in {"naver", "kakao"}:
            assert social.provider_tokens.get(provider, user_ids[-1]) == "provider-access"
        assert all(c.is_closed for c in clients)
        # Restore binding cookie to prove replay fails due to consumed state, not missing cookie.
        cookie_name = (
            "idp_browser_binding" if provider == "google" else f"{provider}_browser_binding"
        )
        binding = start.cookies[cookie_name]
        client.cookies.set(cookie_name, binding)
        count = len(calls)
        replay = await client.get(callback)
        assert replay.status_code == 401
        assert len(calls) == count
        client.cookies.clear()
    assert user_ids[0] == user_ids[1]
    async with sessions() as session:
        assert len((await session.scalars(select(User))).all()) == 1


@pytest.mark.parametrize("provider", ["naver", "kakao"])
@pytest.mark.parametrize(
    "owns,success,expected", [(False, True, 403), (True, False, 502), (True, True, 204)]
)
async def test_revoke_checks_profile_ownership_before_provider_and_db_delete(
    lab, monkeypatch, provider, owns, success, expected
):
    client, sessions = lab
    async with sessions() as session:
        session.add(User(id="owner", email="owner@lab.invalid", status="active"))
        await session.flush()
        session.add(ExternalIdentityLink(provider=provider, subject="42", user_id="owner"))
    operations = []

    def handler(request):
        assert not request.url.query
        if request.method == "GET":
            subject = "42" if owns else "99"
            return httpx.Response(
                200,
                json={"resultcode": "00", "response": {"id": subject}}
                if provider == "naver"
                else {"id": int(subject)},
            )
        operations.append(request.url.path)
        if not success:
            return httpx.Response(200, json={"error": "denied", "code": -1})
        return httpx.Response(200) if provider == "naver" else httpx.Response(200, json={"id": 42})

    clients = providers(monkeypatch, handler)
    social.provider_tokens.put(provider, "owner", "provider-access")
    response = await client.post(f"/oauth/{provider}/revoke", json={})
    assert response.status_code == expected, response.text
    assert len(operations) == int(owns)
    if expected != 204:
        assert social.provider_tokens.get(provider, "owner") == "provider-access"
    else:
        with pytest.raises(Exception) as error:
            social.provider_tokens.get(provider, "owner")
        assert error.value.status_code == 409
    assert all(c.is_closed for c in clients)
    async with sessions() as session:
        link = await session.get(ExternalIdentityLink, (provider, "42"))
        assert (link is None) == (expected == 204)


@pytest.mark.parametrize("provider", ["naver", "kakao"])
async def test_revoke_rejects_query_only_tokens(lab, provider):
    client, sessions = lab
    async with sessions() as session:
        session.add(User(id="owner", email="owner@lab.invalid", status="active"))
    response = await client.post(f"/oauth/{provider}/revoke?access_token=old-client-token")
    assert response.status_code == 422


async def test_same_email_never_automatically_merges_accounts(lab):
    _, sessions = lab
    async with sessions() as session:
        existing = await UserRepository(session).create("same@lab.invalid")
        original_id = existing.id
    async with sessions() as session:
        new_id = await social.resolve_social_user(
            session, ExternalIdentity("google", "42", "same@lab.invalid", True)
        )
        assert new_id != original_id
    async with sessions() as session:
        user = await session.get(User, new_id)
        user.status = "suspended"
    async with sessions() as session:
        with pytest.raises(Exception) as error:
            await social.resolve_social_user(session, ExternalIdentity("google", "42", None, False))
        assert error.value.status_code == 401


def test_optional_provider_settings_and_callback_validation(monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("TEMIS_LAB_"):
            monkeypatch.delenv(name)
    config = Settings(_env_file=None)
    assert config.naver_client_id == config.kakao_rest_api_key == ""
    with pytest.raises(ValueError):
        Settings(_env_file=None, naver_redirect_uri="http://public.example/callback")


@pytest.mark.parametrize("provider", ["google", "naver", "kakao"])
async def test_unconfigured_provider_returns_503(lab, monkeypatch, provider):
    client, _ = lab
    name = "kakao_rest_api_key" if provider == "kakao" else f"{provider}_client_id"
    monkeypatch.setattr(settings, name, "")
    assert (await client.get(f"/oauth/{provider}/login")).status_code == 503


@pytest.mark.parametrize("provider", ["google", "naver", "kakao"])
async def test_wrong_browser_binding_rejected_before_network(lab, monkeypatch, provider):
    client, _ = lab
    store = (
        oauth.flow_store
        if provider == "google"
        else getattr(naver_oauth if provider == "naver" else kakao_oauth, f"{provider}_flow_store")
    )
    flow = store.issue(
        "http://localhost:8000/callback", int(time.time()), "correct-browser-binding"
    )
    cookie = "idp_browser_binding" if provider == "google" else f"{provider}_browser_binding"
    client.cookies.set(cookie, "different-browser-binding")

    def handler(request):
        raise AssertionError("No provider call is allowed for an invalid binding")

    providers(monkeypatch, handler)
    response = await client.get(f"/oauth/{provider}/callback?state={flow.state}&code=code")
    assert response.status_code == 401


@pytest.mark.parametrize("provider", ["google", "naver", "kakao"])
async def test_configured_callback_and_closed_login_http_client(lab, monkeypatch, provider):
    client, _ = lab
    callback = f"https://auth.example/oauth/{provider}/callback"
    monkeypatch.setattr(settings, f"{provider}_redirect_uri", callback)
    monkeypatch.setattr(settings, "oauth_cookie_secure", True)

    def handler(request):
        return httpx.Response(
            200,
            json={
                "issuer": "https://accounts.google.com",
                "authorization_endpoint": "https://accounts.google.com/authorize",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "userinfo_endpoint": "https://openidconnect.googleapis.com/userinfo",
                "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
                "jwks_uri": "https://www.googleapis.com/jwks",
            },
        )

    clients = providers(monkeypatch, handler)
    response = await client.get(f"/oauth/{provider}/login")
    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query)["redirect_uri"] == [callback]
    assert "Secure" in response.headers["set-cookie"]
    assert all(c.is_closed for c in clients)


@pytest.mark.parametrize("provider", ["naver", "kakao"])
@pytest.mark.parametrize(
    "audience,expected", [("lab-client", 409), ("temis-lab", 401), ("other-service", 401)]
)
async def test_revoke_uses_real_bearer_verification_and_requires_recent_login(
    lab, provider, audience, expected
):
    client, sessions = lab
    async with sessions() as session:
        session.add(User(id="owner", email="owner@lab.invalid", status="active"))
    client.headers["Authorization"] = "Bearer " + codec.issue_access("owner", audience=audience)
    response = await client.post(f"/oauth/{provider}/revoke", json={})
    assert response.status_code == expected


@pytest.mark.parametrize("provider", ["naver", "kakao"])
async def test_revoke_does_not_accept_client_supplied_provider_token(lab, provider):
    client, sessions = lab
    async with sessions() as session:
        session.add(User(id="owner", email="owner@lab.invalid", status="active"))
    response = await client.post(f"/oauth/{provider}/revoke", json={"access_token": "untrusted"})
    assert response.status_code == 422


def test_provider_tokens_expire_and_are_scoped_to_provider_and_user(monkeypatch):
    from types import SimpleNamespace

    from fastapi import HTTPException

    now = 100.0
    monkeypatch.setattr(social, "time", SimpleNamespace(monotonic=lambda: now))
    store = social.ProviderTokenStore()
    store.put("naver", "owner", "private-token")
    assert store.get("naver", "owner") == "private-token"
    for provider, user in [("kakao", "owner"), ("naver", "someone-else")]:
        with pytest.raises(HTTPException) as error:
            store.get(provider, user)
        assert error.value.status_code == 409
    now += 300
    with pytest.raises(HTTPException) as error:
        store.get("naver", "owner")
    assert error.value.status_code == 409
    assert not store._tokens
