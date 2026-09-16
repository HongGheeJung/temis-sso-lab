import asyncio
import uuid
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from resource_api.app import create_resource_app
from resource_api.auth import DependencyUnavailable, JwksVerifier
from temis_bff.app import create_bff_app
from temis_bff.oauth import BffOAuthFlow, OAuthFailed
from temis_bff.sessions import RedisSessionStore
from temis_sso.config import settings
from temis_sso.fake_provider import FakeOAuthProvider, ProviderIdentity
from temis_sso.main import create_app
from temis_sso.observability import current_request_id
from temis_sso.tokens import codec


@pytest.mark.asyncio
async def test_bff_replay_and_incomplete_exchange_fail_closed() -> None:
    flow = BffOAuthFlow(
        settings.redis_url,
        "https://auth.lab.invalid/oauth/authorize",
        "temis-web",
        "http://localhost:3000/auth/callback",
    )
    _, url = await flow.begin("/")
    state = url.split("state=", 1)[1]

    async def incomplete(code: str, verifier: str) -> dict[str, str]:
        return {"user_id": "user-1"}

    with pytest.raises(OAuthFailed):
        await flow.complete(state, "code", incomplete)
    with pytest.raises(OAuthFailed):
        await flow.complete(state, "code", incomplete)


@pytest.mark.asyncio
async def test_jwks_outage_without_cache_fails_closed() -> None:
    async def unavailable() -> dict[str, object]:
        raise ConnectionError("JWKS unavailable")

    async def status(subject: str, version: int) -> bool:
        return True

    verifier = JwksVerifier(
        unavailable,
        status,
        issuer="https://auth.lab.invalid",
        audience="temis-lab",
        authorized_party="temis-web",
    )
    with pytest.raises(DependencyUnavailable):
        await verifier.authenticate(codec.issue_access("user-1"))


@pytest.mark.asyncio
async def test_redis_session_loss_requires_a_new_server_session() -> None:
    sessions = RedisSessionStore(settings.redis_url)
    flow = BffOAuthFlow(
        settings.redis_url,
        "http://auth.lab.invalid/oauth/authorize",
        "temis-web",
        "http://localhost:3000/auth/callback",
    )

    async def exchange(code: str, verifier: str) -> dict[str, str]:
        raise AssertionError("session endpoint must not exchange tokens")

    async def revoke(refresh_token: str) -> None:
        return None

    client = TestClient(create_bff_app(flow, sessions, exchange, revoke))
    first = await sessions.create("user-1", "access-1", "refresh-1")
    client.cookies.set("temis_session", first)
    assert client.get("/bff/session").status_code == 200
    await sessions.delete(first)
    assert client.get("/bff/session").status_code == 401
    replacement = await sessions.create("user-1", "access-2", "refresh-2")
    client.cookies.set("temis_session", replacement)
    assert client.get("/bff/session").status_code == 200
    await sessions.delete(replacement)


def test_http_login_bff_resource_and_logout_end_to_end() -> None:
    request_id = "req-e2e-flow"
    sso_logs: list[str] = []
    sso = TestClient(create_app(log_sink=sso_logs))
    sessions = RedisSessionStore(settings.redis_url)
    flow = BffOAuthFlow(
        settings.redis_url,
        "http://auth.lab.invalid/oauth/authorize",
        "temis-web",
        "http://localhost:3000/auth/callback",
    )

    async def exchange(code: str, verifier: str) -> dict[str, str]:
        assert current_request_id() == request_id
        response = sso.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "temis-web",
                "redirect_uri": "http://localhost:3000/auth/callback",
                "code": code,
                "code_verifier": verifier,
            },
            headers={"X-Request-ID": request_id},
        )
        assert response.status_code == 200
        return response.json()

    async def revoke(refresh_token: str) -> None:
        assert current_request_id() == request_id
        assert (
            sso.post(
                "/auth/logout",
                json={"refresh_token": refresh_token},
                headers={"X-Request-ID": request_id},
            ).status_code
            == 204
        )

    bff_logs: list[str] = []
    bff = TestClient(create_bff_app(flow, sessions, exchange, revoke, log_sink=bff_logs))
    authorize_url = bff.get(
        "/login", headers={"X-Request-ID": request_id}, follow_redirects=False
    ).headers["location"]
    parsed = urlsplit(authorize_url)
    provider = sso.get(
        f"{parsed.path}?{parsed.query}",
        headers={"X-Request-ID": request_id},
        follow_redirects=False,
    )
    account = f"e2e-{uuid.uuid4().hex}"
    FakeOAuthProvider.accounts[account] = ProviderIdentity("lab-provider", account)
    provider_callback = sso.get(
        f"{provider.headers['location']}&account={account}",
        headers={"X-Request-ID": request_id},
        follow_redirects=False,
    )
    bff_callback = sso.get(
        provider_callback.headers["location"],
        headers={"X-Request-ID": request_id},
        follow_redirects=False,
    )
    parsed_callback = urlsplit(bff_callback.headers["location"])
    assert (
        bff.get(
            f"{parsed_callback.path}?{parsed_callback.query}",
            headers={"X-Request-ID": request_id},
            follow_redirects=False,
        ).status_code
        == 303
    )
    session_id = bff.cookies.get("temis_session")
    assert session_id is not None
    server_session = asyncio.run(sessions.get(session_id))
    assert server_session is not None

    async def fetch_jwks() -> dict[str, object]:
        assert current_request_id() == request_id
        return sso.get("/.well-known/jwks.json", headers={"X-Request-ID": request_id}).json()

    async def check_status(subject: str, version: int) -> bool:
        assert current_request_id() == request_id
        response = sso.post(
            "/auth/status",
            json={"user_id": subject, "authz_version": version},
            headers={"X-Status-Key": settings.status_service_key, "X-Request-ID": request_id},
        )
        return bool(response.json()["active"])

    verifier = JwksVerifier(
        fetch_jwks,
        check_status,
        issuer="https://auth.lab.invalid",
        audience="temis-lab",
        authorized_party="temis-web",
    )
    resource_logs: list[str] = []
    resource = TestClient(create_resource_app(verifier, log_sink=resource_logs))
    report = resource.get(
        "/api/reports",
        headers={
            "Authorization": f"Bearer {server_session.access_token}",
            "X-Request-ID": request_id,
        },
    )
    assert report.status_code == 200
    exposed = bff.get("/bff/session", headers={"X-Request-ID": request_id}).json()
    logout = bff.post(
        "/logout",
        headers={
            "Origin": "http://localhost:3000",
            "X-CSRF-Token": exposed["csrf_token"],
            "X-Request-ID": request_id,
        },
    )
    assert logout.status_code == 204 and asyncio.run(sessions.get(session_id)) is None
    assert sso_logs and bff_logs and resource_logs
    assert all(request_id in log for log in [*sso_logs, *bff_logs, *resource_logs])
