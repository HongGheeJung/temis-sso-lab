from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from temis_bff.app import create_bff_app
from temis_bff.oauth import BffOAuthFlow, OAuthFailed
from temis_bff.security import (
    RequestRejected,
    require_csrf,
    safe_return_path,
    session_cookie,
)
from temis_bff.sessions import RedisSessionStore
from temis_sso.config import settings
from temis_sso.main import create_app as create_sso_app


@pytest.mark.asyncio
async def test_bff_state_is_one_time_and_tokens_stay_server_side() -> None:
    flow = BffOAuthFlow(
        settings.redis_url,
        "https://auth.lab.invalid/oauth/authorize",
        "temis-web",
        "http://localhost:3000/auth/callback",
    )
    _, authorize_url = await flow.begin("/workspace")
    state = authorize_url.split("state=", 1)[1]

    async def exchange(code: str, verifier: str) -> dict[str, str]:
        assert code == "one-time-code"
        assert len(verifier) >= 43
        return {
            "user_id": "user-1",
            "access_token": "access",
            "refresh_token": "refresh",
        }

    tokens, target = await flow.complete(state, "one-time-code", exchange)
    assert target == "/workspace"
    assert "access" not in authorize_url and tokens["access_token"] == "access"
    with pytest.raises(OAuthFailed):
        await flow.complete(state, "one-time-code", exchange)


@pytest.mark.asyncio
async def test_opaque_session_keeps_tokens_in_redis() -> None:
    store = RedisSessionStore(settings.redis_url)
    opaque = await store.create("user-1", "access-secret", "refresh-secret")
    assert "access-secret" not in opaque and "user-1" not in opaque
    saved = await store.get(opaque)
    assert saved is not None and saved.access_token == "access-secret"
    await store.delete(opaque)
    assert await store.get(opaque) is None


def test_cookie_return_path_and_csrf_contract() -> None:
    assert session_cookie(production=True) == {
        "key": "__Host-temis_session",
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "path": "/",
    }
    assert safe_return_path("/workspace?tab=1") == "/workspace?tab=1"
    for unsafe in ["https://evil.invalid", "//evil.invalid/path"]:
        with pytest.raises(RequestRejected):
            safe_return_path(unsafe)
    require_csrf("https://app.lab.invalid", "https://app.lab.invalid", "csrf", "csrf")
    with pytest.raises(RequestRejected):
        require_csrf("https://evil.invalid", "https://app.lab.invalid", "csrf", "csrf")


def test_fastapi_bff_login_session_and_logout_boundary() -> None:
    flow = BffOAuthFlow(
        settings.redis_url,
        "https://auth.lab.invalid/oauth/authorize",
        "temis-web",
        "https://app.lab.invalid/auth/callback",
    )
    sessions = RedisSessionStore(settings.redis_url)
    revoked: list[str] = []

    async def exchange(code: str, verifier: str) -> dict[str, str]:
        assert code == "authorization-code" and len(verifier) >= 43
        return {
            "user_id": "user-1",
            "access_token": "server-access",
            "refresh_token": "server-refresh",
        }

    async def revoke(refresh_token: str) -> None:
        revoked.append(refresh_token)

    client = TestClient(
        create_bff_app(
            flow,
            sessions,
            exchange,
            revoke,
            public_origin="https://app.lab.invalid",
            production=True,
        ),
        base_url="https://app.lab.invalid",
    )
    login = client.get("/login?return_to=/workspace", follow_redirects=False)
    assert login.status_code == 303
    state = parse_qs(urlsplit(login.headers["location"]).query)["state"][0]
    assert client.get("/auth/callback?code=bad&state=missing").status_code == 401
    callback = client.get(
        "/auth/callback",
        params={"code": "authorization-code", "state": state},
        follow_redirects=False,
    )
    cookie = callback.headers["set-cookie"]
    assert callback.status_code == 303 and "__Host-temis_session=" in cookie
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie
    session_response = client.get("/bff/session")
    assert session_response.headers["cache-control"] == "no-store, private"
    session = session_response.json()
    assert set(session) == {"user_id", "csrf_token"}
    assert client.post("/logout").status_code == 403
    assert (
        client.post(
            "/logout",
            headers={"Origin": "https://evil.invalid", "X-CSRF-Token": session["csrf_token"]},
        ).status_code
        == 403
    )
    logout = client.post(
        "/logout",
        headers={"Origin": "https://app.lab.invalid", "X-CSRF-Token": session["csrf_token"]},
    )
    assert logout.status_code == 204 and "Max-Age=0" in logout.headers["set-cookie"]
    missing = client.get("/bff/session")
    assert missing.status_code == 401 and missing.headers["cache-control"] == "no-store, private"
    assert revoked == ["server-refresh"]
    token_error = TestClient(create_sso_app()).post(
        "/oauth/token",
        data={"grant_type": "authorization_code"},
    )
    assert token_error.status_code == 400
    assert token_error.headers["cache-control"] == "no-store"
