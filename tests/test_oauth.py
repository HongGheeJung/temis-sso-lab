import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from temis_sso.main import create_app

client = TestClient(create_app())
verifier = "v" * 43
challenge = (
    base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
)


def authorization() -> tuple[str, str]:
    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "temis-web",
            "redirect_uri": "http://localhost:3000/auth/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "client-state-value",
        },
        follow_redirects=False,
    )
    provider = client.get(response.headers["location"], follow_redirects=False)
    callback = client.get(provider.headers["location"], follow_redirects=False)
    query = parse_qs(urlsplit(callback.headers["location"]).query)
    return query["code"][0], query["state"][0]


def test_authorization_code_pkce_and_state_round_trip() -> None:
    code, state = authorization()
    assert state == "client-state-value"
    payload = {
        "grant_type": "authorization_code",
        "client_id": "temis-web",
        "redirect_uri": "http://localhost:3000/auth/callback",
        "code": code,
        "code_verifier": verifier,
    }
    tokens = client.post("/oauth/token", data=payload)
    assert tokens.status_code == 200 and "access_token" in tokens.json()
    assert tokens.headers["cache-control"] == "no-store"
    assert tokens.headers["pragma"] == "no-cache"
    assert client.post("/oauth/token", data=payload).status_code == 401


def test_unknown_client_never_redirects() -> None:
    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "unknown",
            "redirect_uri": "https://evil.invalid/callback",
            "code_challenge": challenge,
            "state": "client-state-value",
        },
        follow_redirects=False,
    )
    assert response.status_code == 400 and "location" not in response.headers


def test_wrong_verifier_consumes_code_and_fails_closed() -> None:
    code, _ = authorization()
    payload = {
        "grant_type": "authorization_code",
        "client_id": "temis-web",
        "redirect_uri": "http://localhost:3000/auth/callback",
        "code": code,
        "code_verifier": "x" * 43,
    }
    assert client.post("/oauth/token", data=payload).status_code == 401
    payload["code_verifier"] = verifier
    assert client.post("/oauth/token", data=payload).status_code == 401
