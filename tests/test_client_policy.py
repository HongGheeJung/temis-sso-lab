from fastapi.testclient import TestClient

from temis_sso.main import create_app

client = TestClient(create_app())


def test_cors_is_exact_origin_allowlist() -> None:
    allowed = client.options(
        "/oauth/token",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"},
    )
    denied = client.options(
        "/oauth/token",
        headers={"Origin": "http://evil.local", "Access-Control-Request-Method": "POST"},
    )
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-origin" not in denied.headers
