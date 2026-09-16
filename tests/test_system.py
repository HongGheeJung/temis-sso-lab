from fastapi.testclient import TestClient

from temis_sso.main import create_app


def test_health_and_security_headers() -> None:
    response = TestClient(create_app()).get("/healthz")
    assert response.json() == {"status": "ok"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_readiness_can_fail_without_leaking_configuration() -> None:
    response = TestClient(create_app(ready=False)).get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"error": {"code": "not_ready"}}
    assert "database" not in response.text.lower()
