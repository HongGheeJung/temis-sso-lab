import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from temis_sso.observability import Metrics, StructuredLogger, install_observability, redact


def test_structured_logs_redact_nested_credentials() -> None:
    output: list[str] = []
    logger = StructuredLogger("sso", output.append)
    logger.event(
        "token.exchange",
        "rejected",
        "req-123",
        authorization="Bearer raw",
        payload={"code": "raw-code", "profile": {"email": "learner@lab.invalid"}},
        reason="pkce_mismatch",
        errors=["safe", "Bearer nested-secret"],
    )
    record = json.loads(output[0])
    assert record["authorization"] == "[REDACTED]"
    assert record["payload"]["code"] == "[REDACTED]"
    assert record["payload"]["profile"]["email"] == "[REDACTED]"
    assert "raw-code" not in output[0] and record["reason"] == "pkce_mismatch"
    assert record["errors"][1] == "[REDACTED]"
    for secret in [
        "Cookie: __Host-temis_session=opaque",
        "redirect state=oauth-state",
        "code_verifier=pkce-secret",
        "csrf=csrf-secret",
    ]:
        assert redact(f"failure: {secret}") == "[REDACTED]"


def test_metrics_allow_only_bounded_labels() -> None:
    metrics = Metrics()
    metrics.increment("temis_auth_requests_total", {"route": "token", "outcome": "success"})
    assert 'route="token"' in metrics.render()
    with pytest.raises(ValueError):
        metrics.increment(
            "temis_auth_requests_total",
            {"route": "/users/unique-id", "outcome": "success"},
        )
    with pytest.raises(ValueError):
        metrics.increment("temis_auth_requests_total", {"route": "token", "user_id": "user-1"})


def test_operational_runbooks_cover_rollback_and_evidence() -> None:
    from pathlib import Path

    matrix = Path("ops/E2E-FAILURE-MATRIX.md").read_text()
    rollback = Path("ops/ROLLBACK-RUNBOOK.md").read_text()
    incident = Path("ops/INCIDENT-RUNBOOK.md").read_text()
    assert "authorization code replay" in matrix and "checksum mismatch" in matrix
    assert "roll back the application before the schema" in rollback
    assert "unknown keys fail closed" in incident and "isolated database restore" in incident


def test_observability_middleware_propagates_request_id() -> None:
    app = FastAPI()
    logs: list[str] = []
    metrics = Metrics()

    @app.get("/oauth/token")
    async def endpoint() -> dict[str, str]:
        return {"status": "ok"}

    install_observability(app, "test", metrics, logs.append)
    response = TestClient(app).get("/oauth/token", headers={"X-Request-ID": "req-fixed"})
    assert response.headers["x-request-id"] == "req-fixed"
    assert "req-fixed" in logs[0] and 'route="token"' in metrics.render()


def test_default_structured_sink_does_not_retain_one_log_per_request() -> None:
    app = FastAPI()
    metrics = Metrics()

    @app.get("/health")
    async def endpoint() -> dict[str, str]:
        return {"status": "ok"}

    install_observability(app, "bounded", metrics)
    client = TestClient(app)
    for _ in range(100):
        assert client.get("/health").status_code == 200
    assert len(metrics._values) == 1
