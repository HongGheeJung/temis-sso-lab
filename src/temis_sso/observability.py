import json
import logging
import time
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from contextvars import ContextVar
from uuid import uuid4

from fastapi import FastAPI, Request
from starlette.responses import Response

SENSITIVE_MARKERS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "code",
    "email",
)
SENSITIVE_VALUE_MARKERS = (
    "bearer ",
    "token=",
    "password=",
    "code=",
    "refresh_token",
    "cookie:",
    "__host-",
    "session=",
    "state=",
    "code_verifier=",
    "csrf",
)
_request_id: ContextVar[str | None] = ContextVar("temis_request_id", default=None)


def current_request_id() -> str | None:
    return _request_id.get()


def redact(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]"
            if any(marker in str(key).lower() for marker in SENSITIVE_MARKERS)
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str) and any(
        marker in value.lower() for marker in SENSITIVE_VALUE_MARKERS
    ):
        return "[REDACTED]"
    return value


class StructuredLogger:
    def __init__(self, service: str, sink: Callable[[str], None]) -> None:
        self.service = service
        self.sink = sink

    def event(self, name: str, outcome: str, request_id: str, **fields: object) -> None:
        record = {
            "service": self.service,
            "event": name,
            "outcome": outcome,
            "request_id": request_id,
            **fields,
        }
        self.sink(json.dumps(redact(record), separators=(",", ":"), sort_keys=True))


METRIC_LABELS: dict[str, dict[str, frozenset[str]]] = {
    "temis_auth_requests_total": {
        "route": frozenset(
            {
                "authorize",
                "token",
                "callback",
                "refresh",
                "login",
                "session",
                "logout",
                "reports",
                "other",
            }
        ),
        "outcome": frozenset({"success", "rejected", "error"}),
    },
    "temis_dependency_health": {
        "dependency": frozenset({"postgres", "redis", "jwks"}),
        "state": frozenset({"up", "down"}),
    },
}


class Metrics:
    def __init__(self) -> None:
        self._values: Counter[tuple[str, tuple[tuple[str, str], ...]]] = Counter()

    def increment(self, name: str, labels: dict[str, str]) -> None:
        allowed = METRIC_LABELS.get(name)
        if allowed is None or set(labels) != set(allowed):
            raise ValueError("unknown metric or label schema")
        if any(value not in allowed[key] for key, value in labels.items()):
            raise ValueError("high-cardinality label value")
        self._values[(name, tuple(sorted(labels.items())))] += 1

    def render(self) -> str:
        lines = []
        for (name, labels), value in sorted(self._values.items()):
            encoded = ",".join(f'{key}="{item}"' for key, item in labels)
            lines.append(f"{name}{{{encoded}}} {value}")
        return "\n".join(lines) + ("\n" if lines else "")


def _route_name(path: str) -> str:
    for fragment, name in [
        ("authorize", "authorize"),
        ("token", "token"),
        ("callback", "callback"),
        ("refresh", "refresh"),
        ("login", "login"),
        ("session", "session"),
        ("logout", "logout"),
        ("reports", "reports"),
    ]:
        if fragment in path:
            return name
    return "other"


def install_observability(
    app: FastAPI,
    service: str,
    metrics: Metrics,
    sink: Callable[[str], None] | None = None,
) -> None:
    logger = StructuredLogger(service, sink or logging.getLogger(f"temis.{service}").info)

    @app.middleware("http")
    async def observe(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if supplied.isascii() and 0 < len(supplied) <= 64 else uuid4().hex
        context_token = _request_id.set(request_id)
        route = _route_name(request.url.path)
        started = time.monotonic()
        try:
            response = await call_next(request)
            outcome = "success" if response.status_code < 400 else "rejected"
        except Exception:
            metrics.increment("temis_auth_requests_total", {"route": route, "outcome": "error"})
            logger.event("http.request", "error", request_id, route=route)
            raise
        finally:
            _request_id.reset(context_token)
        metrics.increment("temis_auth_requests_total", {"route": route, "outcome": outcome})
        logger.event(
            "http.request",
            outcome,
            request_id,
            route=route,
            status=response.status_code,
            duration_ms=round((time.monotonic() - started) * 1000, 2),
        )
        response.headers["X-Request-ID"] = request_id
        return response
