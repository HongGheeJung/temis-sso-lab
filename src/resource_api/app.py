from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, status

from resource_api.auth import (
    DependencyUnavailable,
    JwksVerifier,
    ScopeDenied,
    TokenRejected,
    require_scope,
)
from temis_sso.observability import Metrics, install_observability


def create_resource_app(
    verifier: JwksVerifier, metrics: Metrics | None = None, log_sink: list[str] | None = None
) -> FastAPI:
    app = FastAPI(title="TEMIS Resource API Lab")

    @app.get("/api/reports")
    async def reports(authorization: Annotated[str | None, Header()] = None) -> dict[str, str]:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "bearer token required")
        try:
            principal = await verifier.authenticate(authorization.removeprefix("Bearer "))
            require_scope(principal, "reports:read")
            if "temis:user" not in principal.roles and "temis:admin" not in principal.roles:
                raise ScopeDenied("TEMIS role required")
        except DependencyUnavailable as error:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(error)) from error
        except TokenRejected as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
        except ScopeDenied as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
        return {"subject": principal.subject}

    install_observability(
        app,
        "resource-api",
        metrics or Metrics(),
        None if log_sink is None else log_sink.append,
    )
    return app
