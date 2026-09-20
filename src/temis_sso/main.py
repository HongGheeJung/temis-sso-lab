from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from temis_sso.api.admin import router as admin_router
from temis_sso.api.auth import router as auth_router
from temis_sso.api.naver_oauth import router as naver_oauth_router
from temis_sso.api.oauth import router as oauth_router
from temis_sso.api.system import router as system_router
from temis_sso.api.users import router as users_router
from temis_sso.bootstrap import configure_app
from temis_sso.client_policy import allowed_origins
from temis_sso.config import settings
from temis_sso.observability import Metrics, install_observability

metrics = Metrics()


def create_app(ready: bool = True, log_sink: list[str] | None = None) -> FastAPI:
    app = FastAPI(title=settings.service_name, debug=settings.debug, version="0.12.0")
    app.state.ready = ready
    configure_app(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins(),
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Status-Key", "X-Request-ID"],
    )
    app.include_router(system_router)
    app.include_router(auth_router)
    app.include_router(users_router)
    app.include_router(oauth_router)
    app.include_router(admin_router)
    app.include_router(naver_oauth_router)
    install_observability(app, "sso", metrics, None if log_sink is None else log_sink.append)
    return app


app = create_app()
