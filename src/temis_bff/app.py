from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from temis_bff.oauth import BffOAuthFlow, OAuthFailed
from temis_bff.security import RequestRejected, require_csrf, session_cookie
from temis_bff.sessions import RedisSessionStore
from temis_sso.observability import Metrics, install_observability

Exchange = Callable[[str, str], Awaitable[dict[str, str]]]
Revoke = Callable[[str], Awaitable[None]]


def create_bff_app(
    flow: BffOAuthFlow,
    sessions: RedisSessionStore,
    exchange: Exchange,
    revoke: Revoke,
    *,
    public_origin: str = "http://localhost:3000",
    production: bool = False,
    metrics: Metrics | None = None,
    log_sink: list[str] | None = None,
) -> FastAPI:
    app = FastAPI(title="TEMIS BFF Lab")
    cookie = session_cookie(production=production)

    @app.middleware("http")
    async def protect_session_cache(
        request: Request, call_next: Callable[..., Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        if request.url.path == "/bff/session":
            response.headers["Cache-Control"] = "no-store, private"
        return response

    @app.get("/login")
    async def login(return_to: str = "/") -> RedirectResponse:
        try:
            _, location = await flow.begin(return_to)
        except RequestRejected as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
        return RedirectResponse(location, status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/auth/callback")
    async def callback(code: str, state: str) -> RedirectResponse:
        try:
            tokens, return_to = await flow.complete(state, code, exchange)
        except OAuthFailed as error:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(error)) from error
        session_id = await sessions.create(
            tokens["user_id"], tokens["access_token"], tokens["refresh_token"]
        )
        response = RedirectResponse(return_to, status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key=str(cookie["key"]),
            value=session_id,
            max_age=sessions.ttl_seconds,
            httponly=True,
            secure=production,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/bff/session")
    async def session_info(request: Request) -> dict[str, str]:
        session_id = request.cookies.get(str(cookie["key"]))
        session = None if session_id is None else await sessions.get(session_id)
        if session is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session required")
        return {"user_id": session.user_id, "csrf_token": session.csrf_token}

    @app.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        request: Request, response: Response, x_csrf_token: str | None = Header(default=None)
    ) -> None:
        session_id = request.cookies.get(str(cookie["key"]))
        session = None if session_id is None else await sessions.get(session_id)
        if session_id is None or session is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session required")
        try:
            require_csrf(
                request.headers.get("origin"), public_origin, x_csrf_token, session.csrf_token
            )
        except RequestRejected as error:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(error)) from error
        await revoke(session.refresh_token)
        await sessions.delete(session_id)
        response.delete_cookie(
            key=str(cookie["key"]), path="/", secure=production, httponly=True, samesite="lax"
        )

    install_observability(
        app, "bff", metrics or Metrics(), None if log_sink is None else log_sink.append
    )
    return app
