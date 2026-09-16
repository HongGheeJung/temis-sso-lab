from fastapi import APIRouter, Request

from temis_sso.bootstrap import LabError
from temis_sso.tokens import codec

router = APIRouter(tags=["system"])


@router.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
def ready(request: Request) -> dict[str, str]:
    if not request.app.state.ready:
        raise LabError(503, "not_ready")
    return {"status": "ready"}


@router.get("/.well-known/jwks.json")
def jwks() -> dict[str, list[dict[str, str]]]:
    return codec.jwks()
