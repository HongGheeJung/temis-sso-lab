import hmac
from urllib.parse import unquote, urlsplit


class RequestRejected(ValueError):
    pass


def safe_return_path(value: str) -> str:
    decoded = unquote(value)
    parsed = urlsplit(decoded)
    unsafe_character = "\\" in decoded or any(ord(character) < 32 for character in decoded)
    if (
        not decoded.startswith("/")
        or decoded.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or unsafe_character
    ):
        raise RequestRejected("return path must be local")
    return decoded


def require_csrf(
    origin: str | None, expected_origin: str, supplied: str | None, saved: str
) -> None:
    if origin != expected_origin:
        raise RequestRejected("origin mismatch")
    if supplied is None or not hmac.compare_digest(supplied, saved):
        raise RequestRejected("csrf token mismatch")


def session_cookie(*, production: bool) -> dict[str, object]:
    return {
        "key": "__Host-temis_session" if production else "temis_session",
        "httponly": True,
        "secure": production,
        "samesite": "lax",
        "path": "/",
    }
