from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ClientPolicy:
    client_id: str
    audience: str
    redirect_uris: frozenset[str]
    cors_origins: frozenset[str]
    default_role: str

    def permits_redirect(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("absolute HTTP URL required")
    return f"{parsed.scheme}://{parsed.netloc}"


clients = {
    "temis-web": ClientPolicy(
        client_id="temis-web",
        audience="temis-lab",
        redirect_uris=frozenset({"http://localhost:3000/auth/callback"}),
        cors_origins=frozenset({_origin("http://localhost:3000")}),
        default_role="user",
    )
}


def require_client(client_id: str, redirect_uri: str) -> ClientPolicy:
    client = clients.get(client_id)
    if client is None:
        raise ValueError("unknown client")
    if not client.permits_redirect(redirect_uri):
        raise ValueError("redirect URI is not allowed")
    return client


def client_by_id(client_id: str) -> ClientPolicy:
    client = clients.get(client_id)
    if client is None:
        raise ValueError("unknown client")
    return client


def allowed_origins() -> list[str]:
    return sorted({origin for client in clients.values() for origin in client.cors_origins})
