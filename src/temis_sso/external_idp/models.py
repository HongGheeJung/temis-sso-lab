from dataclasses import dataclass
from urllib.parse import urlparse


def _require_https(value: str) -> None:
    if urlparse(value).scheme != "https":
        raise ValueError("provider endpoints must use HTTPS")


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    revocation_endpoint: str
    jwks_uri: str

    def __post_init__(self) -> None:
        for value in (
            self.issuer,
            self.authorization_endpoint,
            self.token_endpoint,
            self.userinfo_endpoint,
            self.revocation_endpoint,
            self.jwks_uri,
        ):
            _require_https(value)


@dataclass(frozen=True)
class ExternalFlow:
    state: str
    nonce: str
    code_verifier: str
    code_challenge: str
    redirect_uri: str
    created_at: int
    browser_binding: str


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    parameters: dict[str, str]


@dataclass(frozen=True)
class ExternalIdentity:
    provider: str
    subject: str
    email: str | None
    email_verified: bool
