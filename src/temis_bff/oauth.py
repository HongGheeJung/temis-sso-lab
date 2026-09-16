import base64
import hashlib
import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from urllib.parse import urlencode

import httpx
from redis.asyncio import Redis

from temis_bff.security import safe_return_path


class OAuthFailed(ValueError):
    pass


@dataclass(frozen=True)
class LoginTransaction:
    verifier: str
    return_to: str


TokenExchange = Callable[[str, str], Awaitable[dict[str, str]]]


class OAuthTokenClient:
    def __init__(self, endpoint: str, client_id: str, redirect_uri: str) -> None:
        self.endpoint = endpoint
        self.client_id = client_id
        self.redirect_uri = redirect_uri

    async def exchange(self, code: str, verifier: str) -> dict[str, str]:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                self.endpoint,
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.client_id,
                    "redirect_uri": self.redirect_uri,
                    "code": code,
                    "code_verifier": verifier,
                },
            )
        if response.status_code != 200:
            raise OAuthFailed("token endpoint rejected authorization code")
        payload = response.json()
        if not isinstance(payload, dict) or not all(
            isinstance(value, str) for value in payload.values()
        ):
            raise OAuthFailed("token response is invalid")
        return payload


class BffOAuthFlow:
    def __init__(
        self, redis_url: str, authorize_endpoint: str, client_id: str, redirect_uri: str
    ) -> None:
        self.redis_url = redis_url
        self.authorize_endpoint = authorize_endpoint
        self.client_id = client_id
        self.redirect_uri = redirect_uri

    async def begin(self, return_to: str) -> tuple[str, str]:
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        transaction = LoginTransaction(verifier, safe_return_path(return_to))
        key = f"temis-bff:oauth:{hashlib.sha256(state.encode()).hexdigest()}"
        async with Redis.from_url(self.redis_url, decode_responses=True) as redis:
            await redis.set(key, json.dumps(asdict(transaction)), ex=300)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        query = urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
            }
        )
        return state, f"{self.authorize_endpoint}?{query}"

    async def complete(
        self, state: str, code: str, exchange: TokenExchange
    ) -> tuple[dict[str, str], str]:
        key = f"temis-bff:oauth:{hashlib.sha256(state.encode()).hexdigest()}"
        async with Redis.from_url(self.redis_url, decode_responses=True) as redis:
            raw = await redis.getdel(key)
        if raw is None:
            raise OAuthFailed("invalid or reused state")
        transaction = LoginTransaction(**json.loads(raw))
        try:
            tokens = await exchange(code, transaction.verifier)
            if not {"user_id", "access_token", "refresh_token"} <= tokens.keys():
                raise OAuthFailed("token response is incomplete")
        except Exception as error:
            if isinstance(error, OAuthFailed):
                raise
            raise OAuthFailed("token exchange failed") from error
        return tokens, transaction.return_to
