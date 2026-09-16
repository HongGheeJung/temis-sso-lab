import base64
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass

from redis.asyncio import Redis

from temis_sso.config import settings


def pkce_challenge(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


def _key(namespace: str, raw: str) -> str:
    return f"temis-lab:{namespace}:{hashlib.sha256(raw.encode()).hexdigest()}"


@dataclass(frozen=True)
class OAuthTransaction:
    client_id: str
    redirect_uri: str
    code_challenge: str
    provider: str
    client_state: str


class RedisOneTimeStore:
    def __init__(self, redis_url: str) -> None:
        self.redis_url = redis_url

    async def put(self, namespace: str, value: dict[str, str], ttl_seconds: int) -> str:
        raw = secrets.token_urlsafe(32)
        async with Redis.from_url(self.redis_url, decode_responses=True) as redis:
            await redis.set(_key(namespace, raw), json.dumps(value), ex=ttl_seconds)
        return raw

    async def take(self, namespace: str, raw: str) -> dict[str, str] | None:
        async with Redis.from_url(self.redis_url, decode_responses=True) as redis:
            value = await redis.getdel(_key(namespace, raw))
        return None if value is None else json.loads(value)

    async def begin(self, transaction: OAuthTransaction, ttl_seconds: int = 300) -> str:
        return await self.put("oauth", asdict(transaction), ttl_seconds)

    async def consume_oauth(self, state: str) -> OAuthTransaction | None:
        value = await self.take("oauth", state)
        return None if value is None else OAuthTransaction(**value)


state_store = RedisOneTimeStore(settings.redis_url)
