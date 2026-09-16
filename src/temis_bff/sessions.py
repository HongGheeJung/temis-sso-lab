import hashlib
import json
import secrets
from dataclasses import asdict, dataclass

from redis.asyncio import Redis


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass(frozen=True)
class BffSession:
    user_id: str
    access_token: str
    refresh_token: str
    csrf_token: str


class RedisSessionStore:
    def __init__(self, redis_url: str, ttl_seconds: int = 3600) -> None:
        self.redis_url = redis_url
        self.ttl_seconds = ttl_seconds

    async def create(self, user_id: str, access_token: str, refresh_token: str) -> str:
        session_id = secrets.token_urlsafe(32)
        session = BffSession(user_id, access_token, refresh_token, secrets.token_urlsafe(24))
        async with Redis.from_url(self.redis_url, decode_responses=True) as redis:
            await redis.set(
                f"temis-bff:session:{_digest(session_id)}",
                json.dumps(asdict(session)),
                ex=self.ttl_seconds,
            )
        return session_id

    async def get(self, session_id: str) -> BffSession | None:
        async with Redis.from_url(self.redis_url, decode_responses=True) as redis:
            raw = await redis.get(f"temis-bff:session:{_digest(session_id)}")
        return None if raw is None else BffSession(**json.loads(raw))

    async def delete(self, session_id: str) -> None:
        async with Redis.from_url(self.redis_url, decode_responses=True) as redis:
            await redis.delete(f"temis-bff:session:{_digest(session_id)}")
