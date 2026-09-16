from dataclasses import dataclass
from typing import ClassVar

from temis_sso.oauth_state import RedisOneTimeStore


@dataclass(frozen=True)
class ProviderIdentity:
    provider: str
    provider_subject: str


class FakeOAuthProvider:
    accounts: ClassVar[dict[str, ProviderIdentity]] = {
        "learner": ProviderIdentity("lab-provider", "learner-001"),
        "reviewer": ProviderIdentity("lab-provider", "reviewer-001"),
    }

    def __init__(self, store: RedisOneTimeStore) -> None:
        self.store = store

    async def authorize(self, state: str, account: str) -> str:
        identity = self.accounts.get(account)
        if identity is None:
            raise ValueError("unknown fake-provider account")
        return await self.store.put(
            "provider-code",
            {
                "state": state,
                "provider": identity.provider,
                "provider_subject": identity.provider_subject,
            },
            60,
        )

    async def exchange(self, code: str) -> dict[str, str] | None:
        return await self.store.take("provider-code", code)
