import hashlib
import re
import secrets
from base64 import urlsafe_b64encode

from temis_sso.external_idp.models import ExternalFlow


def _token() -> str:
    return secrets.token_urlsafe(32)


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return urlsafe_b64encode(digest).rstrip(b"=").decode()


class FlowStore:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._flows: dict[str, ExternalFlow] = {}

    def issue(self, redirect_uri: str, now: int, browser_binding: str) -> ExternalFlow:
        if re.fullmatch(r"[A-Za-z0-9_-]{16,128}", browser_binding) is None:
            raise ValueError("browser binding format is invalid")
        verifier = _token()
        flow = ExternalFlow(
            state=_token(),
            nonce=_token(),
            code_verifier=verifier,
            code_challenge=_s256(verifier),
            redirect_uri=redirect_uri,
            created_at=now,
            browser_binding=browser_binding,
        )
        self._flows[flow.state] = flow
        return flow

    def consume(self, state: str, now: int, browser_binding: str) -> ExternalFlow:
        if re.fullmatch(r"[A-Za-z0-9_-]{16,128}", browser_binding) is None:
            raise ValueError("browser binding format is invalid")
        flow = self._flows.get(state)
        if flow is None:
            raise ValueError("unknown or already used state")
        if now - flow.created_at > self.ttl_seconds:
            raise ValueError("expired state")
        if flow.browser_binding != browser_binding:
            raise ValueError("state browser binding mismatch")
        del self._flows[state]
        return flow
