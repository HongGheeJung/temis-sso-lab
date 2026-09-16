import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import cast

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

JwksFetch = Callable[[], Awaitable[dict[str, object]]]
StatusCheck = Callable[[str, int], Awaitable[bool]]
Clock = Callable[[], float]


class HttpStatusClient:
    def __init__(self, endpoint: str, service_key: str) -> None:
        self.endpoint = endpoint
        self.service_key = service_key

    async def check(self, subject: str, version: int) -> bool:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.post(
                self.endpoint,
                json={"user_id": subject, "authz_version": version},
                headers={"X-Status-Key": self.service_key},
            )
        if response.status_code != 200:
            raise DependencyUnavailable("authorization status unavailable")
        payload = response.json()
        return bool(payload.get("active")) if isinstance(payload, dict) else False


class TokenRejected(ValueError):
    """Maps to HTTP 401 because authentication did not succeed."""


class ScopeDenied(PermissionError):
    """Maps to HTTP 403 because authentication succeeded without permission."""


class DependencyUnavailable(RuntimeError):
    """Maps to HTTP 503 because a verification dependency is unavailable."""


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    roles: frozenset[str]
    authz_version: int


class JwksVerifier:
    def __init__(
        self,
        fetch_jwks: JwksFetch,
        status_check: StatusCheck,
        *,
        issuer: str,
        audience: str,
        authorized_party: str,
        jwks_ttl: float = 300,
        jwks_stale_ttl: float = 600,
        status_ttl: float = 30,
        refresh_cooldown: float = 1,
        clock: Clock = time.monotonic,
    ) -> None:
        self.fetch_jwks = fetch_jwks
        self.status_check = status_check
        self.issuer = issuer
        self.audience = audience
        self.authorized_party = authorized_party
        self.jwks_ttl = jwks_ttl
        self.jwks_stale_ttl = jwks_stale_ttl
        self.status_ttl = status_ttl
        self.refresh_cooldown = refresh_cooldown
        self.clock = clock
        self._keys: dict[str, RSAPublicKey] = {}
        self._jwks_until = 0.0
        self._jwks_stale_until = 0.0
        self._status: dict[str, tuple[float, int]] = {}
        self._negative_kids: dict[str, float] = {}
        self._refresh_lock = asyncio.Lock()
        self._unknown_refresh_after = 0.0
        self._refresh_error_until = 0.0

    async def _refresh(self) -> None:
        document = await self.fetch_jwks()
        raw_keys = document.get("keys")
        if not isinstance(raw_keys, list):
            raise TokenRejected("invalid JWKS document")
        keys: dict[str, RSAPublicKey] = {}
        for value in raw_keys:
            if not isinstance(value, dict) or value.get("alg") != "RS256":
                continue
            kid = value.get("kid")
            if not isinstance(kid, str):
                continue
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(value))
            if isinstance(key, RSAPublicKey):
                keys[kid] = key
        if not keys:
            raise TokenRejected("JWKS has no RS256 signing keys")
        self._keys = keys
        self._jwks_until = self.clock() + self.jwks_ttl
        self._jwks_stale_until = self.clock() + self.jwks_ttl + self.jwks_stale_ttl

    async def _safe_refresh(self) -> None:
        try:
            await self._refresh()
        except TokenRejected:
            raise
        except Exception as error:
            raise DependencyUnavailable("JWKS unavailable") from error

    async def authenticate(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as error:
            raise TokenRejected("malformed bearer token") from error
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise TokenRejected("RS256 token with kid required")
        kid = cast(str, header["kid"])
        if self.clock() >= self._jwks_until:
            async with self._refresh_lock:
                if self.clock() >= self._jwks_until:
                    if self.clock() < self._refresh_error_until:
                        if kid not in self._keys or self.clock() >= self._jwks_stale_until:
                            raise DependencyUnavailable("JWKS unavailable")
                    else:
                        try:
                            await self._safe_refresh()
                            self._refresh_error_until = 0.0
                        except DependencyUnavailable:
                            self._refresh_error_until = self.clock() + self.refresh_cooldown
                            if kid not in self._keys or self.clock() >= self._jwks_stale_until:
                                raise
        key = self._keys.get(kid)
        if key is None:
            if self.clock() < self._negative_kids.get(kid, 0.0):
                raise TokenRejected("unknown signing key")
            async with self._refresh_lock:
                key = self._keys.get(kid)
                if self.clock() < self._negative_kids.get(kid, 0.0):
                    raise TokenRejected("unknown signing key")
                if self.clock() < self._refresh_error_until:
                    raise DependencyUnavailable("JWKS unavailable")
                if key is None and self.clock() >= self._unknown_refresh_after:
                    self._unknown_refresh_after = self.clock() + min(self.jwks_ttl, 30.0)
                    try:
                        await self._safe_refresh()
                        self._refresh_error_until = 0.0
                    except DependencyUnavailable:
                        self._refresh_error_until = self.clock() + self.refresh_cooldown
                        raise
                    key = self._keys.get(kid)
                if key is None:
                    self._negative_kids[kid] = self.clock() + min(self.jwks_ttl, 30.0)
                    raise TokenRejected("unknown signing key")
        try:
            claims = cast(
                dict[str, object],
                jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    issuer=self.issuer,
                    audience=self.audience,
                    options={
                        "require": ["iss", "aud", "sub", "exp", "azp", "scope", "authz_version"]
                    },
                ),
            )
        except jwt.PyJWTError as error:
            raise TokenRejected("token validation failed") from error
        subject = claims.get("sub")
        version = claims.get("authz_version")
        if (
            claims.get("aud") != self.audience
            or claims.get("azp") != self.authorized_party
            or not isinstance(subject, str)
            or not isinstance(version, int)
        ):
            raise TokenRejected("token binding is invalid")
        status = self._status.get(subject)
        if status is None or self.clock() >= status[0] or status[1] != version:
            try:
                active = await self.status_check(subject, version)
            except Exception as error:
                raise DependencyUnavailable("authorization status unavailable") from error
            if not active:
                raise TokenRejected("subject is inactive or stale")
            self._status[subject] = (self.clock() + self.status_ttl, version)
        scopes = frozenset(str(claims["scope"]).split())
        raw_roles = claims.get("https://temis.lab/roles", [])
        roles = (
            frozenset(str(role) for role in raw_roles)
            if isinstance(raw_roles, list)
            else frozenset()
        )
        return Principal(subject, scopes, roles, version)


def require_scope(principal: Principal, required: str) -> None:
    if required not in principal.scopes:
        raise ScopeDenied(f"scope required: {required}")
