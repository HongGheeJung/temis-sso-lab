import asyncio
import base64
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from resource_api.app import create_resource_app
from resource_api.auth import (
    DependencyUnavailable,
    JwksVerifier,
    ScopeDenied,
    TokenRejected,
    require_scope,
)
from temis_sso.api.auth import issue_bundle
from temis_sso.persistence import UserRepository, UserRole, session_scope
from temis_sso.tokens import AUDIENCE, ISSUER, codec


def token(**overrides: object) -> str:
    return codec.issue_access(
        str(overrides.get("user_id", "user-1")),
        roles=["temis:user"],
        audience=str(overrides.get("audience", AUDIENCE)),
        client_id=str(overrides.get("client_id", "temis-web")),
        scopes=list(overrides.get("scopes", ["reports:read"])),
        authz_version=int(overrides.get("authz_version", 7)),
    )


def verifier(
    clock: Callable[[], float] = lambda: 0.0,
) -> tuple[JwksVerifier, list[tuple[str, int]], list[int]]:
    status_calls: list[tuple[str, int]] = []
    jwks_calls: list[int] = []

    async def fetch() -> dict[str, object]:
        jwks_calls.append(1)
        return {"keys": [codec.jwk()]}

    async def status(subject: str, version: int) -> bool:
        status_calls.append((subject, version))
        return subject == "user-1" and version == 7

    return (
        JwksVerifier(
            fetch,
            status,
            issuer=ISSUER,
            audience=AUDIENCE,
            authorized_party="temis-web",
            clock=clock,
        ),
        status_calls,
        jwks_calls,
    )


@pytest.mark.asyncio
async def test_exact_token_binding_scope_and_namespaced_role() -> None:
    checked, _, _ = verifier()
    principal = await checked.authenticate(token())
    assert principal.roles == {"temis:user"} and principal.authz_version == 7
    require_scope(principal, "reports:read")
    with pytest.raises(ScopeDenied):
        require_scope(principal, "reports:write")
    for invalid in [token(audience="other-api"), token(client_id="other-client")]:
        with pytest.raises(TokenRejected):
            await checked.authenticate(invalid)


@pytest.mark.asyncio
async def test_unknown_kid_refreshes_once_then_returns_401_semantics() -> None:
    checked, _, calls = verifier()
    other = codec.issue_access("user-1")
    _, payload, signature = other.split(".")
    altered = (
        base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": "unknown"}).encode())
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(TokenRejected):
        await checked.authenticate(f"{altered}.{payload}.{signature}")
    assert len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("same_kid", [True, False])
async def test_concurrent_unknown_kids_share_one_forced_refresh(same_kid: bool) -> None:
    checked, _, calls = verifier()
    await checked.authenticate(token())

    def unknown(value: int) -> str:
        _, payload, signature = token().split(".")
        kid = "same-unknown" if same_kid else f"unknown-{value}"
        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "kid": kid}).encode())
            .rstrip(b"=")
            .decode()
        )
        return f"{header}.{payload}.{signature}"

    results = await asyncio.gather(
        *(checked.authenticate(unknown(index)) for index in range(20)),
        return_exceptions=True,
    )
    assert all(isinstance(result, TokenRejected) for result in results)
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_status_cache_is_bounded_and_version_change_rechecks() -> None:
    now = [0.0]
    checked, status_calls, _ = verifier(lambda: now[0])
    await checked.authenticate(token())
    await checked.authenticate(token())
    assert len(status_calls) == 1
    now[0] = 31.0
    await checked.authenticate(token())
    assert len(status_calls) == 2
    with pytest.raises(TokenRejected):
        await checked.authenticate(token(authz_version=8))


def test_http_boundary_distinguishes_401_and_403() -> None:
    checked, _, _ = verifier()
    client = TestClient(create_resource_app(checked))
    assert client.get("/api/reports").status_code == 401
    response = client.get(
        "/api/reports",
        headers={"Authorization": f"Bearer {token(scopes=['profile:read'])}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_real_issue_bundle_carries_database_authorization_state() -> None:
    async with session_scope() as session:
        user = await UserRepository(session).create(f"{uuid.uuid4().hex}@mail.test")
        user.status = "active"
        user.authz_version = 9
        session.add(UserRole(user_id=user.id, role="user"))
        user_id = user.id
    bundle = await issue_bundle(user_id)
    claims = codec.verify_access(bundle.access_token)
    assert claims["authz_version"] == 9
    assert claims["https://temis.lab/roles"] == ["temis:user"]
    assert "reports:read" in str(claims["scope"])


def custom_token(**changes: object) -> str:
    import jwt

    claims = jwt.decode(token(), options={"verify_signature": False})
    for key, value in changes.items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    ring = getattr(codec, "ring", None)
    if ring is not None:
        return ring.sign_claims(claims)
    return jwt.encode(claims, codec._private_key, algorithm="RS256", headers={"kid": codec.kid})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://wrong.invalid"},
        {"aud": [AUDIENCE, "other-api"]},
        {"exp": datetime.now(UTC) - timedelta(seconds=1)},
        {"nbf": datetime.now(UTC) + timedelta(minutes=5)},
        {"scope": None},
        {"azp": None},
    ],
)
async def test_adversarial_claims_are_rejected(changes: dict[str, object]) -> None:
    checked, _, _ = verifier()
    with pytest.raises(TokenRejected):
        await checked.authenticate(custom_token(**changes))


@pytest.mark.asyncio
async def test_dependency_outage_is_distinct_and_cached_jwks_can_bridge_briefly() -> None:
    now = [0.0]
    online = [True]

    async def fetch() -> dict[str, object]:
        if not online[0]:
            raise ConnectionError("offline")
        return {"keys": [codec.jwk()]}

    async def status(subject: str, version: int) -> bool:
        return True

    checked = JwksVerifier(
        fetch,
        status,
        issuer=ISSUER,
        audience=AUDIENCE,
        authorized_party="temis-web",
        jwks_ttl=1,
        jwks_stale_ttl=5,
        status_ttl=60,
        clock=lambda: now[0],
    )
    assert (await checked.authenticate(token())).subject == "user-1"
    online[0] = False
    now[0] = 2
    assert (await checked.authenticate(token())).subject == "user-1"
    now[0] = 7
    with pytest.raises(DependencyUnavailable):
        await checked.authenticate(token())


@pytest.mark.asyncio
async def test_inactive_status_and_status_outage_fail_closed() -> None:
    async def fetch() -> dict[str, object]:
        return {"keys": [codec.jwk()]}

    async def inactive(subject: str, version: int) -> bool:
        return False

    async def outage(subject: str, version: int) -> bool:
        raise ConnectionError("status offline")

    for check, error in [(inactive, TokenRejected), (outage, DependencyUnavailable)]:
        verified = JwksVerifier(
            fetch,
            check,
            issuer=ISSUER,
            audience=AUDIENCE,
            authorized_party="temis-web",
        )
        with pytest.raises(error):
            await verified.authenticate(token())


@pytest.mark.asyncio
async def test_none_hmac_and_malformed_tokens_are_rejected_before_key_use() -> None:
    import jwt

    checked, _, _ = verifier()
    claims = {"sub": "user-1", "exp": datetime.now(UTC) + timedelta(minutes=5)}
    attacks = [
        "not-a-jwt",
        jwt.encode(claims, key="", algorithm="none", headers={"kid": codec.kid}),
        jwt.encode(claims, key="attacker-secret", algorithm="HS256", headers={"kid": codec.kid}),
    ]
    for attack in attacks:
        with pytest.raises(TokenRejected):
            await checked.authenticate(attack)
