import asyncio

import httpx
import pytest

from temis_sso.external_idp.naver import NaverAdapter
from temis_sso.external_idp.security import FlowStore


def adapter_with(handler: object) -> tuple[NaverAdapter, httpx.AsyncClient]:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return NaverAdapter("local-naver-client", "local-naver-secret", client), client


def test_naver_uses_oauth_endpoints_without_oidc_discovery() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2.0/token":
            return httpx.Response(
                200, json={"access_token": "naver-access", "token_type": "bearer"}
            )
        raise AssertionError(f"unexpected endpoint: {request.url.path}")

    async def scenario() -> str:
        adapter, client = adapter_with(handler)
        flow = FlowStore().issue(
            "https://client.lab.invalid/callback",
            now=100,
            browser_binding="browser-binding-123",
        )
        request = adapter.authorization_request(flow)
        assert request.url == "https://nid.naver.com/oauth2.0/authorize"
        assert request.parameters["state"] == flow.state
        async with client:
            return await adapter.exchange_code("code-1", "state-1")

    assert asyncio.run(scenario()) == "naver-access"


def test_naver_maps_nested_response_id_with_conservative_email_status() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer naver-access"
        return httpx.Response(
            200,
            json={
                "resultcode": "00",
                "message": "success",
                "response": {"id": "naver-42", "email": "learner@lab.invalid"},
            },
        )

    async def scenario() -> tuple[str, str | None, bool]:
        adapter, client = adapter_with(handler)
        async with client:
            identity = await adapter.fetch_identity("naver-access")
            return identity.subject, identity.email, identity.email_verified

    assert asyncio.run(scenario()) == ("naver-42", "learner@lab.invalid", False)


def test_naver_allows_missing_email_but_requires_response_id() -> None:
    responses = iter(
        [
            httpx.Response(200, json={"resultcode": "00", "response": {"id": "naver-42"}}),
            httpx.Response(
                200,
                json={"resultcode": "00", "response": {"email": "learner@lab.invalid"}},
            ),
        ]
    )

    async def handler(_: httpx.Request) -> httpx.Response:
        return next(responses)

    async def scenario() -> None:
        adapter, client = adapter_with(handler)
        async with client:
            identity = await adapter.fetch_identity("naver-access")
            assert identity.email is None and not identity.email_verified
            with pytest.raises(ValueError, match="response.id"):
                await adapter.fetch_identity("naver-access")

    asyncio.run(scenario())


def test_naver_rejects_provider_error_envelope() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"resultcode": "024", "message": "authentication failed"})

    async def scenario() -> None:
        adapter, client = adapter_with(handler)
        async with client:
            await adapter.fetch_identity("bad-token")

    with pytest.raises(ValueError, match="provider rejected"):
        asyncio.run(scenario())


def test_naver_revoke_uses_dedicated_endpoint_and_client_auth() -> None:
    captured: dict[str, str] = {}
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        assert not request.url.query
        captured.update(dict(httpx.QueryParams(request.content.decode())))
        return httpx.Response(200)

    async def scenario() -> bool:
        adapter, client = adapter_with(handler)
        async with client:
            return await adapter.revoke("naver-access")

    assert asyncio.run(scenario())
    assert paths == ["/oauth2.0/revoke"]
    assert captured["client_id"] == "local-naver-client"
    assert captured["client_secret"] == "local-naver-secret"
    assert captured["token"] == "naver-access"
    assert captured["token_type_hint"] == "access_token"


def test_naver_transport_failure_fails_closed() -> None:
    async def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("provider unavailable")

    async def scenario() -> None:
        adapter, client = adapter_with(handler)
        async with client:
            await adapter.exchange_code("code-1", "state-1")

    with pytest.raises(httpx.ConnectError):
        asyncio.run(scenario())
