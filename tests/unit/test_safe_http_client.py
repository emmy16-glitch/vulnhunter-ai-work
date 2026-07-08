"""Tests for VulnHunter's scope-bound asynchronous HTTP client."""

from collections.abc import Iterable

import httpx
import pytest

from vulnhunter.exceptions import (
    HttpMethodNotAllowedError,
    RedirectLimitExceededError,
    RequestCancelledError,
    ResponseTooLargeError,
    ScopeViolationError,
    TransportRequestError,
    UnsafeRequestHeaderError,
)
from vulnhunter.scanner import (
    CancellationToken,
    HttpClientPolicy,
    SafeHttpClient,
)
from vulnhunter.scope import validate_scoped_url, validate_target


def lab_resolver(_: str) -> Iterable[str]:
    """Return one deterministic private laboratory address."""
    return ("10.0.0.5",)


def create_target_and_url(path: str = "/app/start"):
    """Create a target and scoped URL without external DNS."""
    target = validate_target(
        "http://lab.internal:8000/app/",
        resolver=lab_resolver,
    )

    scoped_url = validate_scoped_url(
        target,
        path,
        resolver=lab_resolver,
    )

    return target, scoped_url


def test_client_policy_rejects_post_without_sending_request() -> None:
    target, scoped_url = create_target_and_url()
    request_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200, content=b"unexpected")

    transport = httpx.MockTransport(handler)

    async def run() -> None:
        async with SafeHttpClient(
            target,
            resolver=lab_resolver,
            transport=transport,
        ) as client:
            with pytest.raises(HttpMethodNotAllowedError):
                await client.request("POST", scoped_url)

    import asyncio

    asyncio.run(run())
    assert request_count == 0


@pytest.mark.asyncio
async def test_follows_only_an_in_scope_redirect() -> None:
    target, scoped_url = create_target_and_url()
    requested_paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)

        if request.url.path == "/app/start":
            return httpx.Response(
                302,
                headers={"Location": "/app/final"},
            )

        return httpx.Response(
            200,
            content=b"completed",
            headers={"Content-Type": "text/plain"},
        )

    policy = HttpClientPolicy(
        minimum_request_delay_seconds=0,
    )

    async with SafeHttpClient(
        target,
        policy=policy,
        resolver=lab_resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.request("GET", scoped_url)

    assert requested_paths == ["/app/start", "/app/final"]
    assert result.status_code == 200
    assert result.body == b"completed"
    assert result.final_url.path == "/app/final"
    assert len(result.redirects) == 1
    assert len(result.audit_events) == 2


@pytest.mark.asyncio
async def test_rejects_out_of_scope_redirect_before_second_request() -> None:
    target, scoped_url = create_target_and_url()
    request_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            302,
            headers={"Location": "/admin"},
        )

    policy = HttpClientPolicy(
        minimum_request_delay_seconds=0,
    )

    async with SafeHttpClient(
        target,
        policy=policy,
        resolver=lab_resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(
            ScopeViolationError,
            match="path boundary",
        ):
            await client.request("GET", scoped_url)

    assert request_count == 1


@pytest.mark.asyncio
async def test_enforces_redirect_limit() -> None:
    target, scoped_url = create_target_and_url()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"Location": "/app/start"},
        )

    policy = HttpClientPolicy(
        maximum_redirects=1,
        minimum_request_delay_seconds=0,
    )

    async with SafeHttpClient(
        target,
        policy=policy,
        resolver=lab_resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(
            RedirectLimitExceededError,
            match="redirect limit of 1",
        ):
            await client.request("GET", scoped_url)

        assert client.request_budget.used_requests == 2


@pytest.mark.asyncio
async def test_rejects_oversized_response() -> None:
    target, scoped_url = create_target_and_url()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"x" * 20,
        )

    policy = HttpClientPolicy(
        maximum_response_bytes=10,
        minimum_request_delay_seconds=0,
    )

    async with SafeHttpClient(
        target,
        policy=policy,
        resolver=lab_resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(ResponseTooLargeError):
            await client.request("GET", scoped_url)

        assert client.audit_events[-1].outcome == "blocked"


@pytest.mark.asyncio
async def test_cancellation_prevents_request() -> None:
    target, scoped_url = create_target_and_url()
    cancellation = CancellationToken()
    cancellation.cancel("Operator stopped the scan.")

    request_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(200)

    async with SafeHttpClient(
        target,
        resolver=lab_resolver,
        cancellation_token=cancellation,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(
            RequestCancelledError,
            match="Operator stopped",
        ):
            await client.request("GET", scoped_url)

    assert request_count == 0


@pytest.mark.asyncio
async def test_rejects_protected_host_header() -> None:
    target, scoped_url = create_target_and_url()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    async with SafeHttpClient(
        target,
        resolver=lab_resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(
            UnsafeRequestHeaderError,
            match="Host",
        ):
            await client.request(
                "GET",
                scoped_url,
                headers={"Host": "other.internal"},
            )


@pytest.mark.asyncio
async def test_wraps_network_errors_safely() -> None:
    target, scoped_url = create_target_and_url()

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "Connection refused",
            request=request,
        )

    policy = HttpClientPolicy(
        minimum_request_delay_seconds=0,
    )

    async with SafeHttpClient(
        target,
        policy=policy,
        resolver=lab_resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(
            TransportRequestError,
            match="Connection refused",
        ):
            await client.request("GET", scoped_url)

        assert client.audit_events[-1].outcome == "error"


@pytest.mark.asyncio
async def test_audit_records_redact_headers_and_url_tokens() -> None:
    target, scoped_url = create_target_and_url("/app/start?access_token=very-secret-token")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"ok",
            headers={
                "Set-Cookie": "sessionid=private-session; HttpOnly",
            },
        )

    policy = HttpClientPolicy(
        minimum_request_delay_seconds=0,
    )

    async with SafeHttpClient(
        target,
        policy=policy,
        resolver=lab_resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await client.request(
            "GET",
            scoped_url,
            headers={
                "Authorization": "Bearer private-access-token",
                "Cookie": "sessionid=private-session",
            },
        )

    event = result.audit_events[0]

    assert "very-secret-token" not in event.url
    assert event.request_headers["Authorization"] == "[REDACTED]"
    assert event.request_headers["Cookie"] == "[REDACTED]"
    assert event.response_headers["set-cookie"] == "[REDACTED]"
