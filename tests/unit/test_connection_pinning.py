from __future__ import annotations

import asyncio
from collections.abc import Iterable
from typing import Any

import httpcore
import httpx
import pytest

from vulnhunter.exceptions import ScopeViolationError
from vulnhunter.scanner import HttpClientPolicy, SafeHttpClient
from vulnhunter.scanner.pinning import PinnedAsyncTransport
from vulnhunter.scope.guard import validate_scoped_url
from vulnhunter.scope.models import ApprovedTarget
from vulnhunter.scope.validator import validate_target


class ScriptedStream(httpcore.AsyncNetworkStream):
    def __init__(self, peer: tuple[Any, ...], response: bytes = b"") -> None:
        self.peer = peer
        self.response = response
        self.writes: list[bytes] = []
        self.closed = False
        self.tls_server_hostname: str | None = None

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self.response:
            chunk = self.response[:max_bytes]
            self.response = self.response[max_bytes:]
            return chunk
        return b""

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.writes.append(buffer)

    async def aclose(self) -> None:
        self.closed = True

    async def start_tls(
        self,
        ssl_context,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.tls_server_hostname = server_hostname
        return self

    def get_extra_info(self, info: str) -> Any:
        if info == "server_addr":
            return self.peer
        if info == "is_readable":
            return False
        return None


class ScriptedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, outcomes: dict[str, ScriptedStream | Exception]) -> None:
        self.outcomes = outcomes
        self.connect_hosts: list[str] = []
        self.streams: list[ScriptedStream] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.connect_hosts.append(host)
        outcome = self.outcomes[host]
        if isinstance(outcome, Exception):
            raise outcome
        self.streams.append(outcome)
        return outcome

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise AssertionError("unix sockets must never be used")

    async def sleep(self, seconds: float) -> None:
        return None


def target(
    *,
    scheme: str = "http",
    hostname: str = "lab.internal",
    port: int = 8000,
    addresses: tuple[str, ...] = ("10.0.0.5",),
) -> ApprovedTarget:
    return ApprovedTarget(
        original_url=f"{scheme}://{hostname}:{port}/app/",
        normalized_url=f"{scheme}://{hostname}:{port}/app/",
        scheme=scheme,
        hostname=hostname,
        port=port,
        path="/app/",
        resolved_addresses=addresses,
    )


def response_bytes(body: bytes = b"ok") -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )


@pytest.mark.asyncio
async def test_transport_connects_to_pinned_ip_and_preserves_host_header() -> None:
    stream = ScriptedStream(("10.0.0.5", 8000), response_bytes())
    backend = ScriptedBackend({"10.0.0.5": stream})
    transport = PinnedAsyncTransport(
        target(),
        resolver=lambda _: ("10.0.0.5",),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get("http://lab.internal:8000/app/status")

    assert response.text == "ok"
    assert backend.connect_hosts == ["10.0.0.5"]
    request_bytes = b"".join(stream.writes).lower()
    assert b"host: lab.internal:8000\r\n" in request_bytes
    event = transport.audit_events[-1]
    assert event.connected_address == "10.0.0.5"
    assert event.outcome == "connected"


@pytest.mark.asyncio
async def test_https_preserves_original_hostname_for_tls_sni() -> None:
    stream = ScriptedStream(("10.0.0.5", 443), response_bytes())
    backend = ScriptedBackend({"10.0.0.5": stream})
    transport = PinnedAsyncTransport(
        target(scheme="https", port=443),
        resolver=lambda _: ("10.0.0.5",),
        verify_tls=False,
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get("https://lab.internal/app/status")

    assert response.status_code == 200
    assert stream.tls_server_hostname == "lab.internal"
    assert transport.audit_events[-1].tls_server_hostname == "lab.internal"


@pytest.mark.asyncio
async def test_connection_time_dns_change_is_blocked_before_tcp() -> None:
    backend = ScriptedBackend({})
    transport = PinnedAsyncTransport(
        target(),
        resolver=lambda _: ("10.0.0.99",),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(ScopeViolationError, match="connection time"):
            await client.get("http://lab.internal:8000/app/status")

    assert backend.connect_hosts == []


@pytest.mark.asyncio
async def test_backend_retries_only_addresses_in_approved_set() -> None:
    stream = ScriptedStream(("10.0.0.6", 8000), response_bytes())
    backend = ScriptedBackend(
        {
            "10.0.0.5": httpcore.ConnectError("refused"),
            "10.0.0.6": stream,
        }
    )
    transport = PinnedAsyncTransport(
        target(addresses=("10.0.0.5", "10.0.0.6")),
        resolver=lambda _: ("10.0.0.6", "10.0.0.5"),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get("http://lab.internal:8000/app/status")

    assert response.status_code == 200
    assert backend.connect_hosts == ["10.0.0.5", "10.0.0.6"]
    attempts = transport.audit_events[-1].connection_attempts
    assert [attempt.outcome for attempt in attempts] == ["error", "connected"]


@pytest.mark.asyncio
async def test_peer_address_mismatch_is_blocked() -> None:
    stream = ScriptedStream(("10.0.0.99", 8000), response_bytes())
    backend = ScriptedBackend({"10.0.0.5": stream})
    transport = PinnedAsyncTransport(
        target(),
        resolver=lambda _: ("10.0.0.5",),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(httpx.ConnectError, match="pinned address"):
            await client.get("http://lab.internal:8000/app/status")

    assert stream.closed is True
    assert transport.audit_events[-1].outcome == "blocked"


@pytest.mark.asyncio
async def test_direct_ip_target_does_not_call_resolver() -> None:
    stream = ScriptedStream(("127.0.0.1", 8000), response_bytes())
    backend = ScriptedBackend({"127.0.0.1": stream})

    def resolver(_: str):
        raise AssertionError("direct IP targets must not be resolved")

    transport = PinnedAsyncTransport(
        target(hostname="127.0.0.1", addresses=("127.0.0.1",)),
        resolver=resolver,
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get("http://127.0.0.1:8000/app/status")

    assert response.status_code == 200
    assert backend.connect_hosts == ["127.0.0.1"]


@pytest.mark.asyncio
async def test_ipv6_address_is_pinned_and_peer_verified() -> None:
    stream = ScriptedStream(("::1", 8000, 0, 0), response_bytes())
    backend = ScriptedBackend({"::1": stream})
    transport = PinnedAsyncTransport(
        target(hostname="::1", addresses=("::1",)),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get("http://[::1]:8000/app/status")

    assert response.status_code == 200
    assert transport.audit_events[-1].connected_address == "::1"


@pytest.mark.asyncio
async def test_wrong_origin_is_blocked_before_tcp() -> None:
    backend = ScriptedBackend({})
    transport = PinnedAsyncTransport(
        target(),
        resolver=lambda _: ("10.0.0.5",),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(ScopeViolationError, match="approved origin"):
            await client.get("http://other.internal:8000/app/status")

    assert backend.connect_hosts == []


@pytest.mark.asyncio
async def test_empty_connection_time_resolution_is_blocked() -> None:
    backend = ScriptedBackend({})
    transport = PinnedAsyncTransport(
        target(),
        resolver=lambda _: (),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        with pytest.raises(ScopeViolationError, match="no usable addresses"):
            await client.get("http://lab.internal:8000/app/status")

    assert backend.connect_hosts == []


@pytest.mark.asyncio
async def test_keepalive_reuse_is_disabled_for_independent_pinning() -> None:
    first = ScriptedStream(("10.0.0.5", 8000), response_bytes(b"one"))
    second = ScriptedStream(("10.0.0.5", 8000), response_bytes(b"two"))

    class RotatingBackend(ScriptedBackend):
        def __init__(self) -> None:
            super().__init__({})
            self.queue = [first, second]

        async def connect_tcp(self, host: str, port: int, **kwargs):
            self.connect_hosts.append(host)
            stream = self.queue.pop(0)
            self.streams.append(stream)
            return stream

    backend = RotatingBackend()
    transport = PinnedAsyncTransport(
        target(),
        resolver=lambda _: ("10.0.0.5",),
        network_backend=backend,
    )

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        one = await client.get("http://lab.internal:8000/app/one")
        two = await client.get("http://lab.internal:8000/app/two")

    assert one.text == "one"
    assert two.text == "two"
    assert backend.connect_hosts == ["10.0.0.5", "10.0.0.5"]
    assert len(transport.audit_events) == 2


@pytest.mark.asyncio
async def test_safe_http_client_enables_pinning_by_default() -> None:
    def resolved(_: str) -> tuple[str, ...]:
        return ("10.0.0.5",)

    approved = validate_target(
        "http://lab.internal:8000/app/",
        resolver=resolved,
    )

    async with SafeHttpClient(
        approved,
        policy=HttpClientPolicy(minimum_request_delay_seconds=0),
        resolver=resolved,
    ) as client:
        assert client.connection_pinning_enabled is True
        assert client.connection_audit_events == ()


@pytest.mark.asyncio
async def test_safe_http_client_exposes_connection_evidence() -> None:
    def resolved(_: str) -> tuple[str, ...]:
        return ("10.0.0.5",)

    approved = validate_target(
        "http://lab.internal:8000/app/",
        resolver=resolved,
    )
    scoped = validate_scoped_url(
        approved,
        "/app/status",
        resolver=resolved,
    )
    stream = ScriptedStream(("10.0.0.5", 8000), response_bytes())
    backend = ScriptedBackend({"10.0.0.5": stream})
    transport = PinnedAsyncTransport(
        approved,
        resolver=resolved,
        network_backend=backend,
    )

    async with SafeHttpClient(
        approved,
        policy=HttpClientPolicy(minimum_request_delay_seconds=0),
        resolver=resolved,
        transport=transport,
    ) as client:
        result = await client.request("GET", scoped)
        events = client.connection_audit_events

    assert result.body == b"ok"
    assert len(events) == 1
    assert events[0].connected_address == "10.0.0.5"


@pytest.mark.asyncio
async def test_default_transport_uses_real_loopback_socket() -> None:
    received = bytearray()

    async def handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        received.extend(await reader.readuntil(b"\r\n\r\n"))
        writer.write(response_bytes(b"loopback"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    approved = validate_target(f"http://127.0.0.1:{port}/app/")
    scoped = validate_scoped_url(approved, "/app/status")

    try:
        async with SafeHttpClient(
            approved,
            policy=HttpClientPolicy(minimum_request_delay_seconds=0),
        ) as client:
            result = await client.request("GET", scoped)
            events = client.connection_audit_events
    finally:
        server.close()
        await server.wait_closed()

    assert result.body == b"loopback"
    assert b"host: 127.0.0.1:" in bytes(received).lower()
    assert events[-1].connected_address == "127.0.0.1"
