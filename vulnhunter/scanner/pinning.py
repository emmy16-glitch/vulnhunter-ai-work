"""Connection-bound DNS scope enforcement for safe HTTP requests.

The transport keeps the original URL hostname for HTTP Host routing and TLS
SNI/certificate validation while forcing the underlying TCP socket to connect
to an address that was approved immediately before the connection attempt.
"""

from __future__ import annotations

import contextvars
import ipaddress
import ssl
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Literal

import httpcore
import httpx
from pydantic import BaseModel, ConfigDict, Field

from vulnhunter.exceptions import ScopeViolationError
from vulnhunter.scope.models import ApprovedTarget
from vulnhunter.scope.validator import Resolver, system_resolver

_HTTP_CORE_EXCEPTIONS: tuple[type[Exception], ...] = (
    httpcore.TimeoutException,
    httpcore.NetworkError,
    httpcore.ProtocolError,
    httpcore.ProxyError,
    httpcore.UnsupportedProtocol,
)


class ConnectionAttempt(BaseModel):
    """One bounded TCP connection attempt to an approved address."""

    model_config = ConfigDict(frozen=True)

    address: str
    outcome: Literal["connected", "error", "blocked"]
    message: str | None = None


class ConnectionAuditEvent(BaseModel):
    """Immutable evidence for one transport-level request connection."""

    model_config = ConfigDict(frozen=True)

    occurred_at: datetime
    scheme: Literal["http", "https"]
    hostname: str
    port: int = Field(ge=1, le=65535)
    approved_addresses: tuple[str, ...]
    connection_attempts: tuple[ConnectionAttempt, ...]
    connected_address: str | None = None
    tls_server_hostname: str | None = None
    outcome: Literal["connected", "error", "blocked"]
    message: str | None = None


@dataclass(slots=True)
class _MutableConnectionPlan:
    scheme: Literal["http", "https"]
    hostname: str
    port: int
    approved_addresses: tuple[str, ...]
    attempts: list[ConnectionAttempt] = field(default_factory=list)
    connected_address: str | None = None


_ACTIVE_PLAN: contextvars.ContextVar[_MutableConnectionPlan | None] = contextvars.ContextVar(
    "vulnhunter_active_connection_plan",
    default=None,
)


def _canonical_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ScopeViolationError("DNS returned an invalid IP address.") from exc


def _canonical_addresses(values: Iterable[str]) -> tuple[str, ...]:
    addresses = tuple(sorted({_canonical_ip(value) for value in values}))
    if not addresses:
        raise ScopeViolationError("Hostname returned no usable addresses at connection time.")
    return addresses


def _effective_port(request: httpx.Request) -> int:
    if request.url.port is not None:
        return request.url.port
    return 443 if request.url.scheme == "https" else 80


def _request_hostname(request: httpx.Request) -> str:
    host = request.url.host
    if not host:
        raise ScopeViolationError("The request URL does not contain a hostname.")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host.rstrip(".").lower()


def _map_httpcore_exception(exc: Exception, request: httpx.Request) -> httpx.RequestError:
    mappings: tuple[tuple[type[Exception], type[httpx.RequestError]], ...] = (
        (httpcore.ConnectTimeout, httpx.ConnectTimeout),
        (httpcore.ReadTimeout, httpx.ReadTimeout),
        (httpcore.WriteTimeout, httpx.WriteTimeout),
        (httpcore.PoolTimeout, httpx.PoolTimeout),
        (httpcore.ConnectError, httpx.ConnectError),
        (httpcore.ReadError, httpx.ReadError),
        (httpcore.WriteError, httpx.WriteError),
        (httpcore.ProxyError, httpx.ProxyError),
        (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
        (httpcore.LocalProtocolError, httpx.LocalProtocolError),
        (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
    )
    for source_type, destination_type in mappings:
        if isinstance(exc, source_type):
            return destination_type(str(exc), request=request)
    return httpx.TransportError(str(exc), request=request)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve no names and connect only to the active approved address set."""

    def __init__(
        self,
        backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        plan = _ACTIVE_PLAN.get()
        if plan is None:
            raise httpcore.ConnectError(
                "A TCP connection was attempted without an active pinned connection plan."
            )

        normalised_host = host.rstrip(".").lower()
        if normalised_host != plan.hostname or port != plan.port:
            plan.attempts.append(
                ConnectionAttempt(
                    address=normalised_host,
                    outcome="blocked",
                    message="The transport attempted to leave the approved origin.",
                )
            )
            raise httpcore.ConnectError(
                "The transport attempted to connect outside the approved origin."
            )

        last_error: Exception | None = None
        for address in plan.approved_addresses:
            try:
                stream = await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
                plan.attempts.append(
                    ConnectionAttempt(
                        address=address,
                        outcome="error",
                        message=type(exc).__name__,
                    )
                )
                continue

            peer = stream.get_extra_info("server_addr")
            try:
                peer_address = _canonical_ip(str(peer[0]))
            except (IndexError, TypeError, ScopeViolationError):
                await stream.aclose()
                plan.attempts.append(
                    ConnectionAttempt(
                        address=address,
                        outcome="blocked",
                        message="The connected peer address could not be verified.",
                    )
                )
                last_error = httpcore.ConnectError(
                    "The connected peer address could not be verified."
                )
                continue

            if peer_address != address or peer_address not in plan.approved_addresses:
                await stream.aclose()
                plan.attempts.append(
                    ConnectionAttempt(
                        address=address,
                        outcome="blocked",
                        message="The connected peer did not match the pinned address.",
                    )
                )
                last_error = httpcore.ConnectError(
                    "The connected peer did not match the pinned address."
                )
                continue

            plan.connected_address = peer_address
            plan.attempts.append(ConnectionAttempt(address=address, outcome="connected"))
            return stream

        if last_error is None:
            last_error = httpcore.ConnectError("No approved address was available.")
        raise last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("Unix-domain sockets are not permitted by this transport.")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: Any, request: httpx.Request) -> None:
        self._stream = stream
        self._request = request

    async def __aiter__(self):
        try:
            async for part in self._stream:
                yield part
        except Exception as exc:
            if isinstance(exc, _HTTP_CORE_EXCEPTIONS):
                raise _map_httpcore_exception(exc, self._request) from exc
            raise

    async def aclose(self) -> None:
        if hasattr(self._stream, "aclose"):
            await self._stream.aclose()


class PinnedAsyncTransport(httpx.AsyncBaseTransport):
    """HTTPX transport that binds every TCP connection to approved DNS results.

    Keep-alive reuse is deliberately disabled. Each request, including every
    redirect hop, receives a fresh connection-time resolution and a new socket
    bound to that exact approved result set.
    """

    def __init__(
        self,
        target: ApprovedTarget,
        *,
        resolver: Resolver = system_resolver,
        verify_tls: bool = True,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._target = target
        self._resolver = resolver
        self._events: list[ConnectionAuditEvent] = []
        self._backend = PinnedNetworkBackend(network_backend)

        ssl_context = ssl.create_default_context()
        if not verify_tls:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=10,
            max_keepalive_connections=0,
            keepalive_expiry=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=self._backend,
        )

    @property
    def audit_events(self) -> tuple[ConnectionAuditEvent, ...]:
        return tuple(self._events)

    async def __aenter__(self) -> PinnedAsyncTransport:
        await self._pool.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        await self._pool.__aexit__(exc_type, exc_value, traceback)

    def _connection_addresses(self, hostname: str) -> tuple[str, ...]:
        try:
            direct = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                current = _canonical_addresses(self._resolver(hostname))
            except ScopeViolationError:
                raise
            except Exception as exc:
                raise ScopeViolationError("Hostname resolution failed at connection time.") from exc
        else:
            current = (str(direct),)

        approved = set(self._target.resolved_addresses)
        unexpected = set(current) - approved
        if unexpected:
            raise ScopeViolationError(
                "DNS resolution changed to an address outside the approved set at connection time."
            )
        return current

    def _validate_request(self, request: httpx.Request) -> _MutableConnectionPlan:
        scheme = request.url.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ScopeViolationError("Only HTTP and HTTPS requests are permitted.")

        hostname = _request_hostname(request)
        port = _effective_port(request)
        if (
            scheme != self._target.scheme
            or hostname != self._target.hostname
            or port != self._target.port
        ):
            raise ScopeViolationError(
                "The transport request attempted to leave the approved origin."
            )

        return _MutableConnectionPlan(
            scheme=scheme,
            hostname=hostname,
            port=port,
            approved_addresses=self._connection_addresses(hostname),
        )

    def _record_event(
        self,
        plan: _MutableConnectionPlan,
        *,
        outcome: Literal["connected", "error", "blocked"],
        message: str | None = None,
    ) -> ConnectionAuditEvent:
        event = ConnectionAuditEvent(
            occurred_at=datetime.now(UTC),
            scheme=plan.scheme,
            hostname=plan.hostname,
            port=plan.port,
            approved_addresses=plan.approved_addresses,
            connection_attempts=tuple(plan.attempts),
            connected_address=plan.connected_address,
            tls_server_hostname=plan.hostname if plan.scheme == "https" else None,
            outcome=outcome,
            message=message,
        )
        self._events.append(event)
        return event

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        plan = self._validate_request(request)
        token = _ACTIVE_PLAN.set(plan)
        try:
            core_request = httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=request.stream,
                extensions=request.extensions,
            )
            try:
                core_response = await self._pool.handle_async_request(core_request)
            except ScopeViolationError:
                self._record_event(plan, outcome="blocked", message="Scope validation failed.")
                raise
            except Exception as exc:
                outcome: Literal["error", "blocked"] = (
                    "blocked"
                    if any(attempt.outcome == "blocked" for attempt in plan.attempts)
                    else "error"
                )
                self._record_event(plan, outcome=outcome, message=type(exc).__name__)
                if isinstance(exc, _HTTP_CORE_EXCEPTIONS):
                    raise _map_httpcore_exception(exc, request) from exc
                raise

            event = self._record_event(plan, outcome="connected")
            extensions = dict(core_response.extensions)
            extensions["vulnhunter_connection_audit"] = event
            return httpx.Response(
                status_code=core_response.status,
                headers=core_response.headers,
                stream=_ResponseStream(core_response.stream, request),
                extensions=extensions,
            )
        finally:
            _ACTIVE_PLAN.reset(token)

    async def aclose(self) -> None:
        await self._pool.aclose()
