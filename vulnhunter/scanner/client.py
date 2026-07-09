"""Scope-bound asynchronous HTTP transport for authorised laboratory targets."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import cast

import httpx

from vulnhunter.exceptions import (
    HttpMethodNotAllowedError,
    RequestCancelledError,
    ResponseTooLargeError,
    TransportRequestError,
    UnsafeRequestHeaderError,
)
from vulnhunter.scanner.budget import RequestBudget
from vulnhunter.scanner.cancellation import CancellationToken
from vulnhunter.scanner.models import (
    HttpAuditEvent,
    RedirectHop,
    SafeHttpResponse,
)
from vulnhunter.scanner.pinning import (
    ConnectionAuditEvent,
    PinnedAsyncTransport,
)
from vulnhunter.scanner.policy import HttpClientPolicy, HttpMethod
from vulnhunter.scanner.rate_limiter import MinimumDelayLimiter
from vulnhunter.scope.guard import validate_scoped_url
from vulnhunter.scope.models import ApprovedTarget, ScopedUrl
from vulnhunter.scope.validator import Resolver, system_resolver
from vulnhunter.security import (
    redact_headers,
    redact_text,
    redact_url,
)

AuditSink = Callable[[HttpAuditEvent], None]

_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

_PROTECTED_REQUEST_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "upgrade",
        "te",
        "trailer",
        "user-agent",
    }
)


class SafeHttpClient:
    """Send bounded GET and HEAD requests only within one approved scope."""

    def __init__(
        self,
        target: ApprovedTarget,
        *,
        policy: HttpClientPolicy | None = None,
        resolver: Resolver = system_resolver,
        cancellation_token: CancellationToken | None = None,
        request_budget: RequestBudget | None = None,
        rate_limiter: MinimumDelayLimiter | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self._target = target
        self._policy = policy or HttpClientPolicy()
        self._resolver = resolver
        self._cancellation = cancellation_token or CancellationToken()

        self._budget = request_budget or RequestBudget(
            maximum_requests=self._policy.maximum_requests
        )

        self._rate_limiter = rate_limiter or MinimumDelayLimiter(
            self._policy.minimum_request_delay_seconds
        )

        self._audit_sink = audit_sink
        self._audit_events: list[HttpAuditEvent] = []

        if transport is None:
            transport = PinnedAsyncTransport(
                target,
                resolver=resolver,
                verify_tls=self._policy.verify_tls,
            )
        self._pinned_transport = transport if isinstance(transport, PinnedAsyncTransport) else None

        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(self._policy.request_timeout_seconds),
            verify=self._policy.verify_tls,
            follow_redirects=False,
            trust_env=False,
        )

    async def __aenter__(self) -> SafeHttpClient:
        """Return the open client inside an asynchronous context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        """Close network resources when leaving the context."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    @property
    def audit_events(self) -> tuple[HttpAuditEvent, ...]:
        """Return immutable access to sanitised audit events."""
        return tuple(self._audit_events)

    @property
    def request_budget(self) -> RequestBudget:
        """Expose request-budget statistics without replacing the budget."""
        return self._budget

    def _emit_audit_event(self, event: HttpAuditEvent) -> None:
        """Record one sanitised audit event."""
        self._audit_events.append(event)

        if self._audit_sink is not None:
            self._audit_sink(event)

    def _validate_method(self, method: str) -> HttpMethod:
        """Normalise and enforce the configured read-only HTTP methods."""
        normalised = method.strip().upper()

        if normalised not in self._policy.allowed_methods:
            raise HttpMethodNotAllowedError(
                f"HTTP method {normalised or '<empty>'} is not permitted. "
                "Only configured read-only methods may be used."
            )

        return cast(HttpMethod, normalised)

    def _prepare_headers(
        self,
        headers: Mapping[str, str] | None,
    ) -> dict[str, str]:
        """Build request headers without allowing transport overrides."""
        prepared = {
            "User-Agent": self._policy.user_agent,
        }

        for name, value in (headers or {}).items():
            normalised_name = name.strip().lower()

            if normalised_name in _PROTECTED_REQUEST_HEADERS:
                raise UnsafeRequestHeaderError(
                    f"The protected HTTP header {name!r} cannot be overridden."
                )

            prepared[str(name)] = str(value)

        return prepared

    async def _read_limited_body(
        self,
        response: httpx.Response,
    ) -> bytes:
        """Read a response without exceeding the configured memory limit."""
        maximum_bytes = self._policy.maximum_response_bytes
        content_length = response.headers.get("content-length")

        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = None

            if declared_size is not None and declared_size > maximum_bytes:
                raise ResponseTooLargeError(
                    "The response Content-Length exceeds the configured "
                    f"limit of {maximum_bytes} bytes."
                )

        chunks: list[bytes] = []
        total_bytes = 0

        async for chunk in response.aiter_bytes():
            self._cancellation.raise_if_cancelled()

            total_bytes += len(chunk)

            if total_bytes > maximum_bytes:
                raise ResponseTooLargeError(
                    f"The streamed response exceeded the configured limit of {maximum_bytes} bytes."
                )

            chunks.append(chunk)

        return b"".join(chunks)

    async def request(
        self,
        method: str,
        scoped_url: ScopedUrl,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> SafeHttpResponse:
        """Send one controlled request, manually validating every redirect."""
        approved_method = self._validate_method(method)
        request_headers = self._prepare_headers(headers)
        safe_request_headers = redact_headers(request_headers)

        current_url = validate_scoped_url(
            self._target,
            scoped_url.url,
            resolver=self._resolver,
        )

        redirects: list[RedirectHop] = []
        request_events: list[HttpAuditEvent] = []
        total_elapsed_ms = 0.0

        while True:
            self._cancellation.raise_if_cancelled()

            await self._rate_limiter.wait()

            self._cancellation.raise_if_cancelled()
            request_number = await self._budget.consume()

            started_at = time.perf_counter()
            response_status: int | None = None
            safe_response_headers: dict[str, str] = {}

            try:
                async with self._client.stream(
                    approved_method,
                    current_url.url,
                    headers=request_headers,
                ) as response:
                    response_status = response.status_code
                    safe_response_headers = redact_headers(dict(response.headers))

                    body = await self._read_limited_body(response)
                    redirect_location = response.headers.get("location")

            except (RequestCancelledError, ResponseTooLargeError) as exc:
                elapsed_ms = (time.perf_counter() - started_at) * 1000

                event = HttpAuditEvent(
                    timestamp=datetime.now(UTC),
                    request_number=request_number,
                    method=approved_method,
                    url=redact_url(current_url.url),
                    outcome="blocked",
                    status_code=response_status,
                    elapsed_ms=elapsed_ms,
                    request_headers=safe_request_headers,
                    response_headers=safe_response_headers,
                    message=redact_text(str(exc)),
                )

                self._emit_audit_event(event)
                request_events.append(event)
                raise

            except httpx.HTTPError as exc:
                elapsed_ms = (time.perf_counter() - started_at) * 1000
                safe_message = redact_text(str(exc))

                event = HttpAuditEvent(
                    timestamp=datetime.now(UTC),
                    request_number=request_number,
                    method=approved_method,
                    url=redact_url(current_url.url),
                    outcome="error",
                    status_code=response_status,
                    elapsed_ms=elapsed_ms,
                    request_headers=safe_request_headers,
                    response_headers=safe_response_headers,
                    message=safe_message,
                )

                self._emit_audit_event(event)
                request_events.append(event)

                raise TransportRequestError(f"HTTP request failed safely: {safe_message}") from exc

            elapsed_ms = (time.perf_counter() - started_at) * 1000
            total_elapsed_ms += elapsed_ms

            event = HttpAuditEvent(
                timestamp=datetime.now(UTC),
                request_number=request_number,
                method=approved_method,
                url=redact_url(current_url.url),
                outcome="response",
                status_code=response_status,
                response_bytes=len(body),
                elapsed_ms=elapsed_ms,
                request_headers=safe_request_headers,
                response_headers=safe_response_headers,
            )

            self._emit_audit_event(event)
            request_events.append(event)

            if response_status in _REDIRECT_STATUS_CODES and redirect_location is not None:
                if len(redirects) >= self._policy.maximum_redirects:
                    from vulnhunter.exceptions import (
                        RedirectLimitExceededError,
                    )

                    raise RedirectLimitExceededError(
                        "The response exceeded the configured redirect "
                        f"limit of {self._policy.maximum_redirects}."
                    )

                next_url = validate_scoped_url(
                    self._target,
                    redirect_location,
                    base_url=current_url.url,
                    resolver=self._resolver,
                )

                redirects.append(
                    RedirectHop(
                        from_url=redact_url(current_url.url),
                        to_url=redact_url(next_url.url),
                        status_code=response_status,
                    )
                )

                current_url = next_url
                continue

            return SafeHttpResponse(
                method=approved_method,
                final_url=current_url,
                status_code=response_status,
                headers=safe_response_headers,
                body=body,
                elapsed_ms=total_elapsed_ms,
                redirects=tuple(redirects),
                audit_events=tuple(request_events),
            )

    @property
    def connection_pinning_enabled(self) -> bool:
        """Return whether the live client uses connection-bound DNS pinning."""
        return self._pinned_transport is not None

    @property
    def connection_audit_events(self) -> tuple[ConnectionAuditEvent, ...]:
        """Return immutable transport-level connection evidence."""
        if self._pinned_transport is None:
            return ()
        return self._pinned_transport.audit_events
