"""Tests for HTTP transport policy, cancellation, and request budgeting."""

import asyncio

import pytest
from pydantic import ValidationError

from vulnhunter.exceptions import (
    RequestBudgetExceededError,
    RequestCancelledError,
)
from vulnhunter.scanner import (
    CancellationToken,
    HttpClientPolicy,
    RequestBudget,
)


def test_http_policy_has_conservative_defaults() -> None:
    policy = HttpClientPolicy()

    assert policy.allowed_methods == ("GET", "HEAD")
    assert policy.request_timeout_seconds == 10.0
    assert policy.maximum_response_bytes == 5 * 1024 * 1024
    assert policy.maximum_redirects == 5
    assert policy.maximum_requests == 100
    assert policy.minimum_request_delay_seconds == 0.2
    assert policy.verify_tls is True


def test_http_policy_rejects_zero_request_limit() -> None:
    with pytest.raises(ValidationError):
        HttpClientPolicy(maximum_requests=0)


def test_http_policy_rejects_excessive_response_limit() -> None:
    with pytest.raises(ValidationError):
        HttpClientPolicy(
            maximum_response_bytes=51 * 1024 * 1024,
        )


def test_http_policy_rejects_duplicate_methods() -> None:
    with pytest.raises(
        ValidationError,
        match="must not contain duplicates",
    ):
        HttpClientPolicy(
            allowed_methods=("GET", "GET"),
        )


def test_http_policy_is_immutable() -> None:
    policy = HttpClientPolicy()

    with pytest.raises(ValidationError):
        policy.maximum_requests = 500


def test_cancellation_token_starts_active_false() -> None:
    token = CancellationToken()

    assert token.is_cancelled is False
    assert token.reason == "Operation cancelled."


def test_cancellation_token_raises_with_reason() -> None:
    token = CancellationToken()
    token.cancel("Emergency stop requested by operator.")

    assert token.is_cancelled is True

    with pytest.raises(
        RequestCancelledError,
        match="Emergency stop requested by operator",
    ):
        token.raise_if_cancelled()


@pytest.mark.asyncio
async def test_cancellation_wait_completes_after_cancel() -> None:
    token = CancellationToken()

    waiter = asyncio.create_task(token.wait())

    await asyncio.sleep(0)
    assert waiter.done() is False

    token.cancel("Test completed.")
    await waiter

    assert waiter.done() is True


@pytest.mark.asyncio
async def test_request_budget_tracks_usage() -> None:
    budget = RequestBudget(maximum_requests=2)

    assert budget.remaining_requests == 2

    assert await budget.consume() == 1
    assert budget.used_requests == 1
    assert budget.remaining_requests == 1

    assert await budget.consume() == 2
    assert budget.used_requests == 2
    assert budget.remaining_requests == 0


@pytest.mark.asyncio
async def test_request_budget_rejects_requests_after_limit() -> None:
    budget = RequestBudget(maximum_requests=1)

    await budget.consume()

    with pytest.raises(
        RequestBudgetExceededError,
        match="request limit of 1",
    ):
        await budget.consume()


@pytest.mark.asyncio
async def test_request_budget_is_safe_under_concurrency() -> None:
    budget = RequestBudget(maximum_requests=5)

    results = await asyncio.gather(
        *(budget.consume() for _ in range(5)),
    )

    assert sorted(results) == [1, 2, 3, 4, 5]
    assert budget.used_requests == 5

    with pytest.raises(RequestBudgetExceededError):
        await budget.consume()
