from __future__ import annotations

import json
import logging
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.http import JsonResponse
from django.test import Client, RequestFactory
from django.urls import resolve

from vulnhunter.web import readiness
from vulnhunter.web.observability import (
    RequestCorrelationMiddleware,
    request_log_record,
    trusted_request_id,
)
from vulnhunter.web.readiness import ReadinessReport


def test_trusted_request_id_accepts_only_bounded_safe_values() -> None:
    trusted = "deploy-check_2026-08-01"
    assert trusted_request_id(trusted) == trusted

    generated = trusted_request_id("bad value\nX-Forged: yes")
    assert len(generated) == 32
    assert generated.isalnum()
    assert generated != trusted


def test_request_log_record_contains_no_path_query_or_body() -> None:
    request = RequestFactory().post(
        "/workspace/message/?token=secret-query",
        data={"message": "secret-body"},
    )
    record = request_log_record(
        request,
        request_id="request-safe-001",
        status_code=202,
        duration_ms=18,
    )
    encoded = json.dumps(record)

    assert record == {
        "duration_ms": 18,
        "event": "http_request",
        "method": "POST",
        "outcome": "completed",
        "request_id": "request-safe-001",
        "route": "unmatched",
        "status": 202,
    }
    assert "secret-query" not in encoded
    assert "secret-body" not in encoded
    assert "/workspace/message/" not in encoded


def test_request_middleware_preserves_valid_id_and_emits_safe_json(caplog) -> None:
    request = RequestFactory().get("/health/?api_key=must-not-log")
    request.META["HTTP_X_REQUEST_ID"] = "phone-health-001"
    middleware = RequestCorrelationMiddleware(
        lambda incoming: JsonResponse({"status": "ok"}, status=200)
    )

    with caplog.at_level(logging.INFO, logger="vulnhunter.web.requests"):
        response = middleware(request)

    assert response["X-Request-ID"] == "phone-health-001"
    record = json.loads(caplog.records[-1].message)
    assert record["request_id"] == "phone-health-001"
    assert record["status"] == 200
    assert "api_key" not in caplog.records[-1].message
    assert "must-not-log" not in caplog.records[-1].message


def test_application_health_response_receives_generated_request_id() -> None:
    response = Client().get("/health/", HTTP_X_REQUEST_ID="invalid request id")

    assert response.status_code == 200
    assert len(response["X-Request-ID"]) == 32
    assert response["X-Request-ID"].isalnum()


def test_ready_route_uses_the_shared_readiness_service() -> None:
    match = resolve("/ready/")
    assert match.func is readiness.deployment_readiness_view


def test_shared_readiness_http_payload_preserves_existing_contract(monkeypatch) -> None:
    monkeypatch.setattr(
        readiness,
        "deployment_readiness",
        lambda: ReadinessReport(configuration=True, database=True, agent_store=True),
    )
    response = readiness.deployment_readiness_view(RequestFactory().get("/ready/"))

    assert response.status_code == 200
    assert json.loads(response.content) == {
        "status": "ready",
        "checks": {
            "configuration": "ok",
            "database": "ok",
            "agent_store": "ok",
        },
    }


def test_shared_readiness_http_returns_503_when_one_check_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        readiness,
        "deployment_readiness",
        lambda: ReadinessReport(configuration=True, database=False, agent_store=True),
    )
    response = readiness.deployment_readiness_view(RequestFactory().get("/ready/"))

    assert response.status_code == 503
    assert json.loads(response.content)["checks"]["database"] == "failed"


def test_deployment_preflight_prints_safe_json_and_succeeds(monkeypatch) -> None:
    from vulnhunter.web.management.commands import vh_deployment_preflight

    monkeypatch.setattr(
        vh_deployment_preflight,
        "deployment_readiness",
        lambda: ReadinessReport(configuration=True, database=True, agent_store=True),
    )
    stdout = StringIO()
    call_command("vh_deployment_preflight", stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert payload["status"] == "ready"
    assert set(payload["checks"]) == {"configuration", "database", "agent_store"}


def test_deployment_preflight_exits_nonzero_when_unready(monkeypatch) -> None:
    from vulnhunter.web.management.commands import vh_deployment_preflight

    monkeypatch.setattr(
        vh_deployment_preflight,
        "deployment_readiness",
        lambda: ReadinessReport(configuration=False, database=True, agent_store=True),
    )
    stdout = StringIO()

    with pytest.raises(CommandError, match="deployment readiness checks failed"):
        call_command("vh_deployment_preflight", stdout=stdout)

    payload = json.loads(stdout.getvalue())
    assert payload["status"] == "unready"
    assert payload["checks"]["configuration"] == "failed"
