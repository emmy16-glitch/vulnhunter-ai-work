from __future__ import annotations

import inspect
import json
from types import SimpleNamespace

from vulnhunter.web import conversation_mobile_retry_views as views
from vulnhunter.web.mobile_retry import MobileRetryError


class _Session(dict):
    modified = False


class _Post(dict):
    def get(self, key: str, default: object = None):
        return super().get(key, default)


def _request(*, method: str = "POST", **post):
    return SimpleNamespace(
        method=method,
        POST=_Post(post),
        session=_Session(),
        get_full_path=lambda: "/conversation/mobile/retry/",
    )


def _plan() -> dict[str, object]:
    return {
        "run_id": "mobile-run-one",
        "profile": "balanced",
        "plan_digest": "plan-digest-one",
        "artifact": {
            "attachment_id": "attachment-one",
            "kind": "android_apk",
            "artifact_id": "artifact-one",
            "artifact_sha256": "a" * 64,
            "original_filename": "sample.apk",
            "size_bytes": 100,
            "archive_entry_count": 2,
            "dex_count": 1,
            "native_library_count": 0,
            "native_abis": [],
            "created_at": "2026-08-03T00:00:00+00:00",
        },
        "assessment_graph": {
            "graph_id": "graph-one",
            "revision": 2,
            "workspace_id": "workspace-one",
            "assessment_kind": "apk",
            "chat_stage": "executing",
            "nodes": [
                {"stage": "artifact", "status": "completed"},
                {"stage": "worker", "status": "failed"},
                {"stage": "report", "status": "pending"},
            ],
        },
        "execution": {
            "state": "failed",
            "failure": {"safe_retry": True, "retry_scope": "worker_status"},
        },
    }


def _actor():
    return SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-one"))


def test_browser_retry_state_returns_authoritative_projection_without_mutation(monkeypatch):
    request = _request(method="GET")
    plan = _plan()
    retry_calls: list[object] = []
    remembered: list[dict[str, object]] = []

    monkeypatch.setattr(views, "_actor", lambda *_args: _actor())
    monkeypatch.setattr(views, "current_mobile_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(
        views,
        "retry_mobile_execution",
        lambda *_args, **_kwargs: retry_calls.append(object()),
    )
    monkeypatch.setattr(
        views,
        "remember_mobile_plan",
        lambda _request, value: remembered.append(value),
    )

    response = inspect.unwrap(views.mobile_retry_view)(request)
    payload = json.loads(response.content)

    assert response.status_code == 200
    assert payload["mobile_plan"] == plan
    assert payload["mobile_execution"] == plan["execution"]
    assert payload["assessment_projection"]["assessment_id"] == "mobile-run-one"
    assert payload["task_card"] == payload["assessment_projection"]["task_card"]
    assert payload["assessment_projection"]["allowed_actions"][-1] == "request_retry"
    assert retry_calls == []
    assert remembered == []


def test_browser_retry_state_fails_closed_with_typed_projection_error(monkeypatch):
    request = _request(method="GET")

    monkeypatch.setattr(views, "_actor", lambda *_args: _actor())
    monkeypatch.setattr(views, "current_mobile_plan", lambda *_args, **_kwargs: _plan())
    monkeypatch.setattr(views, "mobile_assessment_projection", lambda _plan: None)

    response = inspect.unwrap(views.mobile_retry_view)(request)
    error = json.loads(response.content)["error"]

    assert response.status_code == 409
    assert error["code"] == "mobile_retry_projection_unavailable"
    assert error["retryable"] is False
    assert error["assessment_id"] == "mobile-run-one"
    assert error["action"] == {
        "label": "Return to assessment history",
        "method": "GET",
        "url": "/scans/",
    }


def test_browser_retry_persists_authoritative_execution_and_projection(monkeypatch):
    request = _request(retry_scope="worker_status", idempotency_key="retry-one")
    plan = _plan()
    remembered: list[dict[str, object]] = []

    monkeypatch.setattr(views, "_actor", lambda *_args: _actor())
    monkeypatch.setattr(views, "current_mobile_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(views, "_resolve_artifact", lambda _attachment: None)
    monkeypatch.setattr(
        views,
        "retry_mobile_execution",
        lambda *_args, **_kwargs: {
            "state": "completed",
            "job_id": "job-one",
            "retry_scope": "worker_status",
            "retry_attempt": 1,
        },
    )
    monkeypatch.setattr(
        views,
        "remember_mobile_plan",
        lambda _request, value: remembered.append(value),
    )

    response = inspect.unwrap(views.mobile_retry_view)(request)
    payload = json.loads(response.content)

    assert response.status_code == 200
    assert payload["mobile_execution"]["state"] == "completed"
    assert payload["mobile_plan"]["execution"] == payload["mobile_execution"]
    assert payload["assessment_projection"]["assessment_id"] == "mobile-run-one"
    assert payload["task_card"] == payload["assessment_projection"]["task_card"]
    assert payload["task_card"]["assessment_id"] == "mobile-run-one"
    assert payload["task_card"]["state"] == "completed"
    assert remembered == [payload["mobile_plan"]]
    assert plan["execution"]["state"] == "failed"


def test_browser_retry_rejects_unprojectable_refresh_without_persisting(monkeypatch):
    request = _request(retry_scope="worker_status", idempotency_key="retry-one")
    plan = _plan()
    remembered: list[dict[str, object]] = []

    monkeypatch.setattr(views, "_actor", lambda *_args: _actor())
    monkeypatch.setattr(views, "current_mobile_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(views, "_resolve_artifact", lambda _attachment: None)
    monkeypatch.setattr(
        views,
        "retry_mobile_execution",
        lambda *_args, **_kwargs: {"state": "completed", "job_id": "job-one"},
    )
    monkeypatch.setattr(views, "mobile_assessment_projection", lambda _plan: None)
    monkeypatch.setattr(
        views,
        "remember_mobile_plan",
        lambda _request, value: remembered.append(value),
    )

    response = inspect.unwrap(views.mobile_retry_view)(request)
    error = json.loads(response.content)["error"]

    assert response.status_code == 409
    assert error["code"] == "mobile_retry_projection_refresh_unavailable"
    assert error["retryable"] is True
    assert error["assessment_id"] == "mobile-run-one"
    assert error["action"] == {
        "label": "Try again",
        "method": "POST",
        "url": "/conversation/mobile/retry/",
    }
    assert remembered == []
    assert plan["execution"]["state"] == "failed"


def test_browser_retry_returns_typed_conflict_without_mutating_plan(monkeypatch):
    request = _request(retry_scope="worker_status", idempotency_key="retry-one")
    plan = _plan()

    monkeypatch.setattr(views, "_actor", lambda *_args: _actor())
    monkeypatch.setattr(views, "current_mobile_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(views, "_resolve_artifact", lambda _attachment: None)
    monkeypatch.setattr(
        views,
        "retry_mobile_execution",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            MobileRetryError(
                "scope conflict",
                code="mobile_retry_scope_mismatch",
            )
        ),
    )

    response = inspect.unwrap(views.mobile_retry_view)(request)
    error = json.loads(response.content)["error"]

    assert response.status_code == 409
    assert error["code"] == "mobile_retry_scope_mismatch"
    assert error["message"] == "scope conflict"
    assert error["retryable"] is False
    assert error["assessment_id"] == "mobile-run-one"
    assert plan["execution"]["state"] == "failed"


def test_browser_retry_preserved_job_unavailable_offers_scoped_retry(monkeypatch):
    request = _request(retry_scope="worker_status", idempotency_key="retry-one")
    plan = _plan()

    monkeypatch.setattr(views, "_actor", lambda *_args: _actor())
    monkeypatch.setattr(views, "current_mobile_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(views, "_resolve_artifact", lambda _attachment: None)
    monkeypatch.setattr(
        views,
        "retry_mobile_execution",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            MobileRetryError(
                "temporarily unavailable",
                code="mobile_retry_preserved_job_unavailable",
                retryable=True,
            )
        ),
    )

    response = inspect.unwrap(views.mobile_retry_view)(request)
    error = json.loads(response.content)["error"]

    assert response.status_code == 409
    assert error["code"] == "mobile_retry_preserved_job_unavailable"
    assert error["retryable"] is True
    assert error["action"]["url"] == "/conversation/mobile/retry/"
