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


def _request(**post):
    return SimpleNamespace(POST=_Post(post), session=_Session())


def _plan() -> dict[str, object]:
    return {
        "run_id": "mobile-run-one",
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
        "execution": {
            "state": "failed",
            "failure": {"safe_retry": True, "retry_scope": "worker_status"},
        },
    }


def test_browser_retry_persists_authoritative_execution(monkeypatch):
    request = _request(retry_scope="worker_status", idempotency_key="retry-one")
    plan = _plan()
    remembered: list[dict[str, object]] = []
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-one"))

    monkeypatch.setattr(views, "_actor", lambda *_args: actor)
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
    monkeypatch.setattr(views, "remember_mobile_plan", lambda _request, value: remembered.append(value))

    response = inspect.unwrap(views.mobile_retry_view)(request)
    payload = json.loads(response.content)

    assert response.status_code == 200
    assert payload["mobile_execution"]["state"] == "completed"
    assert payload["mobile_plan"]["execution"] == payload["mobile_execution"]
    assert remembered == [payload["mobile_plan"]]
    assert plan["execution"]["state"] == "failed"


def test_browser_retry_returns_conflict_without_mutating_plan(monkeypatch):
    request = _request(retry_scope="worker_status", idempotency_key="retry-one")
    plan = _plan()
    actor = SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-one"))

    monkeypatch.setattr(views, "_actor", lambda *_args: actor)
    monkeypatch.setattr(views, "current_mobile_plan", lambda *_args, **_kwargs: plan)
    monkeypatch.setattr(views, "_resolve_artifact", lambda _attachment: None)
    monkeypatch.setattr(
        views,
        "retry_mobile_execution",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(MobileRetryError("scope conflict")),
    )

    response = inspect.unwrap(views.mobile_retry_view)(request)

    assert response.status_code == 409
    assert json.loads(response.content) == {"detail": "scope conflict"}
    assert plan["execution"]["state"] == "failed"
