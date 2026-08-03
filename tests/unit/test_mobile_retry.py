from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnhunter.web.mobile_retry import MobileRetryError, retry_mobile_execution


class _Session(dict):
    modified = False


def _request():
    return SimpleNamespace(session=_Session())


def _plan(*, scope: str, job_id: str | None = "job-one") -> dict[str, object]:
    execution: dict[str, object] = {
        "state": "failed",
        "failure": {
            "safe_retry": True,
            "retry_scope": scope,
            "preserved": ["artifact", "assessment", "plan", "approval", "previous_receipts"],
        },
        "receipt": {"captures": [{"capture_id": "capture-one"}]},
    }
    if job_id is not None:
        execution["job_id"] = job_id
    return {"run_id": "mobile-run-one", "execution": execution}


def test_status_retry_is_idempotent_and_preserves_one_attempt(monkeypatch):
    request = _request()
    calls: list[str] = []

    def _status(request_arg, *, job_id: str, requested_by: str):
        assert request_arg is request
        assert requested_by == "reviewer-one"
        calls.append(job_id)
        return {
            "state": "completed",
            "job_id": job_id,
            "receipt": {"captures": [{"capture_id": "capture-one"}]},
        }

    monkeypatch.setattr("vulnhunter.web.mobile_retry.mobile_static_status", _status)
    plan = _plan(scope="worker_status")

    first = retry_mobile_execution(
        request,
        plan=plan,
        requested_by="reviewer-one",
        retry_scope="worker_status",
        idempotency_key="retry-click-one",
    )
    replay = retry_mobile_execution(
        request,
        plan=plan,
        requested_by="reviewer-one",
        retry_scope="worker_status",
        idempotency_key="retry-click-one",
    )

    assert calls == ["job-one"]
    assert first == replay
    assert first["state"] == "completed"
    assert first["receipt"] == {"captures": [{"capture_id": "capture-one"}]}
    assert first["retry_attempt"] == 1
    assert first["retry_attempts"] == [
        {"attempt": 1, "scope": "worker_status", "state": "completed"}
    ]
    assert "retry-click-one" not in repr(request.session)


def test_same_idempotency_key_is_isolated_by_reviewer(monkeypatch):
    request = _request()
    reviewers: list[str] = []

    def _status(_request_arg, *, job_id: str, requested_by: str):
        reviewers.append(requested_by)
        return {"state": "completed", "job_id": job_id}

    monkeypatch.setattr("vulnhunter.web.mobile_retry.mobile_static_status", _status)
    plan = _plan(scope="worker_status")

    retry_mobile_execution(
        request,
        plan=plan,
        requested_by="reviewer-one",
        retry_scope="worker_status",
        idempotency_key="shared-key",
    )
    retry_mobile_execution(
        request,
        plan=plan,
        requested_by="reviewer-two",
        retry_scope="worker_status",
        idempotency_key="shared-key",
    )

    assert reviewers == ["reviewer-one", "reviewer-two"]


def test_retry_rejects_scope_different_from_persisted_failure():
    with pytest.raises(MobileRetryError, match="does not match"):
        retry_mobile_execution(
            _request(),
            plan=_plan(scope="worker_status"),
            requested_by="reviewer-one",
            retry_scope="worker_activation",
            idempotency_key="retry-one",
        )


def test_retry_rejects_failure_without_safe_retry():
    plan = _plan(scope="worker_status")
    plan["execution"]["failure"]["safe_retry"] = False

    with pytest.raises(MobileRetryError, match="does not permit"):
        retry_mobile_execution(
            _request(),
            plan=plan,
            requested_by="reviewer-one",
            retry_scope="worker_status",
            idempotency_key="retry-one",
        )


def test_status_retry_requires_preserved_job():
    with pytest.raises(MobileRetryError, match="preserved worker job"):
        retry_mobile_execution(
            _request(),
            plan=_plan(scope="worker_status", job_id=None),
            requested_by="reviewer-one",
            retry_scope="worker_status",
            idempotency_key="retry-one",
        )


def test_status_retry_rejects_job_not_owned_by_session(monkeypatch):
    monkeypatch.setattr(
        "vulnhunter.web.mobile_retry.mobile_static_status",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(MobileRetryError, match="unavailable to this session"):
        retry_mobile_execution(
            _request(),
            plan=_plan(scope="worker_status"),
            requested_by="reviewer-one",
            retry_scope="worker_status",
            idempotency_key="retry-one",
        )


def test_activation_retry_requires_verified_artifact_binding():
    with pytest.raises(MobileRetryError, match="verified artifact binding"):
        retry_mobile_execution(
            _request(),
            plan=_plan(scope="worker_activation", job_id=None),
            requested_by="reviewer-one",
            retry_scope="worker_activation",
            idempotency_key="retry-one",
        )


def test_activation_retry_rejects_mismatched_artifact_binding():
    with pytest.raises(MobileRetryError, match="verified artifact binding"):
        retry_mobile_execution(
            _request(),
            plan=_plan(scope="worker_activation", job_id=None),
            requested_by="reviewer-one",
            retry_scope="worker_activation",
            idempotency_key="retry-one",
            attachment=SimpleNamespace(artifact_id="artifact-one"),
            artifact=SimpleNamespace(artifact_id="artifact-two"),
        )


def test_activation_retry_replays_without_second_enqueue(monkeypatch):
    request = _request()
    calls = 0

    def _enqueue(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return {"state": "queued", "job_id": "job-two"}

    monkeypatch.setattr("vulnhunter.web.mobile_retry.enqueue_mobile_static_if_ready", _enqueue)
    plan = _plan(scope="worker_activation", job_id=None)
    attachment = SimpleNamespace(artifact_id="artifact-one")
    artifact = SimpleNamespace(artifact_id="artifact-one")

    first = retry_mobile_execution(
        request,
        plan=plan,
        requested_by="reviewer-one",
        retry_scope="worker_activation",
        idempotency_key="retry-one",
        attachment=attachment,
        artifact=artifact,
    )
    replay = retry_mobile_execution(
        request,
        plan=plan,
        requested_by="reviewer-one",
        retry_scope="worker_activation",
        idempotency_key="retry-one",
        attachment=attachment,
        artifact=artifact,
    )

    assert calls == 1
    assert first == replay
    assert first["state"] == "queued"
    assert first["retry_attempt"] == 1
