from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnhunter.web.mobile_execution import enqueue_mobile_static_if_ready
from vulnhunter.web.mobile_failures import execution_failure, mobile_failure


class _Session(dict):
    modified = False


def test_mobile_failure_requires_exact_retry_scope():
    with pytest.raises(ValueError, match="exact retry scope"):
        mobile_failure(
            category="worker_unavailable",
            stage="worker_activation",
            reason_code="worker_not_activated",
            message="Worker unavailable.",
            safe_retry=True,
        )


def test_mobile_failure_reference_is_stable_and_redacted():
    first = mobile_failure(
        category="storage_failure",
        stage="worker_status",
        reason_code="status_oserror",
        message="The latest worker status could not be verified safely.",
        operation_id="job-safe-01",
        operator_action="Inspect the signed spool.",
        safe_retry=True,
        retry_scope="worker_status",
        preserved=("artifact", "assessment", "artifact"),
    )
    second = mobile_failure(
        category="storage_failure",
        stage="worker_status",
        reason_code="status_oserror",
        message="The latest worker status could not be verified safely.",
        operation_id="job-safe-01",
        operator_action="Inspect the signed spool.",
        safe_retry=True,
        retry_scope="worker_status",
        preserved=("artifact", "assessment"),
    )

    assert first["reference"] == second["reference"]
    assert first["reference"].startswith("vh-mobile-")
    assert "job-safe-01" not in first["reference"]
    assert first["preserved"] == ["artifact", "assessment"]


def test_execution_failure_keeps_legacy_reason_and_typed_contract():
    failure = mobile_failure(
        category="policy_denied",
        stage="worker_activation",
        reason_code="worker_policy_disabled",
        message="Static APK analysis is disabled by policy.",
        operation_id="run-one",
        operator_action="Enable the reviewed worker policy.",
    )

    payload = execution_failure(state="gated", failure=failure)

    assert payload["state"] == "gated"
    assert payload["reason"] == failure["message"]
    assert payload["failure"] == failure
    assert failure["safe_retry"] is False
    assert failure["retry_scope"] is None


def test_disabled_worker_returns_actionable_typed_failure(monkeypatch):
    monkeypatch.delenv("VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED", raising=False)
    request = SimpleNamespace(session=_Session())
    plan = {"run_id": "mobile-run-one", "plan_digest": "a" * 64}
    attachment = SimpleNamespace(artifact_id="attachment-one")
    artifact = SimpleNamespace()

    result = enqueue_mobile_static_if_ready(
        request,
        plan=plan,
        attachment=attachment,
        artifact=artifact,
        requested_by="reviewer-one",
    )

    assert result["state"] == "gated"
    assert result["failure"] == {
        "category": "worker_unavailable",
        "stage": "worker_activation",
        "reason_code": "worker_not_activated",
        "reference": result["failure"]["reference"],
        "message": "Static APK analysis is not activated in this deployment.",
        "user_action": None,
        "operator_action": (
            "Enable the isolated mobile worker after its policy and signing key pass preflight."
        ),
        "safe_retry": False,
        "retry_scope": None,
        "preserved": ["artifact", "assessment", "plan", "approval"],
    }
    assert result["failure"]["reference"].startswith("vh-mobile-")
