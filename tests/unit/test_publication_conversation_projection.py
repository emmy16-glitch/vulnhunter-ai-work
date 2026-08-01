from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from vulnhunter.web.remediation_conversation_state import (
    _event_message,
    _finding_payload,
    remediation_chat_reply,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _finding():
    report = SimpleNamespace(
        report_id="report-01",
        manifest_id="manifest-01",
        report_sha256="a" * 64,
        manifest_sha256="b" * 64,
        generator_id="report-writer",
        generator_identity_sha256="c" * 64,
        fixed_revision="1" * 40,
        review_receipt_id="review-01",
        formats=("json", "html"),
        created_at=NOW,
    )
    remediation = SimpleNamespace(
        remediation_id="remediation-01",
        state=SimpleNamespace(value="report_generated"),
        plan_sha256="d" * 64,
        source_finding_revision=7,
        source_finding_fingerprint="e" * 64,
        owner_id="developer-owner",
        summary="Enforce ownership before returning the user record.",
        target_references=("app/users.py",),
        regression_test="Cross-user access must be rejected.",
        verification_recipe="Run the exact ownership regression test.",
        compatibility_risks=(),
        references=(),
        verification_history=(),
        review_history=(),
        report_history=(report,),
        created_at=NOW,
        expires_at=None,
        due_at=None,
        cancellation_reason=None,
    )
    return SimpleNamespace(
        finding_id="finding-01",
        campaign_id="campaign-01",
        fingerprint="f" * 64,
        title="IDOR",
        severity=SimpleNamespace(value="high"),
        verification=SimpleNamespace(value="verified"),
        status=SimpleNamespace(value="report_generated"),
        affected_asset="repo-01",
        affected_component="app/users.py",
        evidence=(),
        revision=8,
        remediation=remediation,
    )


def _published_graph():
    publication = {
        "publication_id": "publication-01",
        "publication_sha256": "1" * 64,
        "source_report_id": "report-01",
        "source_manifest_id": "manifest-01",
        "destination_id": "owner-release-vault",
        "destination_label": "Owner-controlled release vault",
        "formats": ["json", "html"],
        "requester_id": "release-requester",
        "approver_id": "release-approver",
        "publisher_id": "release-publisher",
        "published_at": NOW.isoformat(),
        "release_state": "published",
    }
    return {
        "graph_id": "graph-01",
        "chat_stage": "final_report_published",
        "report_state": "published",
        "publication_state": "published",
        "publication_history": [publication],
        "latest_publication": publication,
    }


@pytest.mark.django_db
def test_workspace_payload_replaces_hardcoded_unreleased_state_with_signed_projection():
    payload = _finding_payload(_finding(), graph=_published_graph(), workspace_id=None)

    assert payload["schema_version"] == "1.4"
    assert payload["plan"]["publication_state"] == "published"
    assert payload["plan"]["latest_publication"]["publication_id"] == "publication-01"
    assert payload["plan"]["latest_report"]["release_state"] == "published"
    assert payload["plan"]["latest_report"]["publication_id"] == "publication-01"


def test_chat_status_and_event_metadata_truthfully_expose_publication():
    plan = {
        "finding_id": "finding-01",
        "remediation_id": "remediation-01",
        "task_graph_id": "graph-01",
        "finding": {"revision": 8},
        "plan": {
            "state": "report_generated",
            "latest_verification": None,
            "latest_review": None,
            "latest_report": {
                "report_id": "report-01",
                "manifest_id": "manifest-01",
                "formats": ["json", "html"],
                "release_state": "published",
            },
            "publication_state": "published",
            "latest_publication": {
                "publication_id": "publication-01",
                "destination_id": "owner-release-vault",
                "destination_label": "Owner-controlled release vault",
            },
        },
        "assessment_graph": _published_graph(),
    }

    status = remediation_chat_reply("status", plan)
    result = remediation_chat_reply("results", plan)
    next_step = remediation_chat_reply("next_step", plan)
    event = _event_message(plan)

    assert "separately published as publication-01" in status
    assert "Finding closure, merge and deployment are not implied" in status
    assert "release state is published" in result
    assert "finding closure, merge or deployment" in next_step.lower()
    assert event["metadata"]["remediation"]["release_state"] == "published"
    assert event["metadata"]["remediation"]["publication_id"] == "publication-01"
    assert event["metadata"]["remediation_event"].endswith(
        ":published:publication-01"
    )


def test_chat_fails_closed_for_publication_integrity_error():
    plan = {
        "finding_id": "finding-01",
        "remediation_id": "remediation-01",
        "finding": {"revision": 8},
        "plan": {
            "state": "report_generated",
            "latest_report": {
                "report_id": "report-01",
                "manifest_id": "manifest-01",
                "formats": ["json"],
                "release_state": "integrity_error",
            },
            "publication_state": "integrity_error",
            "latest_publication": None,
        },
        "assessment_graph": {
            "chat_stage": "publication_integrity_error",
            "report_state": "blocked_publication_integrity",
            "publication_state": "integrity_error",
        },
    }

    assert "No publication claim is made" in remediation_chat_reply("status", plan)
    assert "integrity verification failed" in remediation_chat_reply("results", plan)
    assert "restore and verify" in remediation_chat_reply("next_step", plan)
