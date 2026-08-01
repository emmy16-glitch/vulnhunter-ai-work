from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from vulnhunter.publication import (
    PublicationDestination,
    PublicationDestinationConfig,
    PublicationStore,
    ReleaseApproval,
    ReleaseRequest,
)
from vulnhunter.reports import FinalReportFormat
from vulnhunter.web.publication_service import PublicationRuntimeConfig

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
URL = "/findings/finding-01/remediation/report/publication/"


def _actor(actor_id: str):
    return SimpleNamespace(
        governance_identity=SimpleNamespace(
            reviewer_id=actor_id,
            roles=("campaign_admin",),
        )
    )


def _finding_and_bundle():
    latest_report = SimpleNamespace(
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
    finding = SimpleNamespace(
        finding_id="finding-01",
        status=SimpleNamespace(value="report_generated"),
        revision=9,
        remediation=SimpleNamespace(report_history=(latest_report,)),
    )
    bundle = SimpleNamespace(
        manifest=SimpleNamespace(
            artifacts=(
                SimpleNamespace(format=FinalReportFormat.JSON),
                SimpleNamespace(format=FinalReportFormat.HTML),
            )
        )
    )
    return finding, bundle, latest_report


def _runtime(tmp_path):
    return PublicationRuntimeConfig(
        destinations=(
            PublicationDestinationConfig(
                destination_id="owner-release-vault",
                label="Owner-controlled release vault",
                root=tmp_path / "published-secret-path",
                allowed_formats=(FinalReportFormat.JSON, FinalReportFormat.HTML),
            ),
        ),
        release_authority_ids=frozenset(
            {"release-requester", "release-approver", "release-publisher"}
        ),
    )


def _store(tmp_path):
    return PublicationStore(
        tmp_path / "publication-state",
        signing_key=b"publication-browser-signing-key-material",
    )


def _request() -> ReleaseRequest:
    destination = PublicationDestination(
        destination_id="owner-release-vault",
        label="Owner-controlled release vault",
        root_sha256="d" * 64,
        allowed_formats=(FinalReportFormat.JSON, FinalReportFormat.HTML),
    )
    return ReleaseRequest.create(
        source_report_id="report-01",
        source_manifest_id="manifest-01",
        source_report_sha256="a" * 64,
        source_manifest_sha256="b" * 64,
        source_finding_id="finding-01",
        destination=destination,
        formats=(FinalReportFormat.JSON, FinalReportFormat.HTML),
        requester_id="release-requester",
        requester_identity_sha256="e" * 64,
        reason="Release the exact independently reviewed report.",
        created_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )


def _approval(release_request: ReleaseRequest) -> ReleaseApproval:
    return ReleaseApproval.create(
        request=release_request,
        approver_id="release-approver",
        approver_identity_sha256="f" * 64,
        approved_at=NOW + timedelta(minutes=1),
    )


def _patch_world(*, tmp_path, actor_id: str, store, service):
    finding, bundle, _latest_report = _finding_and_bundle()
    return patch.multiple(
        "vulnhunter.web.remediation_publication_views",
        _publication_reader=Mock(return_value=_actor(actor_id)),
        _publication_actor=Mock(return_value=_actor(actor_id)),
        remediation_finding_store=Mock(
            return_value=SimpleNamespace(get=Mock(return_value=finding))
        ),
        publication_runtime_config=Mock(return_value=_runtime(tmp_path)),
        publication_store=Mock(return_value=store),
        final_report_store=Mock(
            return_value=SimpleNamespace(load=Mock(return_value=bundle))
        ),
        publication_service=Mock(return_value=service),
    )


@pytest.mark.django_db
def test_publication_workspace_is_responsive_and_does_not_expose_destination_path(
    client,
    tmp_path,
):
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create_user(username="release-reader", password="password")
    client.force_login(user)
    store = _store(tmp_path)
    service = Mock()

    with _patch_world(
        tmp_path=tmp_path,
        actor_id="release-requester",
        store=store,
        service=service,
    ):
        response = client.get(URL)

    assert response.status_code == 200
    content = response.content.decode()
    assert "Governed final-report publication" in content
    assert "Create signed release request" in content
    assert "Typed actor IDs are ignored" in content
    assert "published-secret-path" not in content


@pytest.mark.django_db
def test_request_action_uses_mapped_identity_and_ignores_forged_actor_id(client, tmp_path):
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create_user(username="requester", password="password")
    client.force_login(user)
    store = _store(tmp_path)
    service = Mock()
    service.request_release.return_value = SimpleNamespace(request_id="release-request-01")

    with _patch_world(
        tmp_path=tmp_path,
        actor_id="release-requester",
        store=store,
        service=service,
    ):
        response = client.post(
            URL,
            {
                "action": "request",
                "requester_id": "ordinary-operator",
                "destination_id": "owner-release-vault",
                "formats": ["json", "html"],
                "reason": "Release the exact independently reviewed report.",
                "expires_in_hours": "24",
                "governance_secret": "requester-secret",
            },
        )

    assert response.status_code == 302
    call = service.request_release.call_args.kwargs
    assert call["report_id"] == "report-01"
    assert call["requester_id"] == "release-requester"
    assert call["requester_secret"] == "requester-secret"
    assert call["formats"] == ["json", "html"]
    assert NOW < call["expires_at"] <= datetime.now(UTC) + timedelta(hours=25)


@pytest.mark.django_db
def test_approval_action_uses_second_mapped_identity(client, tmp_path):
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create_user(username="approver", password="password")
    client.force_login(user)
    store = _store(tmp_path)
    release_request = _request()
    store.save_request(release_request)
    service = Mock()
    service.approve_release.return_value = SimpleNamespace(
        approval_id="release-approval-01"
    )

    with _patch_world(
        tmp_path=tmp_path,
        actor_id="release-approver",
        store=store,
        service=service,
    ):
        response = client.post(
            URL,
            {
                "action": "approve",
                "approver_id": "release-requester",
                "request_id": release_request.request_id,
                "governance_secret": "approver-secret",
            },
        )

    assert response.status_code == 302
    service.approve_release.assert_called_once_with(
        request_id=release_request.request_id,
        approver_id="release-approver",
        approver_secret="approver-secret",
    )


@pytest.mark.django_db
def test_publish_action_uses_third_mapped_identity(client, tmp_path):
    from django.contrib.auth import get_user_model

    user = get_user_model().objects.create_user(username="publisher", password="password")
    client.force_login(user)
    store = _store(tmp_path)
    release_request = _request()
    approval = _approval(release_request)
    store.save_request(release_request)
    store.save_approval(approval)
    service = Mock()
    service.publish.return_value = SimpleNamespace(publication_id="publication-01")

    with _patch_world(
        tmp_path=tmp_path,
        actor_id="release-publisher",
        store=store,
        service=service,
    ):
        response = client.post(
            URL,
            {
                "action": "publish",
                "publisher_id": "release-approver",
                "request_id": release_request.request_id,
                "approval_id": approval.approval_id,
                "governance_secret": "publisher-secret",
            },
        )

    assert response.status_code == 302
    service.publish.assert_called_once_with(
        request_id=release_request.request_id,
        approval_id=approval.approval_id,
        publisher_id="release-publisher",
        publisher_secret="publisher-secret",
    )
