from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from vulnhunter.web.services import WebPermissionDenied


@pytest.fixture
def logged_in_client(db):
    user = get_user_model().objects.create_user(
        username="mobile-records-view", password="password-1234"
    )
    client = Client()
    client.force_login(user)
    return client


def actor():
    return SimpleNamespace(governance_identity=SimpleNamespace(reviewer_id="reviewer-records"))


def projection():
    components = [
        {
            "record_id": "component-1",
            "name": "MainActivity",
            "ownership": "app",
            "state": "observed",
        },
        {
            "record_id": "component-2",
            "name": "ExportedReceiver",
            "ownership": "third_party",
            "state": "candidate",
        },
        {
            "record_id": "component-3",
            "name": "PrivateService",
            "ownership": "app",
            "state": "verified",
        },
    ] + [
        {
            "record_id": f"component-{index}",
            "name": f"Component{index}",
            "ownership": "app",
            "state": "observed",
        }
        for index in range(4, 12)
    ]
    return {
        "assessment_id": "apk-records",
        "intelligence": {
            "exported_component_surfaces": components,
            "endpoint_references": [
                {
                    "record_id": "endpoint-1",
                    "protocol": "https",
                    "host": "api.example.test",
                    "ownership": "app",
                },
                {
                    "record_id": "endpoint-2",
                    "protocol": "http",
                    "host": "cdn.example.test",
                    "ownership": "third_party",
                },
            ],
            "verified_findings": [
                {"record_id": "finding-1", "state": "verified", "severity": "high"},
            ],
        },
        "source_hunt": {"results": [], "graph": {"edges": []}},
    }


@pytest.mark.django_db
def test_mobile_records_returns_authenticated_paginated_items(logged_in_client):
    with (
        patch("vulnhunter.web.mobile_records_views._actor", return_value=actor()),
        patch(
            "vulnhunter.web.mobile_records_views.current_mobile_plan",
            return_value={"run_id": "apk-records"},
        ) as current_plan,
        patch(
            "vulnhunter.web.mobile_records_views.mobile_assessment_projection",
            return_value=projection(),
        ),
    ):
        response = logged_in_client.get(
            reverse("web-conversation-mobile-records"),
            {"record_type": "components", "page": "2", "page_size": "10"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["record_type"] == "components"
    assert [item["record_id"] for item in payload["items"]] == ["component-11"]
    assert payload["pagination"] == {
        "page": 2,
        "page_size": 10,
        "total_items": 11,
        "total_pages": 2,
    }
    current_plan.assert_called_once_with(
        response.wsgi_request,
        requested_by="reviewer-records",
    )


@pytest.mark.django_db
def test_mobile_records_filters_query_state_ownership_and_protocol(logged_in_client):
    with (
        patch("vulnhunter.web.mobile_records_views._actor", return_value=actor()),
        patch(
            "vulnhunter.web.mobile_records_views.current_mobile_plan",
            return_value={"run_id": "apk-records"},
        ),
        patch(
            "vulnhunter.web.mobile_records_views.mobile_assessment_projection",
            return_value=projection(),
        ),
    ):
        component_response = logged_in_client.get(
            reverse("web-conversation-mobile-records"),
            {
                "record_type": "components",
                "query": "receiver",
                "state": "candidate",
                "ownership": "third_party",
            },
        )
        endpoint_response = logged_in_client.get(
            reverse("web-conversation-mobile-records"),
            {"record_type": "endpoints", "protocol": "http"},
        )

    assert [item["record_id"] for item in component_response.json()["items"]] == ["component-2"]
    assert [item["record_id"] for item in endpoint_response.json()["items"]] == ["endpoint-2"]


@pytest.mark.django_db
def test_mobile_records_rejects_unsupported_type(logged_in_client):
    with (
        patch("vulnhunter.web.mobile_records_views._actor", return_value=actor()),
        patch(
            "vulnhunter.web.mobile_records_views.current_mobile_plan",
            return_value={"run_id": "apk-records"},
        ),
    ):
        response = logged_in_client.get(
            reverse("web-conversation-mobile-records"), {"record_type": "secrets"}
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported mobile record type."


@pytest.mark.django_db
def test_mobile_records_returns_404_without_selected_plan(logged_in_client):
    with (
        patch("vulnhunter.web.mobile_records_views._actor", return_value=actor()),
        patch("vulnhunter.web.mobile_records_views.current_mobile_plan", return_value=None),
    ):
        response = logged_in_client.get(reverse("web-conversation-mobile-records"))

    assert response.status_code == 404
    assert response.json()["detail"] == "No mobile assessment is selected."


@pytest.mark.django_db
def test_mobile_records_returns_403_when_governance_denies_access(logged_in_client):
    with patch(
        "vulnhunter.web.mobile_records_views._actor",
        side_effect=WebPermissionDenied("scan.read is not available"),
    ):
        response = logged_in_client.get(reverse("web-conversation-mobile-records"))

    assert response.status_code == 403
    assert response.json()["detail"] == "scan.read is not available"


def test_mobile_records_requires_authentication():
    response = Client().get(reverse("web-conversation-mobile-records"))
    assert response.status_code in {302, 403}
