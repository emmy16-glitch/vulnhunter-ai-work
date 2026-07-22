from __future__ import annotations

from pathlib import Path

from django.urls import reverse

from vulnhunter.web.workspace_forms import (
    GovernedAdjudicationForm,
    GovernedReviewForm,
)

_ROOT = Path(__file__).resolve().parents[2]
_WEB_ROOT = _ROOT / "vulnhunter" / "web"


def test_governed_workspace_routes_are_wired() -> None:
    assignment_reference = "a" * 24
    assert reverse(
        "web-finding-detail",
        kwargs={"finding_id": "evidence-one"},
    ) == "/findings/evidence-one/"
    assert reverse(
        "web-review-detail",
        kwargs={"assignment_reference": assignment_reference},
    ) == f"/reviews/{assignment_reference}/"
    assert reverse(
        "web-adjudication-detail",
        kwargs={"assignment_reference": assignment_reference},
    ) == f"/adjudications/{assignment_reference}/"
    assert reverse(
        "web-release-detail",
        kwargs={"campaign_id": "campaign-one"},
    ) == "/releases/campaign-one/"
    assert reverse(
        "web-dataset-detail",
        kwargs={"campaign_id": "campaign-one"},
    ) == "/datasets/campaign-one/"
    assert reverse(
        "web-model-detail",
        kwargs={"component_id": "advisory-analysis"},
    ) == "/models/advisory-analysis/"


def test_login_and_console_remain_server_authoritative() -> None:
    login = (_WEB_ROOT / "templates" / "web" / "login.html").read_text(
        encoding="utf-8"
    )
    base = (_WEB_ROOT / "templates" / "web" / "base.html").read_text(
        encoding="utf-8"
    )

    assert '{% csrf_token %}' in login
    assert 'method="post"' in login
    assert "onsubmit=" not in login
    assert "onclick=" not in login
    assert "role-switch" not in login
    assert "web/console.css" in base
    assert "web/workspaces.css" in base
    assert "Private Lab" in login
    assert "Private Lab" in base


def test_web_product_surface_contains_no_qwen_copy() -> None:
    browser_roots = (
        _WEB_ROOT / "templates",
        _WEB_ROOT / "static",
    )
    browser_suffixes = {".html", ".css", ".js"}
    checked_paths = [
        _WEB_ROOT / "governance_workspace_views.py",
        _WEB_ROOT / "workspace_forms.py",
    ]

    for root in browser_roots:
        checked_paths.extend(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix in browser_suffixes
        )

    for path in checked_paths:
        text = path.read_text(encoding="utf-8").lower()
        assert "qwen" not in text, path


def test_governance_credentials_are_password_inputs() -> None:
    review = GovernedReviewForm()
    adjudication = GovernedAdjudicationForm()

    for form in (review, adjudication):
        field = form.fields["governance_secret"]
        assert field.widget.input_type == "password"
        assert field.widget.render_value is False
        assert field.widget.attrs["autocomplete"] == "current-password"


def test_workspace_assets_and_templates_exist() -> None:
    expected = (
        "static/web/console.css",
        "static/web/workspaces.css",
        "static/web/intelligence.css",
        "templates/web/finding_detail.html",
        "templates/web/review_workspace.html",
        "templates/web/adjudication_workspace.html",
        "templates/web/release_detail.html",
        "templates/web/dataset_detail.html",
        "templates/web/model_detail.html",
    )
    for relative_path in expected:
        assert (_WEB_ROOT / relative_path).is_file(), relative_path
