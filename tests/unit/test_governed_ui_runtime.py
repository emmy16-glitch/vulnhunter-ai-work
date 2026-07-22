from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.template.loader import get_template
from governance_test_support import (
    ADJUDICATOR_SECRET,
    REVIEWER_ONE_SECRET,
    REVIEWER_TWO_SECRET,
    make_governance_store,
)
from test_governance_workflow import assign_default, prepare_world

from vulnhunter.agent.store import AgentStore
from vulnhunter.web.models import WebUserMapping

_ROOT = Path(__file__).resolve().parents[2]
_WEB_ROOT = _ROOT / "vulnhunter" / "web"
_TEMPLATES = _WEB_ROOT / "templates" / "web"
_STATIC = _WEB_ROOT / "static" / "web"
_ALL_PRODUCT_ROLES = [
    "system-administrator",
    "campaign-operator",
    "campaign-approver",
    "reviewer",
    "adjudicator",
    "security-auditor",
    "model-analyst",
]


@pytest.fixture
def governed_runtime(tmp_path: Path, settings):
    settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    settings.VULNHUNTER_AUTHORIZATION_DATABASE = str(tmp_path / "auth.db")
    settings.VULNHUNTER_GOVERNANCE_DATABASE = str(tmp_path / "governance.db")
    settings.VULNHUNTER_AGENT_DATABASE = str(tmp_path / "agent.db")
    settings.VULNHUNTER_APPROVAL_DATABASE = str(tmp_path / "approvals.sqlite3")
    settings.VULNHUNTER_AGENT_ACTIVITY_ROOT = str(tmp_path / "activity")
    settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT = str(tmp_path / "evidence")
    settings.VULNHUNTER_MOBILE_ARTIFACT_ROOT = str(tmp_path / "mobile-artifacts")
    settings.ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

    AgentStore.initialize_database(tmp_path / "agent.db")
    store = make_governance_store(tmp_path)
    world = prepare_world(store, tmp_path)
    assignment = assign_default(store, world)
    return store, world, assignment


def _mapped_user(*, username: str, identity: str, roles: list[str]):
    user = get_user_model().objects.create_user(
        username=username,
        password="password-1234",
    )
    WebUserMapping.objects.create(
        user=user,
        governance_identity_id=identity,
        product_roles=roles,
    )
    return user


@pytest.mark.django_db
def test_review_and_adjudication_workspaces_execute_real_governed_flow(
    client,
    governed_runtime,
) -> None:
    store, world, assignment = governed_runtime
    reference = assignment.record_sha256[:24]
    first_note = "Primary reviewer A confirmed the persisted evidence."
    second_note = "Primary reviewer B found the signal to be a false positive."

    reviewer_a = _mapped_user(
        username="reviewer-a-ui",
        identity="reviewer-a",
        roles=["reviewer"],
    )
    client.force_login(reviewer_a)
    response = client.get(f"/reviews/{reference}/")
    assert response.status_code == 200
    assert b"Independent primary review" in response.content
    assert b"Record immutable decision" in response.content
    assert b"Traceback" not in response.content

    response = client.post(
        f"/reviews/{reference}/",
        {
            "outcome": "confirmed",
            "note": first_note,
            "governance_secret": REVIEWER_ONE_SECRET,
        },
    )
    assert response.status_code == 302

    reviewer_b = _mapped_user(
        username="reviewer-b-ui",
        identity="reviewer-b",
        roles=["reviewer"],
    )
    client.force_login(reviewer_b)
    response = client.get(f"/reviews/{reference}/")
    assert response.status_code == 200
    assert first_note.encode() not in response.content
    assert b"intentionally hidden" in response.content

    response = client.post(
        f"/reviews/{reference}/",
        {
            "outcome": "false_positive",
            "note": second_note,
            "governance_secret": REVIEWER_TWO_SECRET,
        },
    )
    assert response.status_code == 302

    adjudicator = _mapped_user(
        username="adjudicator-ui",
        identity="lead-c",
        roles=["adjudicator"],
    )
    client.force_login(adjudicator)
    response = client.get(f"/adjudications/{reference}/")
    assert response.status_code == 200
    assert first_note.encode() in response.content
    assert second_note.encode() in response.content
    assert b"Record final adjudication" in response.content

    rationale = "The persisted evidence supports a confirmed final outcome."
    response = client.post(
        f"/adjudications/{reference}/",
        {
            "outcome": "confirmed",
            "rationale": rationale,
            "governance_secret": ADJUDICATOR_SECRET,
        },
    )
    assert response.status_code == 302
    response = client.get(f"/adjudications/{reference}/")
    assert response.status_code == 200
    assert b"Adjudication locked" in response.content
    assert rationale.encode() in response.content

    case = world["repository"].get_review_case(world["observation_id"])
    assert len(case.decisions) == 2
    assert case.adjudication is not None
    assert case.adjudication.outcome == "confirmed"
    assert len(store.list_attestations(world["campaign"].campaign_id)) == 3


@pytest.mark.django_db
def test_detail_workspaces_render_with_governed_campaign_data(
    client,
    governed_runtime,
) -> None:
    _, world, assignment = governed_runtime
    admin = _mapped_user(
        username="governed-ui-admin",
        identity="reviewer-a",
        roles=_ALL_PRODUCT_ROLES,
    )
    client.force_login(admin)

    campaign_id = world["campaign"].campaign_id
    reference = assignment.record_sha256[:24]
    routes = (
        (f"/reviews/{reference}/", b"Independent primary review"),
        (f"/releases/{campaign_id}/", b"Governed release assessment"),
        (f"/datasets/{campaign_id}/", b"Dataset quality and provenance"),
    )
    for route, marker in routes:
        response = client.get(route)
        assert response.status_code == 200, route
        assert marker in response.content
        assert b"Traceback" not in response.content
        assert "no-store" in response.headers.get("Cache-Control", "")

    release_list = client.get("/releases/")
    dataset_list = client.get("/datasets/")
    assert f"/releases/{campaign_id}/".encode() in release_list.content
    assert f"/datasets/{campaign_id}/".encode() in dataset_list.content


@pytest.mark.django_db
def test_review_workspace_fails_closed_when_evidence_database_disappears(
    client,
    governed_runtime,
) -> None:
    _, world, assignment = governed_runtime
    reviewer = _mapped_user(
        username="reviewer-missing-evidence",
        identity="reviewer-a",
        roles=["reviewer"],
    )
    client.force_login(reviewer)
    world["scan_database"].unlink()

    response = client.get(f"/reviews/{assignment.record_sha256[:24]}/")
    assert response.status_code == 503
    assert b"Review unavailable" in response.content
    assert b"Evidence could not be loaded safely" in response.content
    assert b"Record immutable decision" not in response.content
    assert b"Traceback" not in response.content


@pytest.mark.django_db
def test_finding_detail_renders_critical_evidence_and_provenance(
    client,
    governed_runtime,
) -> None:
    admin = _mapped_user(
        username="finding-ui-admin",
        identity="admin-a",
        roles=["security-auditor"],
    )
    client.force_login(admin)

    finding_id = "evidence-critical-one"
    summary = SimpleNamespace(run_id="run-ui-one", assessment_owner="admin-a")
    run = SimpleNamespace(
        run_id="run-ui-one",
        findings=(
            {
                "evidence_id": finding_id,
                "title": "Critical authorization bypass",
                "description": "A persisted test finding.",
                "severity": "CRITICAL",
                "confidence": "high",
                "verification": "verified",
                "release_state": "not_released",
                "review_state": "confirmed",
                "target_reference": "https://example.invalid/redacted",
                "category": "authorization",
                "evidence_summary": "Deterministic evidence is available.",
            },
        ),
        artifacts=(
            {
                "title": "Proof capsule",
                "summary": "Sanitized deterministic evidence.",
                "sha256": "a" * 64,
            },
        ),
        evaluation_result="verified",
        requested_tool="nuclei",
        scope_summary="Authorized target",
        workflow_state="completed",
        current_state="completed",
        authorization_id="authorization-ui",
        plan_digest="b" * 64,
        final_event_sha256="c" * 64,
    )
    service = SimpleNamespace(
        list_agent_runs=lambda: (summary,),
        get_agent_run=lambda run_id: run if run_id == run.run_id else None,
    )

    with patch(
        "vulnhunter.web.governance_workspace_views.product_service",
        return_value=service,
    ):
        response = client.get(f"/findings/{finding_id}/")

    assert response.status_code == 200
    assert b"Critical authorization bypass" in response.content
    assert b"vh-severity-critical" in response.content
    assert b"Proof capsule" in response.content
    assert ("a" * 64).encode() in response.content
    assert b"Traceback" not in response.content


@pytest.mark.django_db
def test_intelligence_routes_use_stable_component_identity_not_provider_order(
    client,
    governed_runtime,
) -> None:
    admin = _mapped_user(
        username="intelligence-ui-admin",
        identity="admin-a",
        roles=["model-analyst"],
    )
    client.force_login(admin)

    statuses = (
        {
            "name": "Deterministic verification",
            "state": "READY_ENABLED",
            "detail": "deterministic marker",
        },
        {
            "name": "Groq advisory",
            "state": "CODE_READY_DISABLED",
            "detail": "advisory marker",
        },
        {
            "name": "Graphify advisory graph",
            "state": "NOT_READY",
            "detail": "graph marker",
        },
    )
    with patch(
        "vulnhunter.web.intelligence_views.intelligence_status",
        return_value=statuses,
    ):
        overview = client.get("/models/")
        graph = client.get("/models/graph-context/")
        advisory = client.get("/models/advisory-analysis/")
        verification = client.get("/models/deterministic-verification/")

    assert overview.status_code == 200
    assert b'data-component-id="graph-context"' in overview.content
    assert b'data-component-id="advisory-analysis"' in overview.content
    assert b'data-component-id="deterministic-verification"' in overview.content
    assert b"graph marker" in graph.content
    assert b"advisory marker" in advisory.content
    assert b"deterministic marker" in verification.content
    for response in (overview, graph, advisory, verification):
        assert response.status_code == 200
        assert b"Traceback" not in response.content
        assert "no-store" in response.headers.get("Cache-Control", "")


def test_all_web_templates_compile_and_reference_defined_icons() -> None:
    for path in sorted(_TEMPLATES.glob("*.html")):
        get_template(f"web/{path.name}")

    base = (_TEMPLATES / "base.html").read_text(encoding="utf-8")
    defined = set(re.findall(r'id="(vh-i-[^"]+)"', base))
    referenced: set[str] = set()
    for path in _TEMPLATES.glob("*.html"):
        referenced.update(
            re.findall(r'href="#(vh-i-[^"]+)"', path.read_text(encoding="utf-8"))
        )
    assert referenced <= defined


def test_workspace_visual_contract_covers_all_severities_and_breakpoints() -> None:
    css = (_STATIC / "workspaces.css").read_text(encoding="utf-8")
    for token in (
        ".vh-severity-critical",
        ".vh-severity-high",
        ".vh-severity-medium",
        ".vh-severity-low",
        ".vh-severity-info",
        ".vh-severity-unknown",
        "@media (max-width: 980px)",
        "@media (max-width: 639px)",
        "overflow-x: auto",
        "overscroll-behavior-inline: contain",
    ):
        assert token in css

    models = (_TEMPLATES / "models_overview.html").read_text(encoding="utf-8")
    assert "forloop.counter0" not in models
    assert "item.component_id" in models
    assert '<link rel="stylesheet"' not in models
