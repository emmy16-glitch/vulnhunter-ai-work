from __future__ import annotations

from django.urls import path
from django.views.generic import RedirectView

from vulnhunter.web import (
    assessment_views,
    audit_views,
    findings_views,
    lab_views,
    operations_views,
    report_views,
    stream_views,
    views,
)

urlpatterns = [
    path("health/", views.health_view, name="web-health"),
    path("ready/", views.deployment_readiness_view, name="web-deployment-readiness"),
    path("login/", views.VulnHunterLoginView.as_view(), name="web-login"),
    path("logout/", views.logout_view, name="web-logout"),
    path("", views.dashboard_view, name="web-dashboard"),
    path("status/", views.status_view, name="web-status"),
    path("audit/", audit_views.audit_overview_view, name="web-audit-overview"),
    path("authorizations/", views.authorization_list_view, name="web-authorization-list"),
    path("scans/new/", assessment_views.new_assessment_view, name="web-new-scan"),
    path(
        "scans/authorizations/",
        operations_views.active_authorizations_view,
        name="web-active-authorizations",
    ),
    path("scans/", views.agent_run_list_view, name="web-scan-run-list"),
    path("scans/<str:run_id>/", views.agent_run_detail_view, name="web-scan-run-detail"),
    path(
        "scans/<str:assessment_id>/active-validation/new/",
        lab_views.lab_create_view,
        name="web-lab-create",
    ),
    path(
        "active-validation/<str:lab_id>/",
        lab_views.lab_detail_view,
        name="web-lab-detail",
    ),
    path(
        "active-validation/<str:lab_id>/approve/",
        lab_views.lab_approve_view,
        name="web-lab-approve",
    ),
    path(
        "active-validation/<str:lab_id>/queue/",
        lab_views.lab_queue_view,
        name="web-lab-queue",
    ),
    path(
        "active-validation/<str:lab_id>/stop/",
        lab_views.lab_stop_view,
        name="web-lab-stop",
    ),
    path(
        "active-validation/<str:lab_id>/activity/stream/",
        lab_views.lab_activity_stream_view,
        name="web-lab-activity-stream",
    ),
    path("reviews/", views.review_queue_view, name="web-review-queue"),
    path("adjudications/", views.adjudication_queue_view, name="web-adjudication-queue"),
    path("releases/", views.release_list_view, name="web-release-list"),
    path("datasets/", views.dataset_list_view, name="web-dataset-list"),
    path("models/", views.model_list_view, name="web-model-list"),
    path("findings/", findings_views.findings_overview_view, name="web-findings-overview"),
    path(
        "machine-oracle/",
        RedirectView.as_view(pattern_name="web-scan-run-list", permanent=False),
        name="web-oracle-overview",
    ),
    path("reports/", report_views.reports_overview_view, name="web-reports-overview"),
    path("governance/", views.governance_overview_view, name="web-governance-overview"),
    path("settings/", views.settings_overview_view, name="web-settings-overview"),
    path("campaigns/", views.campaign_list_view, name="web-campaign-list"),
    path("campaigns/<str:campaign_id>/", views.campaign_detail_view, name="web-campaign-detail"),
    path("readiness/<str:campaign_id>/", views.readiness_view, name="web-readiness-detail"),
    path("roles/", views.role_list_view, name="web-role-list"),
    path("roles/<str:role_id>/", views.role_detail_view, name="web-role-detail"),
    path("skills/", views.skill_list_view, name="web-skill-list"),
    path("skills/<str:skill_id>/", views.skill_detail_view, name="web-skill-detail"),
    path("agent/runs/", views.agent_run_list_view, name="web-agent-run-list"),
    path("agent/runs/<str:run_id>/", views.agent_run_detail_view, name="web-agent-run-detail"),
    path(
        "agent/runs/<str:run_id>/activity/",
        views.agent_activity_view,
        name="web-agent-run-activity",
    ),
    path(
        "agent/runs/<str:run_id>/activity/stream/",
        stream_views.agent_activity_stream_view,
        name="web-agent-run-activity-stream",
    ),
    path("agent/runs/<str:run_id>/stop/", views.stop_run_view, name="web-agent-run-stop"),
    path("approvals/", operations_views.approval_list_view, name="web-approval-list"),
    path(
        "approvals/<str:request_id>/",
        operations_views.approval_detail_view,
        name="web-approval-detail",
    ),
    path(
        "approvals/<str:request_id>/decision/",
        operations_views.approval_decision_view,
        name="web-approval-decision",
    ),
    path(
        "security-tools/",
        operations_views.security_tool_registry_view,
        name="web-security-tool-registry",
    ),
    path(
        "advanced-assessment/",
        operations_views.advanced_profiles_view,
        name="web-advanced-profiles",
    ),
    path(
        "mobile-analysis/",
        operations_views.mobile_analysis_view,
        name="web-mobile-analysis",
    ),
    path("pilot/plans/", views.pilot_plan_list_view, name="web-pilot-plan-list"),
    path("pilot/plans/<str:plan_id>/", views.pilot_plan_detail_view, name="web-pilot-plan-detail"),
    path(
        "pilot/plans/<str:plan_id>/validation/",
        views.pilot_plan_validation_view,
        name="web-pilot-plan-validation",
    ),
]
