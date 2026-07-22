from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from django.contrib.auth.decorators import login_required
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.decorators.cache import cache_control
from django.views.decorators.http import require_GET

from vulnhunter.reports import ReportExportError, ReportExporter
from vulnhunter.web.services import (
    WebPermissionDenied,
    authorized_actor,
    get_pilot_plan_record,
    list_pilot_plan_records,
    navigation_for,
)


def _authorize(request: HttpRequest):
    return authorized_actor(request.user, required_actions=("campaign.read", "report.read"))


def _formats() -> tuple[dict[str, str | None], ...]:
    return (
        {"name": "HTML", "state": "download available", "slug": "html"},
        {"name": "JSON", "state": "download available", "slug": "json"},
        {"name": "SARIF", "state": "finding context required", "slug": None},
        {"name": "Evidence ZIP", "state": "evidence context required", "slug": None},
        {"name": "Attack-path SVG", "state": "attack path required", "slug": None},
        {"name": "PDF", "state": "renderer not active", "slug": None},
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def reports_overview_view(request: HttpRequest) -> HttpResponse:
    """Show real report inputs and renderer/export contract state."""
    try:
        _authorize(request)
    except WebPermissionDenied as exc:
        return render(
            request,
            "web/denied.html",
            {
                "page_title": "Access Denied",
                "denied_message": str(exc),
                "current_route": "web-reports-overview",
                "navigation": navigation_for(request.user),
            },
            status=403,
        )
    return render(
        request,
        "web/reports_overview.html",
        {
            "page_title": "Reports",
            "current_route": "web-reports-overview",
            "navigation": navigation_for(request.user),
            "records": list_pilot_plan_records(),
            "report_formats": _formats(),
        },
    )


@cache_control(private=True, no_store=True)
@login_required
@require_GET
def pilot_plan_download_view(
    request: HttpRequest,
    plan_id: str,
    export_format: str,
) -> HttpResponse:
    """Generate one safe, temporary report artifact from a validated pilot plan."""
    try:
        _authorize(request)
    except WebPermissionDenied as exc:
        return HttpResponse(str(exc), status=403, content_type="text/plain; charset=utf-8")
    if export_format not in {"json", "html"}:
        raise Http404("This report format is not available for pilot plans.")
    try:
        record = get_pilot_plan_record(plan_id)
    except FileNotFoundError as exc:
        raise Http404("Pilot plan does not exist.") from exc
    if record.plan is None or record.report is None:
        raise Http404("Pilot plan report is not valid or available.")

    payload: dict[str, object] = {
        "schema_version": "1.0",
        "plan": record.plan.model_dump(mode="json"),
        "validation": record.report.model_dump(mode="json"),
    }
    provenance = (record.report.plan_sha256, record.report.report_sha256)
    try:
        with TemporaryDirectory(prefix="vulnhunter-report-") as temporary:
            exporter = ReportExporter(Path(temporary))
            if export_format == "json":
                artifact = exporter.export_json(
                    artifact_id=f"pilot-plan-{record.plan_id}",
                    payload=payload,
                    provenance=provenance,
                )
            else:
                artifact = exporter.export_html(
                    artifact_id=f"pilot-plan-{record.plan_id}",
                    title=f"VulnHunter pilot plan — {record.plan.title}",
                    payload=payload,
                    provenance=provenance,
                )
            data = Path(artifact.path).read_bytes()
    except (OSError, ReportExportError) as exc:
        return HttpResponse(
            f"Report generation failed closed: {exc}",
            status=409,
            content_type="text/plain; charset=utf-8",
        )

    response = HttpResponse(data, content_type=artifact.content_type)
    response["Content-Disposition"] = f'attachment; filename="{artifact.filename}"'
    response["X-VulnHunter-Artifact-SHA256"] = artifact.sha256
    return response
