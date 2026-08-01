from pathlib import Path


def replace_once(path: Path, old: str, new: str, *, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block in {path}, found {count}")
    path.write_text(text.replace(old, new), encoding="utf-8")


urls = Path("vulnhunter/web/urls.py")
replace_once(
    urls,
    '''    operations_views,
    remediation_review_conversation_views,
''',
    '''    operations_views,
    remediation_final_report_conversation_views,
    remediation_final_report_views,
    remediation_review_conversation_views,
''',
    label="final report URL imports",
)
replace_once(
    urls,
    '''    path(
        "workspace/remediation-review/",
        remediation_review_conversation_views.remediation_review_chat_view,
        name="web-conversation-remediation-review",
    ),
''',
    '''    path(
        "workspace/remediation-review/",
        remediation_review_conversation_views.remediation_review_chat_view,
        name="web-conversation-remediation-review",
    ),
    path(
        "workspace/remediation-final-report/",
        remediation_final_report_conversation_views.remediation_final_report_chat_view,
        name="web-conversation-remediation-final-report",
    ),
''',
    label="final report chat route",
)
replace_once(
    urls,
    '''    path(
        "findings/<str:finding_id>/remediation/review/",
        remediation_review_views.remediation_review_view,
        name="web-remediation-review",
    ),
''',
    '''    path(
        "findings/<str:finding_id>/remediation/review/",
        remediation_review_views.remediation_review_view,
        name="web-remediation-review",
    ),
    path(
        "findings/<str:finding_id>/remediation/report/",
        remediation_final_report_views.remediation_final_report_view,
        name="web-remediation-final-report",
    ),
    path(
        "findings/<str:finding_id>/remediation/report/download/<slug:artifact_format>/",
        remediation_final_report_views.remediation_final_report_download_view,
        name="web-remediation-final-report-download",
    ),
''',
    label="final report protected routes",
)

report_module = Path("vulnhunter/reports/final_remediation.py")
replace_once(
    report_module,
    '''                    affected_component=redact_text(finding.affected_component),
''',
    '''                    affected_component=redact_text(
                        finding.affected_component or "Not specified"
                    ),
''',
    label="optional affected component",
)

report_views = Path("vulnhunter/web/remediation_final_report_views.py")
replace_once(
    report_views,
    '''    downloads: dict[str, str] = {}
    if bundle is not None:
        downloads = {
            item.format.value: remediation_final_report_download_url(
                finding_id,
                item.format.value,
                workspace_id,
            )
            for item in bundle.manifest.artifacts
        }
''',
    '''    artifact_downloads: list[dict[str, object]] = []
    if bundle is not None:
        artifact_downloads = [
            {
                "artifact": item,
                "url": remediation_final_report_download_url(
                    finding_id,
                    item.format.value,
                    workspace_id,
                ),
            }
            for item in bundle.manifest.artifacts
        ]
''',
    label="artifact download presentation",
)
replace_once(
    report_views,
    '''            "download_urls": downloads,
''',
    '''            "artifact_downloads": artifact_downloads,
''',
    label="artifact download context",
)

template = Path("vulnhunter/web/templates/web/remediation_final_report.html")
replace_once(
    template,
    '''      <ul class="vh-compact-list">
        {% for artifact in report_bundle.manifest.artifacts %}
        <li><span><strong>{{ artifact.format.value|upper }}</strong> — {{ artifact.size_bytes }} bytes — <code>{{ artifact.sha256 }}</code></span>{% if artifact.format.value in download_urls %}<a class="vh-button-secondary" href="{{ download_urls|get_item:artifact.format.value }}">Download</a>{% endif %}</li>
        {% endfor %}
      </ul>
''',
    '''      <ul class="vh-compact-list">
        {% for download in artifact_downloads %}
        <li><span><strong>{{ download.artifact.format.value|upper }}</strong> — {{ download.artifact.size_bytes }} bytes — <code>{{ download.artifact.sha256 }}</code></span><a class="vh-button-secondary" href="{{ download.url }}">Download</a></li>
        {% endfor %}
      </ul>
''',
    label="artifact download template",
)

state = Path("vulnhunter/web/remediation_conversation_state.py")
replace_once(
    state,
    '''def remediation_review_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-review", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def _verification_payload(reference) -> dict[str, object]:
''',
    '''def remediation_review_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-review", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def remediation_final_report_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-final-report", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def _verification_payload(reference) -> dict[str, object]:
''',
    label="final report URL helper",
)
replace_once(
    state,
    '''def _finding_payload(
''',
    '''def _report_payload(reference) -> dict[str, object]:
    return {
        "report_id": reference.report_id,
        "manifest_id": reference.manifest_id,
        "report_sha256": reference.report_sha256,
        "manifest_sha256": reference.manifest_sha256,
        "generator_id": reference.generator_id,
        "generator_identity_sha256": reference.generator_identity_sha256,
        "fixed_revision": reference.fixed_revision,
        "review_receipt_id": reference.review_receipt_id,
        "formats": list(reference.formats),
        "release_state": "unreleased",
        "created_at": reference.created_at.isoformat(),
    }


def _finding_payload(
''',
    label="final report payload helper",
)
replace_once(
    state,
    '''    review_history = [_review_payload(item) for item in remediation.review_history]
    latest_review = review_history[-1] if review_history else None
    return {
        "schema_version": "1.2",
''',
    '''    review_history = [_review_payload(item) for item in remediation.review_history]
    latest_review = review_history[-1] if review_history else None
    report_history = [_report_payload(item) for item in remediation.report_history]
    latest_report = report_history[-1] if report_history else None
    return {
        "schema_version": "1.3",
''',
    label="final report history payload",
)
replace_once(
    state,
    '''            "review_history": review_history,
            "latest_review": latest_review,
            "created_at": remediation.created_at.isoformat() if remediation.created_at else None,
''',
    '''            "review_history": review_history,
            "latest_review": latest_review,
            "report_history": report_history,
            "latest_report": latest_report,
            "created_at": remediation.created_at.isoformat() if remediation.created_at else None,
''',
    label="final report history fields",
)
replace_once(
    state,
    '''        "review_url": remediation_review_url(finding.finding_id, workspace_id),
        "workspace_url": remediation_workspace_url(workspace_id),
''',
    '''        "review_url": remediation_review_url(finding.finding_id, workspace_id),
        "report_url": remediation_final_report_url(finding.finding_id, workspace_id),
        "workspace_url": remediation_workspace_url(workspace_id),
''',
    label="final report workspace URL",
)
replace_once(
    state,
    '''    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}
    event_key = f"remediation:{remediation_id}:{state}:{revision}"
''',
    '''    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}
    latest_report = remediation.get("latest_report")
    latest_report = latest_report if isinstance(latest_report, dict) else {}
    event_key = f"remediation:{remediation_id}:{state}:{revision}"
''',
    label="final report event payload",
)
replace_once(
    state,
    '''    elif state == "review_approved":
        boundary = (
            "Independent review approved report readiness; merge and closure remain separate."
        )
    else:
''',
    '''    elif state == "review_approved":
        boundary = (
            "Independent review approved report readiness; merge and closure remain separate."
        )
    elif state == "report_generated":
        boundary = (
            "The signed final report is generated but unreleased; closure and publication remain "
            "separate."
        )
    else:
''',
    label="final report event boundary",
)
replace_once(
    state,
    '''                "review_outcome": latest_review.get("outcome"),
                "report_state": graph.get("report_state"),
''',
    '''                "review_outcome": latest_review.get("outcome"),
                "final_report_id": latest_report.get("report_id"),
                "final_report_manifest_id": latest_report.get("manifest_id"),
                "release_state": latest_report.get("release_state"),
                "report_state": graph.get("report_state"),
''',
    label="final report event metadata",
)
replace_once(
    state,
    '''    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}

    if intent == "status":
''',
    '''    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}
    latest_report = remediation.get("latest_report")
    latest_report = latest_report if isinstance(latest_report, dict) else {}

    if intent == "status":
''',
    label="final report chat payload",
)
replace_once(
    state,
    '''    if intent == "status":
        if latest_review:
''',
    '''    if intent == "status":
        if latest_report:
            return (
                f"Remediation for {finding_id} is {state}. Final report "
                f"{latest_report.get('report_id', 'unknown')} is generated with signed manifest "
                f"{latest_report.get('manifest_id', 'unknown')} and remains unreleased. Finding "
                "closure, release and publication are not implied."
            )
        if latest_review:
''',
    label="final report status chat",
)
replace_once(
    state,
    '''    if intent == "results":
        if latest_review:
''',
    '''    if intent == "results":
        if latest_report:
            return (
                f"The immutable final report is {latest_report.get('report_id', 'unknown')} with "
                f"manifest {latest_report.get('manifest_id', 'unknown')}. Available formats: "
                f"{', '.join(latest_report.get('formats') or []) or 'unknown'}. The release state "
                "is unreleased."
            )
        if latest_review:
''',
    label="final report results chat",
)
replace_once(
    state,
    '''        if state == "review_approved":
            return (
                "Independent review approved the evidence. The next milestone is governed final "
                "report generation; merge, closure, release and publication remain separate."
            )
        if state == "cancelled":
''',
    '''        if state == "review_approved":
            return (
                "Independent review approved the evidence. The next milestone is governed final "
                "report generation; merge, closure, release and publication remain separate."
            )
        if state == "report_generated":
            return (
                "The signed report and artifact manifest are complete but unreleased. The next "
                "milestone is a dedicated human-authorised release/publication service; this "
                "report does not close the finding."
            )
        if state == "cancelled":
''',
    label="final report next-step chat",
)
replace_once(
    state,
    '''    "remediation_detail_url",
    "remediation_finding_store",
''',
    '''    "remediation_detail_url",
    "remediation_final_report_url",
    "remediation_finding_store",
''',
    label="final report helper export",
)

remediation_views = Path("vulnhunter/web/remediation_views.py")
replace_once(
    remediation_views,
    '''from vulnhunter.security import redact_text
''',
    '''from vulnhunter.reports import FinalRemediationReportError
from vulnhunter.security import redact_text
''',
    label="final report error import",
)
replace_once(
    remediation_views,
    '''from vulnhunter.web.remediation_fix_verification import (
''',
    '''from vulnhunter.web.final_report_service import final_report_store
from vulnhunter.web.remediation_final_report_views import remediation_final_report_url
from vulnhunter.web.remediation_fix_verification import (
''',
    label="final report detail imports",
)
replace_once(
    remediation_views,
    '''    active_states = {
''',
    '''    latest_report = remediation.report_history[-1] if remediation.report_history else None
    report_bundle = None
    if latest_report is not None:
        try:
            report_bundle = final_report_store().load(latest_report.report_id)
        except FinalRemediationReportError:
            report_bundle = None
    active_states = {
''',
    label="final report detail state",
)
replace_once(
    remediation_views,
    '''            "review_bundle": review_bundle,
            "verification_url": remediation_verify_url(finding_id, workspace_id),
''',
    '''            "review_bundle": review_bundle,
            "latest_report": latest_report,
            "report_bundle": report_bundle,
            "verification_url": remediation_verify_url(finding_id, workspace_id),
''',
    label="final report detail context",
)
replace_once(
    remediation_views,
    '''            "review_url": remediation_review_url(finding_id, workspace_id),
            "workspace_return_url": remediation_workspace_url(workspace_id),
''',
    '''            "review_url": remediation_review_url(finding_id, workspace_id),
            "report_url": remediation_final_report_url(finding_id, workspace_id),
            "workspace_return_url": remediation_workspace_url(workspace_id),
''',
    label="final report detail URL",
)
replace_once(
    remediation_views,
    '''            "can_review": remediation.state == RemediationState.AWAITING_REVIEW,
            "can_cancel": (
''',
    '''            "can_review": remediation.state == RemediationState.AWAITING_REVIEW,
            "can_generate_report": remediation.state == RemediationState.REVIEW_APPROVED,
            "can_cancel": (
''',
    label="final report detail permission",
)

detail = Path("vulnhunter/web/templates/web/remediation_detail.html")
replace_once(
    detail,
    '''      {% if can_review %}<a class="vh-button-primary" href="{{ review_url }}">Open independent review</a>{% endif %}
''',
    '''      {% if can_generate_report %}<a class="vh-button-primary" href="{{ report_url }}">Generate final report</a>{% endif %}
      {% if can_review %}<a class="vh-button-primary" href="{{ review_url }}">Open independent review</a>{% endif %}
''',
    label="final report detail button",
)
report_section = '''

  {% if latest_report %}
  <section class="vh-surface">
    <header class="vh-surface-header"><div><h2>Signed final remediation report</h2><p>The artifact set is integrity-bound and unreleased. It does not close the finding or grant publication authority.</p></div></header>
    <div class="vh-surface-body">
      <dl class="vh-terminal-facts">
        <div><dt>Report ID</dt><dd>{{ latest_report.report_id }}</dd></div>
        <div><dt>Manifest ID</dt><dd>{{ latest_report.manifest_id }}</dd></div>
        <div><dt>Generator</dt><dd>{{ latest_report.generator_id }}</dd></div>
        <div><dt>Fixed revision</dt><dd><code>{{ latest_report.fixed_revision }}</code></dd></div>
        <div><dt>Manifest SHA-256</dt><dd><code>{{ latest_report.manifest_sha256 }}</code></dd></div>
        <div><dt>Formats</dt><dd>{{ latest_report.formats|join:", " }}</dd></div>
        <div><dt>Release state</dt><dd>unreleased</dd></div>
      </dl>
      {% if report_bundle %}<p>{{ report_bundle.report.evidence_citations|length }} redacted evidence citations are included. Raw evidence bytes are not embedded.</p>{% else %}<div class="vh-alert vh-alert-danger" role="alert">The report pointer exists, but its signed manifest or artifact integrity could not be verified.</div>{% endif %}
      <a class="vh-button-secondary" href="{{ report_url }}">Inspect final report</a>
    </div>
  </section>
  {% elif remediation.state.value == 'review_approved' %}
  <section class="vh-surface"><div class="vh-empty-panel"><h3>Final report generation ready</h3><p>The exact fixed revision, passed retest and approved independent review can now be rendered into signed unreleased artifacts.</p><a class="vh-button-primary" href="{{ report_url }}">Generate protected report</a></div></section>
  {% endif %}
'''
replace_once(
    detail,
    '''
  {% if can_cancel %}
''',
    report_section + '''
  {% if can_cancel %}
''',
    label="final report detail section",
)

js = Path("vulnhunter/web/static/web/conversation-runtime-compat.js")
replace_once(
    js,
    '''  const remediationReviewMessage = (value) => {
''',
    '''  const finalReportMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\\s+/g, " ").trim();
    return /\\b(generate final report|create final report|open final report|final remediation report|export final report|build final report)\\b/.test(text);
  };

  const remediationReviewMessage = (value) => {
''',
    label="final report JS detector",
)
replace_once(
    js,
    '''      const remediationReview = remediationReviewMessage(message);
      const remediation = !retest && !remediationReview && remediationMessage(message);
      const sourceHunt = sourceHuntMessage(message);
      if (!activeValidation && !retest && !remediationReview && !remediation && !sourceHunt) return;
''',
    '''      const finalReport = finalReportMessage(message);
      const remediationReview = !finalReport && remediationReviewMessage(message);
      const remediation = !retest && !finalReport && !remediationReview && remediationMessage(message);
      const sourceHunt = sourceHuntMessage(message);
      if (!activeValidation && !retest && !finalReport && !remediationReview && !remediation && !sourceHunt) return;
''',
    label="final report JS precedence",
)
replace_once(
    js,
    '''      if (sourceHunt && !activeValidation && !retest && !remediationReview && !remediation) {
''',
    '''      if (sourceHunt && !activeValidation && !retest && !finalReport && !remediationReview && !remediation) {
''',
    label="final report JS source guard",
)
replace_once(
    js,
    '''        : retest
          ? "/workspace/retest/"
          : remediationReview
''',
    '''        : retest
          ? "/workspace/retest/"
          : finalReport
            ? "/workspace/remediation-final-report/"
            : remediationReview
''',
    label="final report JS endpoint",
)
replace_once(
    js,
    '''        : retest
          ? "Governed Retest"
          : remediationReview
''',
    '''        : retest
          ? "Governed Retest"
          : finalReport
            ? "Final Remediation Report"
            : remediationReview
''',
    label="final report JS label",
)
text = js.read_text(encoding="utf-8")
text = text.replace("?v=20260801-review1", "?v=20260801-report1")
text = text.replace(
    "controlled validation, remediation, retesting and independent review",
    "controlled validation, remediation, retesting, independent review and final reporting",
)
js.write_text(text, encoding="utf-8")

env = Path(".env.example")
replace_once(
    env,
    '''VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE=/run/secrets/remediation_review_signing_key
''',
    '''VULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE=/run/secrets/remediation_review_signing_key
VULNHUNTER_FINAL_REPORT_ROOT=/srv/vulnhunter/evidence/final-reports
VULNHUNTER_FINAL_REPORT_SIGNING_KEY_FILE=/run/secrets/final_report_signing_key
VULNHUNTER_FINAL_REPORT_PDF_ENABLED=false
''',
    label="final report environment",
)

architecture = Path("docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md")
replace_once(
    architecture,
    '''**Implementation status:** `IN_PROGRESS` — signed independent remediation review can now open an authoritative `ready_for_report` gate only after an exact passed retest. Stable final report schemas, evidence rendering, export manifests, integrity hashes, PDF activation and separate release authorisation remain unfinished.
''',
    '''**Implementation status:** `DONE` foundation — an identity-separated governed report writer can now generate a stable final-remediation JSON schema, human-readable HTML, redacted evidence citations, explicit limitations, an HMAC-SHA256 signed unreleased export manifest and optional deterministic PDF only when the renderer readiness gate is enabled. The exact report and manifest are append-only, integrity-checked, projected into the authoritative graph and durable chat workspace, and advance only to `report_generated`. Dedicated release/publication authorisation, correction/revocation, deployment and finding closure remain unfinished Step 30 work.
''',
    label="Step 29 implementation status",
)
replace_once(
    architecture,
    '''| Reporting and PDF | `PARTIAL` / `ACTIVATION_REQUIRED` | Final report schemas, PDF renderer activation, signed export manifests and release workflow. |
''',
    '''| Reporting and PDF | `DONE` foundation / `ACTIVATION_REQUIRED` | Stable final-remediation JSON/HTML, signed unreleased manifests and disabled-by-default deterministic PDF readiness are implemented; production PDF activation and the separate release/publication workflow remain. |
''',
    label="reporting gap row",
)
replace_once(
    architecture,
    '''**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation, verified-finding remediation planning, immutable fixed-revision verification, governed retest and signed independent remediation review now create or update workspace-bound authoritative task graphs and project approval, queue, execution readiness, bounded rework, fixed-verdict progression, before/after retest outcomes, reviewer decisions, report readiness, cancellation, failed-closed and user-facing chat stages from durable stores. Controlled patch-execution integration and final report generation still require migration to the shared graph.
''',
    '''**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation, verified-finding remediation planning, immutable fixed-revision verification, governed retest, signed independent remediation review and governed final report generation now create or update workspace-bound authoritative task graphs and project approval, queue, execution readiness, bounded rework, fixed-verdict progression, before/after retest outcomes, reviewer decisions, report readiness, generated-unreleased state, cancellation, failed-closed and user-facing chat stages from durable stores. Controlled patch-execution integration and the dedicated publication service still require migration to the shared graph.
''',
    label="Step 18 final report status",
)
