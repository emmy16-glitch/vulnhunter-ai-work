from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block, found {count}")
    return text.replace(old, new)


urls_path = Path("vulnhunter/web/urls.py")
urls = urls_path.read_text(encoding="utf-8")
urls = replace_once(
    urls,
    "    remediation_views,\n    report_views,\n",
    "    remediation_review_conversation_views,\n    remediation_review_views,\n    remediation_views,\n    report_views,\n",
    label="review URL imports",
)
urls = replace_once(
    urls,
    '''    path(
        "workspace/remediation/",
        remediation_views.remediation_chat_view,
        name="web-conversation-remediation",
    ),
''',
    '''    path(
        "workspace/remediation/",
        remediation_views.remediation_chat_view,
        name="web-conversation-remediation",
    ),
    path(
        "workspace/remediation-review/",
        remediation_review_conversation_views.remediation_review_chat_view,
        name="web-conversation-remediation-review",
    ),
''',
    label="review chat route",
)
urls = replace_once(
    urls,
    '''    path(
        "findings/<str:finding_id>/remediation/verify/",
        remediation_views.remediation_verify_view,
        name="web-remediation-verify",
    ),
''',
    '''    path(
        "findings/<str:finding_id>/remediation/verify/",
        remediation_views.remediation_verify_view,
        name="web-remediation-verify",
    ),
    path(
        "findings/<str:finding_id>/remediation/review/",
        remediation_review_views.remediation_review_view,
        name="web-remediation-review",
    ),
''',
    label="protected review route",
)
urls_path.write_text(urls, encoding="utf-8")


state_path = Path("vulnhunter/web/remediation_conversation_state.py")
state = state_path.read_text(encoding="utf-8")
state = replace_once(
    state,
    '''def remediation_verify_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-verify", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def _verification_payload(reference) -> dict[str, object]:
''',
    '''def remediation_verify_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-verify", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def remediation_review_url(finding_id: str, workspace_id: str | None) -> str:
    base = reverse("web-remediation-review", kwargs={"finding_id": finding_id})
    return f"{base}?{urlencode({'thread': workspace_id})}" if workspace_id else base


def _verification_payload(reference) -> dict[str, object]:
''',
    label="review URL helper",
)
state = replace_once(
    state,
    '''def _finding_payload(
''',
    '''def _review_payload(reference) -> dict[str, object]:
    return {
        "receipt_id": reference.receipt_id,
        "review_id": reference.review_id,
        "sha256": reference.sha256,
        "outcome": reference.outcome.value,
        "reviewer_id": reference.reviewer_id,
        "reviewer_identity_sha256": reference.reviewer_identity_sha256,
        "fixed_revision": reference.fixed_revision,
        "retest_receipt_id": reference.retest_receipt_id,
        "created_at": reference.created_at.isoformat(),
    }


def _finding_payload(
''',
    label="review payload helper",
)
state = replace_once(
    state,
    '''    latest_verification = verification_history[-1] if verification_history else None
    return {
        "schema_version": "1.1",
''',
    '''    latest_verification = verification_history[-1] if verification_history else None
    review_history = [_review_payload(item) for item in remediation.review_history]
    latest_review = review_history[-1] if review_history else None
    return {
        "schema_version": "1.2",
''',
    label="review history payload",
)
state = replace_once(
    state,
    '''            "latest_verification": latest_verification,
            "created_at": remediation.created_at.isoformat() if remediation.created_at else None,
''',
    '''            "latest_verification": latest_verification,
            "review_history": review_history,
            "latest_review": latest_review,
            "created_at": remediation.created_at.isoformat() if remediation.created_at else None,
''',
    label="review history fields",
)
state = replace_once(
    state,
    '''        "verify_url": remediation_verify_url(finding.finding_id, workspace_id),
        "workspace_url": remediation_workspace_url(workspace_id),
''',
    '''        "verify_url": remediation_verify_url(finding.finding_id, workspace_id),
        "review_url": remediation_review_url(finding.finding_id, workspace_id),
        "workspace_url": remediation_workspace_url(workspace_id),
''',
    label="review workspace URL",
)
state = replace_once(
    state,
    '''    latest = remediation.get("latest_verification")
    latest = latest if isinstance(latest, dict) else {}
    event_key = f"remediation:{remediation_id}:{state}:{revision}"
    if state == "ready_for_retest":
        boundary = "Fix verification passed; retest, review, merge and release remain separate."
    elif state == "needs_rework":
        boundary = "The verifier requires rework; no fixed, retested or merged claim exists."
    else:
        boundary = "Developer implementation, fix verification, review and merge remain separate."
''',
    '''    latest = remediation.get("latest_verification")
    latest = latest if isinstance(latest, dict) else {}
    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}
    event_key = f"remediation:{remediation_id}:{state}:{revision}"
    if state == "ready_for_retest":
        boundary = "Fix verification passed; retest, review, merge and release remain separate."
    elif state in {"needs_rework", "review_needs_rework"}:
        boundary = "Bounded rework is required; report, merge and closure remain blocked."
    elif state == "awaiting_review":
        boundary = "The retest passed; an independent governed reviewer must decide next."
    elif state == "review_approved":
        boundary = "Independent review approved report readiness; merge and closure remain separate."
    else:
        boundary = "Developer implementation, fix verification, review and merge remain separate."
''',
    label="review event boundaries",
)
state = replace_once(
    state,
    '''                "verification_verdict": latest.get("verdict"),
            },
''',
    '''                "verification_verdict": latest.get("verdict"),
                "review_receipt_id": latest_review.get("receipt_id"),
                "review_outcome": latest_review.get("outcome"),
                "report_state": graph.get("report_state"),
            },
''',
    label="review event metadata",
)
state = replace_once(
    state,
    '''    latest = remediation.get("latest_verification")
    latest = latest if isinstance(latest, dict) else {}

    if intent == "status":
''',
    '''    latest = remediation.get("latest_verification")
    latest = latest if isinstance(latest, dict) else {}
    latest_review = remediation.get("latest_review")
    latest_review = latest_review if isinstance(latest_review, dict) else {}

    if intent == "status":
''',
    label="review chat payload",
)
state = replace_once(
    state,
    '''    if intent == "status":
        if latest:
''',
    '''    if intent == "status":
        if latest_review:
            return (
                f"Remediation for {finding_id} is {state}. Independent review returned "
                f"{latest_review.get('outcome', 'unknown')} in signed receipt "
                f"{latest_review.get('receipt_id', 'unknown')}. Report state: "
                f"{graph.get('report_state', 'unknown')}. Merge, closure and publication are not "
                "implied."
            )
        if latest:
''',
    label="review status chat",
)
state = replace_once(
    state,
    '''    if intent == "results":
        if latest:
''',
    '''    if intent == "results":
        if latest_review:
            return (
                f"The signed independent review receipt is "
                f"{latest_review.get('receipt_id', 'unknown')} with outcome "
                f"{latest_review.get('outcome', 'unknown')}. It binds reviewer identity, fixed "
                "revision and passed retest, but it is not a final report, merge or closure."
            )
        if latest:
''',
    label="review results chat",
)
state = replace_once(
    state,
    '''        if state == "cancelled":
            return (
''',
    '''        if state == "awaiting_review":
            return (
                "The exact passed retest is ready for an independent reviewer. Open the protected "
                "review workspace; governance authentication and checklist authority stay outside chat."
            )
        if state == "review_needs_rework":
            return (
                "The signed reviewer decision requires bounded remediation rework. The prior review "
                "receipt remains append-only and report generation stays blocked."
            )
        if state == "review_approved":
            return (
                "Independent review approved the evidence. The next milestone is governed final "
                "report generation; merge, closure, release and publication remain separate."
            )
        if state == "cancelled":
            return (
''',
    label="review next-step chat",
)
state = replace_once(
    state,
    '''    "remediation_verify_url",
    "remediation_workspace_url",
''',
    '''    "remediation_review_url",
    "remediation_verify_url",
    "remediation_workspace_url",
''',
    label="review helper export",
)
state_path.write_text(state, encoding="utf-8")


views_path = Path("vulnhunter/web/remediation_views.py")
views = views_path.read_text(encoding="utf-8")
views = replace_once(
    views,
    '''from vulnhunter.web.remediation_fix_verification import (
    remediation_fix_verification_service,
    remediation_fix_verification_store,
)
''',
    '''from vulnhunter.web.remediation_fix_verification import (
    remediation_fix_verification_service,
    remediation_fix_verification_store,
)
from vulnhunter.web.remediation_review_service import remediation_review_receipt_store
from vulnhunter.web.remediation_review_views import remediation_review_url
''',
    label="review detail imports",
)
views = replace_once(
    views,
    '''    active_states = {
        RemediationState.READY_FOR_IMPLEMENTATION,
        RemediationState.NEEDS_REWORK,
    }
''',
    '''    latest_review = remediation.review_history[-1] if remediation.review_history else None
    review_bundle = None
    if latest_review is not None:
        try:
            review_bundle = remediation_review_receipt_store().load(latest_review.receipt_id)
        except Exception:
            review_bundle = None
    active_states = {
        RemediationState.READY_FOR_IMPLEMENTATION,
        RemediationState.NEEDS_REWORK,
        RemediationState.REVIEW_NEEDS_REWORK,
    }
''',
    label="review detail state",
)
views = replace_once(
    views,
    '''            "verification_bundle": verification_bundle,
            "verification_url": remediation_verify_url(finding_id, workspace_id),
''',
    '''            "verification_bundle": verification_bundle,
            "latest_review": latest_review,
            "review_bundle": review_bundle,
            "verification_url": remediation_verify_url(finding_id, workspace_id),
            "review_url": remediation_review_url(finding_id, workspace_id),
''',
    label="review detail context",
)
views = replace_once(
    views,
    '''            "can_cancel": (
                remediation.state in active_states
                and (request.user.is_staff or request.user.is_superuser)
            ),
''',
    '''            "can_review": remediation.state == RemediationState.AWAITING_REVIEW,
            "can_cancel": (
                remediation.state in active_states
                and (request.user.is_staff or request.user.is_superuser)
            ),
''',
    label="review detail permission",
)
views_path.write_text(views, encoding="utf-8")


template_path = Path("vulnhunter/web/templates/web/remediation_detail.html")
template = template_path.read_text(encoding="utf-8")
template = replace_once(
    template,
    '''      {% if can_verify %}<a class="vh-button-primary" href="{{ verification_url }}">Record implementation and verify</a>{% endif %}
''',
    '''      {% if can_review %}<a class="vh-button-primary" href="{{ review_url }}">Open independent review</a>{% endif %}
      {% if can_verify %}<a class="vh-button-primary" href="{{ verification_url }}">Record implementation and verify</a>{% endif %}
''',
    label="review detail button",
)
review_section = '''

  {% if latest_review %}
  <section class="vh-surface">
    <header class="vh-surface-header"><div><h2>Latest signed independent review</h2><p>This receipt controls report readiness only; it does not merge, close, release or publish.</p></div></header>
    <div class="vh-surface-body">
      <dl class="vh-terminal-facts">
        <div><dt>Receipt ID</dt><dd>{{ latest_review.receipt_id }}</dd></div>
        <div><dt>Outcome</dt><dd>{{ latest_review.outcome.value }}</dd></div>
        <div><dt>Reviewer</dt><dd>{{ latest_review.reviewer_id }}</dd></div>
        <div><dt>Fixed revision</dt><dd><code>{{ latest_review.fixed_revision }}</code></dd></div>
        <div><dt>Retest receipt</dt><dd>{{ latest_review.retest_receipt_id }}</dd></div>
        <div><dt>Receipt SHA-256</dt><dd><code>{{ latest_review.sha256 }}</code></dd></div>
      </dl>
      {% if review_bundle %}<h3>Review rationale</h3><p>{{ review_bundle.rationale }}</p>{% else %}<div class="vh-alert vh-alert-danger" role="alert">The signed receipt pointer exists, but its immutable bundle could not be verified.</div>{% endif %}
      <a class="vh-button-secondary" href="{{ review_url }}">Inspect signed review</a>
    </div>
  </section>
  {% elif remediation.state.value == 'awaiting_review' %}
  <section class="vh-surface"><div class="vh-empty-panel"><h3>Independent review required</h3><p>The governed retest passed. An identity-separated reviewer must evaluate the exact evidence before report generation can become ready.</p><a class="vh-button-primary" href="{{ review_url }}">Open protected review</a></div></section>
  {% endif %}
'''
template = replace_once(
    template,
    '''
  {% if can_cancel %}
''',
    review_section + '''
  {% if can_cancel %}
''',
    label="review detail section",
)
template_path.write_text(template, encoding="utf-8")


js_path = Path("vulnhunter/web/static/web/conversation-runtime-compat.js")
js = js_path.read_text(encoding="utf-8")
js = replace_once(
    js,
    '''  const remediationMessage = (value) => {
''',
    '''  const remediationReviewMessage = (value) => {
    const text = String(value || "").toLowerCase().replace(/\\s+/g, " ").trim();
    return /\\b(independent remediation review|review remediation|review the remediation|review the fix|approve remediation review)\\b/.test(text);
  };

  const remediationMessage = (value) => {
''',
    label="review JS detector",
)
js = replace_once(
    js,
    '''      const retest = retestMessage(message);
      const remediation = !retest && remediationMessage(message);
      const sourceHunt = sourceHuntMessage(message);
      if (!activeValidation && !retest && !remediation && !sourceHunt) return;
''',
    '''      const retest = retestMessage(message);
      const remediationReview = remediationReviewMessage(message);
      const remediation = !retest && !remediationReview && remediationMessage(message);
      const sourceHunt = sourceHuntMessage(message);
      if (!activeValidation && !retest && !remediationReview && !remediation && !sourceHunt) return;
''',
    label="review JS precedence",
)
js = replace_once(
    js,
    '''      if (sourceHunt && !activeValidation && !retest && !remediation) {
''',
    '''      if (sourceHunt && !activeValidation && !retest && !remediationReview && !remediation) {
''',
    label="review JS source guard",
)
js = replace_once(
    js,
    '''        : retest
          ? "/workspace/retest/"
          : remediation
''',
    '''        : retest
          ? "/workspace/retest/"
          : remediationReview
            ? "/workspace/remediation-review/"
            : remediation
''',
    label="review JS endpoint",
)
js = replace_once(
    js,
    '''        : retest
          ? "Governed Retest"
          : remediation
''',
    '''        : retest
          ? "Governed Retest"
          : remediationReview
            ? "Independent Remediation Review"
            : remediation
''',
    label="review JS label",
)
js = js.replace("?v=20260801-retest1", "?v=20260801-review1")
js = js.replace(
    "controlled validation, remediation and retesting",
    "controlled validation, remediation, retesting and independent review",
)
js_path.write_text(js, encoding="utf-8")


env_path = Path(".env.example")
env = env_path.read_text(encoding="utf-8")
env = replace_once(
    env,
    "VULNHUNTER_RETEST_RECEIPT_ROOT=/srv/vulnhunter/evidence/retest-receipts\n",
    "VULNHUNTER_RETEST_RECEIPT_ROOT=/srv/vulnhunter/evidence/retest-receipts\nVULNHUNTER_REMEDIATION_REVIEW_ROOT=/srv/vulnhunter/evidence/remediation-reviews\n",
    label="review receipt environment",
)
env_path.write_text(env, encoding="utf-8")
