from __future__ import annotations

from pathlib import Path

ROOT = Path.cwd()


def replace_once(relative: str, old: str, new: str) -> None:
    path = ROOT / relative
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"Expected one match in {relative}, found {count}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def write(relative: str, content: str) -> None:
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# Navigation and activation wiring.
replace_once(
    "vulnhunter/web/services.py",
    '''                "web-agent-run-stop",
            ),''',
    '''                "web-agent-run-stop",
                "web-lab-create",
                "web-lab-detail",
                "web-lab-approve",
                "web-lab-queue",
                "web-lab-stop",
                "web-lab-activity-stream",
            ),''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "active_routes": ("web-findings-overview",),
        },''',
    '''            "active_routes": ("web-findings-overview", "web-finding-detail"),
        },
        {
            "section_id": "analysis",
            "section_label": "Analysis",
            "label": "Mobile Analysis",
            "url_name": "web-mobile-analysis",
            "icon": "mobile",
            "actions": ("scan.create", "settings.manage"),
            "active_routes": ("web-mobile-analysis",),
        },
        {
            "section_id": "review",
            "section_label": "Review & Approval",
            "label": "Approval Centre",
            "url_name": "web-approval-list",
            "icon": "bell",
            "actions": ("settings.manage", "audit.read"),
            "active_routes": (
                "web-approval-list",
                "web-approval-detail",
                "web-approval-decision",
            ),
        },''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "section_label": "Independent Review",
            "label": "Review Queue",''',
    '''            "section_label": "Review & Approval",
            "label": "Review Queue",''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "active_routes": ("web-review-queue",),''',
    '''            "active_routes": ("web-review-queue", "web-review-detail"),''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "section_label": "Independent Review",
            "label": "Adjudications",''',
    '''            "section_label": "Review & Approval",
            "label": "Adjudications",''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "active_routes": ("web-adjudication-queue",),''',
    '''            "active_routes": ("web-adjudication-queue", "web-adjudication-detail"),''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "active_routes": ("web-release-list",),''',
    '''            "active_routes": ("web-release-list", "web-release-detail"),''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "active_routes": ("web-dataset-list",),''',
    '''            "active_routes": ("web-dataset-list", "web-dataset-detail"),''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "active_routes": ("web-model-list", "web-oracle-overview"),''',
    '''            "active_routes": (
                "web-model-list",
                "web-model-detail",
                "web-oracle-overview",
            ),''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''            "active_routes": ("web-reports-overview",),''',
    '''            "active_routes": (
                "web-reports-overview",
                "web-pilot-plan-list",
                "web-pilot-plan-detail",
                "web-pilot-plan-validation",
                "web-pilot-plan-download",
            ),''',
)
replace_once(
    "vulnhunter/web/services.py",
    '''                "web-skill-detail",
                "web-mobile-analysis",
            ),''',
    '''                "web-skill-detail",
            ),''',
)
replace_once(
    "vulnhunter/web/services.py",
    "execution_enabled=False,",
    "execution_enabled=settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED,",
)

replace_once(
    "vulnhunter/web/settings.py",
    '''VULNHUNTER_MOBILE_ARTIFACT_ROOT = os.environ.get(
    "VULNHUNTER_MOBILE_ARTIFACT_ROOT",
    str(BASE_DIR / ".local" / "mobile-artifacts"),
)
VULNHUNTER_MOBILE_MAX_APK_BYTES = env_int(''',
    '''VULNHUNTER_MOBILE_ARTIFACT_ROOT = os.environ.get(
    "VULNHUNTER_MOBILE_ARTIFACT_ROOT",
    str(BASE_DIR / ".local" / "mobile-artifacts"),
)
VULNHUNTER_MOBILE_STATIC_WORKER_POLICY = os.environ.get(
    "VULNHUNTER_MOBILE_STATIC_WORKER_POLICY",
    str(BASE_DIR / "config" / "security_tools" / "mobile_static_worker.json"),
)
VULNHUNTER_MOBILE_MAX_APK_BYTES = env_int(''',
)

# Real settings control plane.
replace_once(
    "vulnhunter/web/views.py",
    '''def settings_overview_view(request: HttpRequest) -> HttpResponse:
    try:
        _protected(request, required_actions=("audit.read", "dashboard.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))
    return _render(
        request,
        "web/settings_overview.html",
        {"page_title": "Settings", "intelligence_status": intelligence_status()},
    )''',
    '''def settings_overview_view(request: HttpRequest) -> HttpResponse:
    try:
        actor = _protected(request, required_actions=("audit.read", "dashboard.read"))
    except WebPermissionDenied as exc:
        return _denied(request, str(exc))

    status = product_service().load_status()
    state_copy = {
        "available": "Validated and available.",
        "empty": "Configured and healthy; no records exist yet.",
        "missing": "Required local state has not been created.",
        "invalid": "Configuration or integrity validation failed.",
        "unavailable": "A required dependency is not available.",
    }
    capability_rows = tuple(
        {
            "name": name,
            "state": capability.state.value,
            "detail": state_copy.get(capability.state.value, "State reported by the backend."),
        }
        for name, capability in (
            ("Authorization store", status.authorization_store),
            ("Governance store", status.governance_store),
            ("Role and skill registry", status.role_registry),
            ("Bounded agent runtime", status.agent_runtime),
            ("Dataset readiness", status.readiness),
            ("Audit evidence", status.audit_evidence),
        )
    )

    mobile_policy = Path(settings.VULNHUNTER_MOBILE_STATIC_WORKER_POLICY)
    activation_rows = (
        {
            "name": "Passive Nuclei enqueue",
            "enabled": bool(settings.VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED),
            "detail": (
                "Approved plans may be written to the signed worker spool."
                if settings.VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED
                else "Gated until the reviewed worker policy, signing key and local target are ready."
            ),
            "link": "web-security-tool-registry",
        },
        {
            "name": "Controlled active validation",
            "enabled": bool(settings.VULNHUNTER_ADVERSARY_LAB_ENABLED),
            "detail": (
                "Synthetic isolated validation workspaces are available."
                if settings.VULNHUNTER_ADVERSARY_LAB_ENABLED
                else "Gated in this environment; existing evidence remains readable."
            ),
            "link": "web-scan-run-list",
        },
        {
            "name": "Repository graph refresh",
            "enabled": bool(settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED),
            "detail": (
                "Explicit repository graph generation is enabled."
                if settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED
                else "Read-only validated graph loading is available; rebuild execution is gated."
            ),
            "link": "web-model-list",
        },
        {
            "name": "Sanitized advisory analysis",
            "enabled": bool(settings.VULNHUNTER_GROQ_ENABLED),
            "detail": (
                "Bounded advisory health checks are enabled; the provider remains non-authoritative."
                if settings.VULNHUNTER_GROQ_ENABLED
                else "Optional remote advisory routing is gated; deterministic workflows continue."
            ),
            "link": "web-model-list",
        },
        {
            "name": "Mobile static worker policy",
            "enabled": mobile_policy.is_file(),
            "detail": (
                "A local networkless static-analysis policy is present."
                if mobile_policy.is_file()
                else "Upload is available, but no reviewed static worker policy is present."
            ),
            "link": "web-mobile-analysis",
        },
    )
    enabled_count = sum(1 for row in activation_rows if row["enabled"])
    healthy_count = sum(
        1 for row in capability_rows if row["state"] in {"available", "empty"}
    )
    security_rows = (
        {"name": "Django debug", "safe": not settings.DEBUG, "value": "Off" if not settings.DEBUG else "On"},
        {"name": "HTTPS enforcement", "safe": bool(settings.SECURE_SSL_REDIRECT), "value": "Required" if settings.SECURE_SSL_REDIRECT else "Local-only"},
        {"name": "Session cookie", "safe": bool(settings.SESSION_COOKIE_HTTPONLY), "value": "HttpOnly"},
        {"name": "CSRF cookie", "safe": bool(settings.CSRF_COOKIE_HTTPONLY), "value": "HttpOnly"},
        {"name": "Frame embedding", "safe": settings.X_FRAME_OPTIONS == "DENY", "value": settings.X_FRAME_OPTIONS},
        {"name": "Content Security Policy", "safe": bool(settings.VULNHUNTER_CSP), "value": "Same-origin"},
    )
    identity = actor.governance_identity
    return _render(
        request,
        "web/settings_overview.html",
        {
            "page_title": "Settings",
            "intelligence_status": intelligence_status(),
            "capability_rows": capability_rows,
            "activation_rows": activation_rows,
            "enabled_count": enabled_count,
            "healthy_count": healthy_count,
            "security_rows": security_rows,
            "identity": identity,
            "product_roles": actor.product_roles,
            "database_engine": settings.DATABASES["default"]["ENGINE"].rsplit(".", 1)[-1],
            "environment_label": "Local debug" if settings.DEBUG else "Hardened runtime",
        },
    )''',
)

write(
    "vulnhunter/web/templates/web/settings_overview.html",
    '''{% extends "web/base.html" %}
{% load static %}
{% block content %}
<link rel="stylesheet" href="{% static 'web/settings.css' %}?v=20260722-audit">
<section class="vh-page-shell vh-settings-page">
  <header class="vh-page-header vh-settings-hero">
    <div><p class="vh-eyebrow">System control plane</p><h1>Settings &amp; readiness</h1><p>Inspect the real identity, security posture, local capabilities and activation gates used by this deployment. This page never reveals secrets or enables a control without its backend contract.</p></div>
    <div class="vh-page-actions"><a class="vh-button-secondary" href="{% url 'web-status' %}">System status</a><a class="vh-button-primary" href="{% url 'web-security-tool-registry' %}">Integrations &amp; tools</a></div>
  </header>

  <section class="vh-summary-strip" aria-label="Settings summary">
    <article class="vh-summary-item"><small>Environment</small><strong>{{ environment_label }}</strong><span>{{ database_engine }} database</span></article>
    <article class="vh-summary-item"><small>Governed identity</small><strong>{{ identity.status }}</strong><span>{{ identity.display_name }}</span></article>
    <article class="vh-summary-item"><small>Capabilities healthy</small><strong>{{ healthy_count }}/{{ capability_rows|length }}</strong><span>Backend-validated state</span></article>
    <article class="vh-summary-item"><small>Activations ready</small><strong>{{ enabled_count }}/{{ activation_rows|length }}</strong><span>Explicit configuration only</span></article>
  </section>

  <div class="vh-settings-layout">
    <section class="vh-surface vh-settings-identity">
      <header class="vh-surface-header"><div><h2>Operator identity</h2><p>The authenticated account and governed authority used for every protected request.</p></div><span class="vh-status-chip {% if identity.status == 'active' %}vh-status-safe{% else %}vh-status-warning{% endif %}">{{ identity.status }}</span></header>
      <div class="vh-settings-profile"><div class="vh-settings-avatar" aria-hidden="true">{{ request.user.username|slice:':1'|upper }}</div><div><span>Signed in as</span><strong>{{ request.user.username }}</strong><small>{{ identity.display_name }}</small></div></div>
      <dl class="vh-settings-definition">
        <div><dt>Governance identity</dt><dd><code>{{ identity.reviewer_id }}</code></dd></div>
        <div><dt>Identity roles</dt><dd>{{ identity.roles|join:", " }}</dd></div>
        <div class="vh-settings-definition-wide"><dt>Product permissions</dt><dd><div class="vh-settings-chip-row">{% for role in product_roles %}<span>{{ role }}</span>{% endfor %}</div></dd></div>
      </dl>
      <div class="vh-settings-note"><strong>Authority remains server-side</strong><p>No browser control, query parameter or visual state can grant a role or override the governed identity mapping.</p></div>
    </section>

    <section class="vh-surface vh-settings-activation">
      <header class="vh-surface-header"><div><h2>Activation gates</h2><p>Capabilities become active only after their required policy and local dependencies are present.</p></div><span class="vh-panel-count">{{ activation_rows|length }}</span></header>
      <div class="vh-activation-list">{% for item in activation_rows %}<article class="vh-activation-row {% if item.enabled %}is-enabled{% else %}is-gated{% endif %}"><span class="vh-activation-indicator" aria-hidden="true"></span><div><strong>{{ item.name }}</strong><p>{{ item.detail }}</p></div><div class="vh-activation-action"><span class="vh-status-chip {% if item.enabled %}vh-status-safe{% else %}vh-status-warning{% endif %}">{% if item.enabled %}configured{% else %}gated{% endif %}</span><a href="{% url item.link %}">Inspect →</a></div></article>{% endfor %}</div>
    </section>

    <section class="vh-surface vh-settings-capabilities">
      <header class="vh-surface-header"><div><h2>Core capability health</h2><p>Read directly from local stores, configuration and integrity checks.</p></div></header>
      <div class="vh-capability-grid">{% for item in capability_rows %}<article class="vh-capability-card"><div><span class="vh-capability-dot is-{{ item.state }}" aria-hidden="true"></span><strong>{{ item.name }}</strong></div><span class="vh-status-chip {% if item.state == 'available' or item.state == 'empty' %}vh-status-safe{% elif item.state == 'invalid' %}vh-status-danger{% else %}vh-status-warning{% endif %}">{{ item.state }}</span><p>{{ item.detail }}</p></article>{% endfor %}</div>
    </section>

    <section class="vh-surface vh-settings-security">
      <header class="vh-surface-header"><div><h2>Browser security posture</h2><p>Effective Django and response-layer controls for this deployment.</p></div></header>
      <ul class="vh-security-posture">{% for item in security_rows %}<li><span class="vh-security-check {% if item.safe %}is-safe{% else %}is-local{% endif %}" aria-hidden="true">{% if item.safe %}✓{% else %}!{% endif %}</span><div><strong>{{ item.name }}</strong><small>{{ item.value }}</small></div></li>{% endfor %}</ul>
      <div class="vh-settings-note"><strong>Local-only is not production-ready</strong><p>When HTTPS enforcement or debug hardening is not active, keep the web process bound to loopback and use the documented deployment-readiness gates before exposure.</p></div>
    </section>

    <section class="vh-surface vh-settings-providers">
      <header class="vh-surface-header"><div><h2>Intelligence components</h2><p>Health and authority state only. Opening this page never starts inference or graph generation.</p></div><span class="vh-panel-count">{{ intelligence_status|length }}</span></header>
      {% if intelligence_status %}<ul class="vh-provider-list">{% for item in intelligence_status %}<li><div><strong>{{ item.name }}</strong><p>{{ item.detail }}</p></div><span class="vh-status-chip {% if 'READY' in item.state %}vh-status-safe{% else %}vh-status-warning{% endif %}">{{ item.state }}</span></li>{% endfor %}</ul>{% else %}<div class="vh-empty-panel"><svg aria-hidden="true"><use href="#vh-i-settings"></use></svg><h3>No provider state</h3><p>No advisory component status is available.</p></div>{% endif %}
    </section>

    <section class="vh-surface vh-settings-links">
      <header class="vh-surface-header"><div><h2>Configuration workspaces</h2><p>Open the authoritative read-only or governed control surface.</p></div></header>
      <nav class="vh-settings-link-grid" aria-label="Configuration workspaces"><a href="{% url 'web-authorization-list' %}"><svg aria-hidden="true"><use href="#vh-i-authorization"></use></svg><span><strong>Authorizations</strong><small>Scope, owner and expiry records</small></span></a><a href="{% url 'web-advanced-profiles' %}"><svg aria-hidden="true"><use href="#vh-i-radar"></use></svg><span><strong>Assessment profiles</strong><small>Limits and approval gates</small></span></a><a href="{% url 'web-role-list' %}"><svg aria-hidden="true"><use href="#vh-i-team"></use></svg><span><strong>Role registry</strong><small>Allowed and denied authority</small></span></a><a href="{% url 'web-audit-overview' %}"><svg aria-hidden="true"><use href="#vh-i-audit"></use></svg><span><strong>Audit evidence</strong><small>Integrity and governance events</small></span></a></nav>
    </section>
  </div>
</section>
{% endblock %}
''',
)

write(
    "vulnhunter/web/static/web/settings.css",
    '''.vh-settings-page { display: grid; gap: 20px; }
.vh-settings-hero { align-items: flex-start; }
.vh-settings-hero > div:first-child { max-width: 820px; }
.vh-settings-layout { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 16px; align-items: start; }
.vh-settings-identity { grid-column: span 5; }
.vh-settings-activation { grid-column: span 7; }
.vh-settings-capabilities { grid-column: 1 / -1; }
.vh-settings-security { grid-column: span 5; }
.vh-settings-providers { grid-column: span 7; }
.vh-settings-links { grid-column: 1 / -1; }
.vh-settings-profile { display: flex; align-items: center; gap: 14px; padding: 20px 18px 14px; }
.vh-settings-avatar { display: grid; width: 52px; height: 52px; flex: 0 0 auto; place-items: center; border: 1px solid rgba(79, 140, 255, .34); border-radius: 14px; background: rgba(79, 140, 255, .12); color: var(--vh-accent-hover); font-size: 1.25rem; font-weight: 850; }
.vh-settings-profile span, .vh-settings-profile strong, .vh-settings-profile small { display: block; }
.vh-settings-profile span { color: var(--vh-muted); font-size: .72rem; font-weight: 800; letter-spacing: .055em; text-transform: uppercase; }
.vh-settings-profile strong { margin-top: 3px; font-size: 1.06rem; }
.vh-settings-profile small { margin-top: 2px; color: var(--vh-muted); }
.vh-settings-definition { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1px; margin: 0; padding: 0 18px 18px; }
.vh-settings-definition > div { min-width: 0; padding: 13px; border: 1px solid var(--vh-border); background: var(--vh-panel-2); }
.vh-settings-definition > div:first-child { border-radius: var(--vh-radius-sm) 0 0 0; }
.vh-settings-definition > div:nth-child(2) { border-radius: 0 var(--vh-radius-sm) 0 0; }
.vh-settings-definition > .vh-settings-definition-wide { grid-column: 1 / -1; border-radius: 0 0 var(--vh-radius-sm) var(--vh-radius-sm); }
.vh-settings-definition dt { color: var(--vh-muted); font-size: .68rem; font-weight: 800; letter-spacing: .055em; text-transform: uppercase; }
.vh-settings-definition dd { margin: 6px 0 0; overflow-wrap: anywhere; }
.vh-settings-chip-row { display: flex; flex-wrap: wrap; gap: 6px; }
.vh-settings-chip-row span { padding: 4px 8px; border: 1px solid var(--vh-border-strong); border-radius: 999px; background: var(--vh-bg-soft); color: #dbe7ff; font-size: .72rem; }
.vh-settings-note { margin: 0 18px 18px; padding: 13px 14px; border: 1px solid rgba(79, 140, 255, .24); border-radius: var(--vh-radius-sm); background: rgba(79, 140, 255, .07); }
.vh-settings-note strong { display: block; }
.vh-settings-note p { margin: 5px 0 0; color: var(--vh-muted); }
.vh-activation-list { display: grid; }
.vh-activation-row { display: grid; grid-template-columns: 12px minmax(0, 1fr) auto; gap: 12px; align-items: center; padding: 15px 18px; border-top: 1px solid var(--vh-border); }
.vh-activation-row:first-child { border-top: 0; }
.vh-activation-row:hover { background: var(--vh-panel-2); }
.vh-activation-indicator { width: 8px; height: 8px; border-radius: 50%; background: var(--vh-warning); box-shadow: 0 0 0 4px rgba(245, 158, 11, .1); }
.vh-activation-row.is-enabled .vh-activation-indicator { background: var(--vh-success); box-shadow: 0 0 0 4px rgba(34, 197, 94, .1); }
.vh-activation-row strong { display: block; }
.vh-activation-row p { margin: 4px 0 0; color: var(--vh-muted); }
.vh-activation-action { display: grid; justify-items: end; gap: 7px; min-width: 112px; }
.vh-activation-action a { color: var(--vh-accent-hover); font-size: .76rem; font-weight: 750; }
.vh-capability-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; padding: 16px; }
.vh-capability-card { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 11px; padding: 15px; border: 1px solid var(--vh-border); border-radius: var(--vh-radius-sm); background: var(--vh-panel-2); }
.vh-capability-card > div { display: flex; min-width: 0; align-items: center; gap: 9px; }
.vh-capability-card > div strong { overflow-wrap: anywhere; }
.vh-capability-card > p { grid-column: 1 / -1; margin: 0; color: var(--vh-muted); }
.vh-capability-dot { width: 9px; height: 9px; flex: 0 0 auto; border-radius: 50%; background: var(--vh-warning); }
.vh-capability-dot.is-available, .vh-capability-dot.is-empty { background: var(--vh-success); }
.vh-capability-dot.is-invalid { background: var(--vh-danger); }
.vh-security-posture { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1px; margin: 0; padding: 16px 18px; list-style: none; }
.vh-security-posture li { display: flex; align-items: center; gap: 10px; min-width: 0; padding: 12px; border: 1px solid var(--vh-border); background: var(--vh-panel-2); }
.vh-security-check { display: grid; width: 26px; height: 26px; flex: 0 0 auto; place-items: center; border-radius: 50%; background: rgba(245, 158, 11, .12); color: var(--vh-warning); font-weight: 850; }
.vh-security-check.is-safe { background: rgba(34, 197, 94, .12); color: var(--vh-success); }
.vh-security-posture strong, .vh-security-posture small { display: block; }
.vh-security-posture small { margin-top: 2px; color: var(--vh-muted); }
.vh-provider-list { display: grid; margin: 0; padding: 0; list-style: none; }
.vh-provider-list li { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 14px; align-items: start; padding: 15px 18px; border-top: 1px solid var(--vh-border); }
.vh-provider-list li:first-child { border-top: 0; }
.vh-provider-list p { margin: 5px 0 0; color: var(--vh-muted); }
.vh-settings-link-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; padding: 16px; }
.vh-settings-link-grid a { display: flex; min-width: 0; align-items: center; gap: 11px; padding: 15px; border: 1px solid var(--vh-border); border-radius: var(--vh-radius-sm); background: var(--vh-panel-2); }
.vh-settings-link-grid a:hover { border-color: var(--vh-accent); background: rgba(79, 140, 255, .08); }
.vh-settings-link-grid svg { width: 22px; height: 22px; flex: 0 0 auto; color: var(--vh-accent-hover); }
.vh-settings-link-grid strong, .vh-settings-link-grid small { display: block; }
.vh-settings-link-grid small { margin-top: 3px; color: var(--vh-muted); }
@media (max-width: 1100px) {
  .vh-settings-identity, .vh-settings-activation, .vh-settings-security, .vh-settings-providers { grid-column: 1 / -1; }
  .vh-capability-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .vh-settings-link-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 639px) {
  .vh-settings-hero { display: grid; }
  .vh-settings-hero .vh-page-actions { width: 100%; }
  .vh-settings-hero .vh-page-actions a { flex: 1; }
  .vh-settings-definition, .vh-capability-grid, .vh-security-posture, .vh-settings-link-grid { grid-template-columns: 1fr; }
  .vh-settings-definition > div, .vh-settings-definition > div:first-child, .vh-settings-definition > div:nth-child(2), .vh-settings-definition > .vh-settings-definition-wide { grid-column: 1; border-radius: var(--vh-radius-sm); }
  .vh-activation-row { grid-template-columns: 12px minmax(0, 1fr); }
  .vh-activation-action { grid-column: 2; grid-auto-flow: column; align-items: center; justify-content: space-between; justify-items: start; min-width: 0; width: 100%; }
  .vh-provider-list li { grid-template-columns: 1fr; }
}
''',
)

# Safe pilot-plan report downloads backed by ReportExporter.
write(
    "vulnhunter/web/report_views.py",
    '''from __future__ import annotations

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
''',
)
replace_once(
    "vulnhunter/web/urls.py",
    '''    path("reports/", report_views.reports_overview_view, name="web-reports-overview"),''',
    '''    path("reports/", report_views.reports_overview_view, name="web-reports-overview"),
    path(
        "reports/plans/<str:plan_id>/download/<slug:export_format>/",
        report_views.pilot_plan_download_view,
        name="web-pilot-plan-download",
    ),''',
)
write(
    "vulnhunter/web/templates/web/reports_overview.html",
    '''{% extends "web/base.html" %}
{% block content %}
<section class="vh-page-shell">
  <header class="vh-page-header"><div><p class="vh-eyebrow">Governance</p><h1>Reports &amp; exports</h1><p>Generate safe, temporary artifacts from validated persisted records. Rendering never publishes a finding or changes governance state.</p></div><div class="vh-page-actions"><a class="vh-button-secondary" href="{% url 'web-findings-overview' %}">Findings</a><a class="vh-button-primary" href="{% url 'web-release-list' %}">Release assessments</a></div></header>
  <section class="vh-summary-strip" aria-label="Report summary"><article class="vh-summary-item"><small>Plan records</small><strong>{{ records|length }}</strong><span>Loaded from the pilot plan store</span></article><article class="vh-summary-item"><small>Direct downloads</small><strong>2</strong><span>HTML and JSON pilot reports</span></article><article class="vh-summary-item"><small>Source rule</small><strong>Persisted data</strong><span>No report is invented by the UI</span></article><article class="vh-summary-item"><small>Release</small><strong>Separate gate</strong><span>Rendering does not publish</span></article></section>
  <div class="vh-surface-grid">
    <section class="vh-surface vh-surface-span-8"><header class="vh-surface-header"><div><h2>Validated report records</h2><p>Inspect a plan or download a deterministic artifact generated from its stored plan and readiness report.</p></div><span class="vh-panel-count">{{ records|length }}</span></header>{% if records %}<div class="vh-table-wrap"><table class="vh-table"><thead><tr><th>Plan</th><th>State</th><th>Applications</th><th>Families</th><th>Plan hash</th><th>Actions</th></tr></thead><tbody>{% for record in records %}<tr><td><strong>{{ record.plan_id }}</strong>{% if record.error %}<small>{{ record.error }}</small>{% endif %}</td><td>{% if record.report %}{% if record.report.valid %}<span class="vh-status-chip vh-status-safe">valid</span>{% else %}<span class="vh-status-chip vh-status-warning">blocked</span>{% endif %}{% else %}<span class="vh-status-chip vh-status-danger">invalid</span>{% endif %}</td><td>{% if record.plan %}{{ record.plan.applications|length }}{% else %}—{% endif %}</td><td>{% if record.report %}{{ record.report.informational_metrics.application_family_count }}{% else %}—{% endif %}</td><td>{% if record.report %}<code>{{ record.report.plan_sha256|slice:":16" }}…</code>{% else %}—{% endif %}</td><td><div class="vh-row-actions"><a href="{% url 'web-pilot-plan-detail' record.plan_id %}">Inspect</a>{% if record.plan and record.report %}<a href="{% url 'web-pilot-plan-download' record.plan_id 'html' %}">HTML</a><a href="{% url 'web-pilot-plan-download' record.plan_id 'json' %}">JSON</a>{% endif %}</div></td></tr>{% endfor %}</tbody></table></div>{% else %}<div class="vh-empty-panel"><svg aria-hidden="true"><use href="#vh-i-report"></use></svg><h3>No report records</h3><p>No pilot plan records are available. Add a validated local plan before generating an export.</p></div>{% endif %}</section>
    <aside class="vh-surface vh-surface-span-4"><header class="vh-surface-header"><div><h2>Output contracts</h2><p>Each format is enabled only when its required data context exists.</p></div></header><ul class="vh-compact-list">{% for format in report_formats %}<li><span>{{ format.name }}<small>{% if format.slug %}Generated on demand{% else %}No decorative download control{% endif %}</small></span><strong class="{% if format.slug %}vh-state-safe{% else %}vh-state-warning{% endif %}">{{ format.state }}</strong></li>{% endfor %}</ul><div class="vh-boundary-note"><strong>Fail-closed exports</strong><p>Protected payloads, unsafe filenames, oversized artifacts and evidence outside approved roots are rejected by the existing exporter.</p></div></aside>
  </div>
</section>
{% endblock %}
''',
)

# Deterministic browser audit seed.
write(
    "tests/ui/prepare_visual_audit.py",
    '''#!/usr/bin/env python3
"""Seed a deterministic, local-only UI audit workspace with no external actions."""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests" / "unit"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnhunter.web.settings")

import django

django.setup()

from django.conf import settings
from django.contrib.auth import get_user_model

from governance_test_support import REVIEWER_ONE_SECRET, REVIEWER_TWO_SECRET, make_governance_store
from test_governance_workflow import assign_default, prepare_world
from test_web_app import _controller

from vulnhunter.agent.models import PermissionManifest, ToolRisk
from vulnhunter.approvals import ApprovalRequest, ApprovalStore
from vulnhunter.evidence import EvidenceStore, FindingStatus
from vulnhunter.governance.service import submit_governed_review
from vulnhunter.web.models import WebUserMapping


def mapped_user(username: str, identity: str, roles: list[str], password: str) -> None:
    model = get_user_model()
    user, _ = model.objects.get_or_create(username=username)
    user.set_password(password)
    user.is_active = True
    user.is_staff = True
    user.save()
    WebUserMapping.objects.update_or_create(user=user, defaults={"governance_identity_id": identity, "product_roles": roles})


def main() -> int:
    runtime_root = Path(settings.VULNHUNTER_GOVERNANCE_DATABASE).resolve().parent
    runtime_root.mkdir(parents=True, exist_ok=True)
    store = make_governance_store(runtime_root)
    world = prepare_world(store, runtime_root)
    assignment = assign_default(store, world)
    all_roles = ["system-administrator", "campaign-operator", "campaign-approver", "reviewer", "adjudicator", "security-auditor", "model-analyst"]
    password = "Vh-Visual-Audit-2026!"
    mapped_user("visual-admin", "admin-a", all_roles, password)
    mapped_user("visual-reviewer", "reviewer-a", ["reviewer"], password)
    mapped_user("visual-adjudicator", "lead-c", ["adjudicator"], password)

    controller = _controller(runtime_root)
    task = controller.create_task(
        task_id="ui-reference-run",
        objective="Inspect a bounded local application and preserve evidence for human review.",
        permission_manifest=PermissionManifest(
            manifest_id="ui-reference-manifest",
            role_id="orchestrator",
            skill_id="bounded-task-routing",
            allowed_actions=("evidence.inspect",),
            allowed_tools=("agent.echo",),
            allowed_risks=(ToolRisk.READ_ONLY,),
        ),
    )
    controller.run(task.task_id)

    evidence_root = Path(settings.VULNHUNTER_SECURITY_EVIDENCE_ROOT)
    evidence_root.mkdir(parents=True, exist_ok=True)
    artifact = evidence_root / "ui-reference-proof.txt"
    artifact.write_text("Sanitized deterministic proof for local visual validation.\n", encoding="utf-8")
    finding = EvidenceStore(evidence_root).append(
        evidence_id="ui-critical-finding",
        campaign_id=world["campaign"].campaign_id,
        run_id=task.task_id,
        action_manifest_sha256="a" * 64,
        tool_id="nuclei",
        target_reference="http://127.0.0.1:8000/app/",
        finding_status=FindingStatus.VALIDATED,
        title="Critical authorization boundary regression",
        severity="critical",
        confidence="high",
        recorded_by="admin-a",
        artifact_path=artifact,
        metadata={"attack_path": [{"label": "Authorized target", "state": "observed"}, {"label": "Candidate evidence", "state": "validated"}, {"label": "Human review", "state": "required"}]},
    )

    submit_governed_review(store, world["repository"], actor_id="reviewer-a", actor_secret=REVIEWER_ONE_SECRET, campaign_id=world["campaign"].campaign_id, scan_database=world["scan_database"], observation_id=world["observation_id"], outcome="confirmed", note="The persisted local evidence supports confirmation.")
    submit_governed_review(store, world["repository"], actor_id="reviewer-b", actor_secret=REVIEWER_TWO_SECRET, campaign_id=world["campaign"].campaign_id, scan_database=world["scan_database"], observation_id=world["observation_id"], outcome="false_positive", note="The second reviewer found the candidate inconclusive.")

    now = datetime.now(UTC)
    ApprovalStore(Path(settings.VULNHUNTER_APPROVAL_DATABASE)).create(
        ApprovalRequest(request_id="ui-approval-request", campaign_id=world["campaign"].campaign_id, run_id=task.task_id, action_manifest_sha256="b" * 64, requested_by="reviewer-a", summary="Approve one bounded local validation action.", risk_summary="The action is restricted to synthetic local evidence.", requested_at=now, expires_at=now + timedelta(hours=2))
    )

    manifest = {
        "simulation_only": True,
        "external_actions_performed": False,
        "personas": {
            "admin": {"username": "visual-admin", "password": password},
            "reviewer": {"username": "visual-reviewer", "password": password},
            "adjudicator": {"username": "visual-adjudicator", "password": password},
        },
        "pages": [
            {"name": "dashboard", "path": "/", "persona": "admin", "responsive": True},
            {"name": "new-scan", "path": "/scans/new/", "persona": "admin"},
            {"name": "scan-runs", "path": "/scans/", "persona": "admin"},
            {"name": "run-detail", "path": f"/scans/{task.task_id}/", "persona": "admin", "responsive": True},
            {"name": "findings", "path": "/findings/", "persona": "admin"},
            {"name": "finding-detail", "path": f"/findings/{finding.evidence_id}/", "persona": "admin", "responsive": True},
            {"name": "approvals", "path": "/approvals/", "persona": "admin"},
            {"name": "approval-detail", "path": "/approvals/ui-approval-request/", "persona": "admin"},
            {"name": "review", "path": f"/reviews/{assignment.record_sha256[:24]}/", "persona": "reviewer"},
            {"name": "adjudication", "path": f"/adjudications/{assignment.record_sha256[:24]}/", "persona": "adjudicator"},
            {"name": "campaigns", "path": "/campaigns/", "persona": "admin"},
            {"name": "campaign-detail", "path": f"/campaigns/{world['campaign'].campaign_id}/", "persona": "admin"},
            {"name": "releases", "path": "/releases/", "persona": "admin"},
            {"name": "datasets", "path": "/datasets/", "persona": "admin"},
            {"name": "models", "path": "/models/", "persona": "admin"},
            {"name": "reports", "path": "/reports/", "persona": "admin"},
            {"name": "mobile", "path": "/mobile-analysis/", "persona": "admin"},
            {"name": "audit", "path": "/audit/", "persona": "admin"},
            {"name": "settings", "path": "/settings/", "persona": "admin", "responsive": True},
        ],
    }
    output = Path(os.environ.get("VULNHUNTER_UI_MANIFEST", runtime_root / "ui-manifest.json"))
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''',
)

write(
    ".playwright-validate.cjs",
    '''const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const baseUrl = process.env.VULNHUNTER_UI_BASE_URL || "http://127.0.0.1:8767";
const manifestPath = process.env.VULNHUNTER_UI_MANIFEST;
const outputRoot = process.env.VULNHUNTER_UI_OUTPUT || "/tmp/vulnhunter-ui-audit";
if (!manifestPath) throw new Error("VULNHUNTER_UI_MANIFEST is required");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const viewports = [
  { name: "reference-1672", width: 1672, height: 941 },
  { name: "desktop-1440", width: 1440, height: 900 },
  { name: "tablet-1024", width: 1024, height: 768 },
  { name: "tablet-768", width: 768, height: 1024 },
  { name: "mobile-390", width: 390, height: 844 },
  { name: "mobile-360", width: 360, height: 800 },
];
function safeName(value) { return value.replace(/[^a-zA-Z0-9._-]+/g, "-"); }

(async () => {
  fs.mkdirSync(outputRoot, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const report = { pages: [], consoleErrors: [], pageErrors: [], assetFailures: [], failures: [] };
  const contextCache = new Map();
  async function contextFor(viewport, personaName) {
    const key = `${viewport.name}:${personaName}`;
    if (contextCache.has(key)) return contextCache.get(key);
    const context = await browser.newContext({ viewport, colorScheme: "dark", reducedMotion: "reduce" });
    const page = await context.newPage();
    const persona = manifest.personas[personaName];
    const login = await page.goto(`${baseUrl}/login/`, { waitUntil: "networkidle" });
    if (!login || login.status() >= 400) throw new Error(`Login page failed for ${personaName}`);
    await page.getByLabel("Username").fill(persona.username);
    await page.getByLabel("Password").fill(persona.password);
    await Promise.all([page.waitForURL(`${baseUrl}/`), page.getByRole("button", { name: /sign in securely/i }).click()]);
    await page.close();
    contextCache.set(key, context);
    return context;
  }
  for (const pageDefinition of manifest.pages) {
    const targets = pageDefinition.responsive ? viewports : [viewports[1]];
    for (const viewport of targets) {
      const context = await contextFor(viewport, pageDefinition.persona);
      const page = await context.newPage();
      const routeKey = `${pageDefinition.name}:${viewport.name}`;
      page.on("console", (message) => { if (message.type() === "error") report.consoleErrors.push({ routeKey, text: message.text() }); });
      page.on("pageerror", (error) => report.pageErrors.push({ routeKey, text: error.message }));
      page.on("response", (response) => { if (response.url().includes("/static/") && response.status() >= 400) report.assetFailures.push({ routeKey, url: response.url(), status: response.status() }); });
      const response = await page.goto(`${baseUrl}${pageDefinition.path}`, { waitUntil: "networkidle" });
      await page.waitForTimeout(150);
      const audit = await page.evaluate(() => {
        const visible = (element) => { const style = getComputedStyle(element); const rect = element.getBoundingClientRect(); return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0; };
        const controls = [...document.querySelectorAll("button, a, input, select, textarea, summary")].filter(visible);
        const unnamedControls = controls.filter((element) => { const id = element.getAttribute("id"); const label = id ? document.querySelector(`label[for="${CSS.escape(id)}"]`) : null; return !(element.getAttribute("aria-label") || element.getAttribute("aria-labelledby") || element.textContent.trim() || element.getAttribute("title") || element.getAttribute("placeholder") || label?.textContent.trim()); }).map((element) => element.outerHTML.slice(0, 220));
        const ids = [...document.querySelectorAll("[id]")].map((element) => element.id);
        const duplicateIds = ids.filter((id, index) => ids.indexOf(id) !== index);
        const sidebar = document.querySelector(".vh-sidebar");
        const navToggle = document.querySelector("[data-nav-toggle]");
        const activeNavigation = [...document.querySelectorAll('.vh-nav-list a[aria-current="page"]')].filter(visible);
        const bodyText = document.body.innerText;
        return { title: document.title, h1Count: [...document.querySelectorAll("h1")].filter(visible).length, overflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1, bodyScrollWidth: document.documentElement.scrollWidth, bodyClientWidth: document.documentElement.clientWidth, unnamedControls, duplicateIds: [...new Set(duplicateIds)], activeNavigation: activeNavigation.map((item) => item.textContent.trim()), djangoError: /Traceback|TemplateSyntaxError|Server Error \(500\)/i.test(bodyText), sidebarVisible: sidebar ? visible(sidebar) : false, navToggleVisible: navToggle ? visible(navToggle) : false };
      });
      const status = response ? response.status() : 0;
      report.pages.push({ ...pageDefinition, viewport: viewport.name, status, ...audit });
      if (status >= 400) report.failures.push(`${routeKey} returned ${status}`);
      if (audit.djangoError) report.failures.push(`${routeKey} displayed a Django error`);
      if (audit.overflowX) report.failures.push(`${routeKey} has body-level horizontal overflow`);
      if (audit.unnamedControls.length) report.failures.push(`${routeKey} has unnamed controls`);
      if (audit.duplicateIds.length) report.failures.push(`${routeKey} has duplicate ids`);
      if (audit.h1Count !== 1) report.failures.push(`${routeKey} has ${audit.h1Count} visible h1 elements`);
      if (audit.activeNavigation.length !== 1) report.failures.push(`${routeKey} has ${audit.activeNavigation.length} active navigation items`);
      if (viewport.width <= 768 && (!audit.navToggleVisible || audit.sidebarVisible)) report.failures.push(`${routeKey} mobile navigation is not closed with a visible toggle`);
      await page.screenshot({ path: path.join(outputRoot, `${safeName(pageDefinition.name)}-${viewport.name}.png`), fullPage: true });
      await page.close();
    }
  }
  for (const context of contextCache.values()) await context.close();
  await browser.close();
  if (report.consoleErrors.length) report.failures.push(`${report.consoleErrors.length} console error(s)`);
  if (report.pageErrors.length) report.failures.push(`${report.pageErrors.length} page error(s)`);
  if (report.assetFailures.length) report.failures.push(`${report.assetFailures.length} failed static asset response(s)`);
  fs.writeFileSync(path.join(outputRoot, "validation-report.json"), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ pages: report.pages.length, failures: report.failures }, null, 2));
  if (report.failures.length) process.exitCode = 1;
})().catch((error) => { console.error(error); process.exitCode = 1; });
''',
)

write(
    ".github/workflows/ui-quality.yml",
    '''name: VulnHunter browser UI quality

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  visual-smoke:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    env:
      VULNHUNTER_WEB_DEBUG: "true"
      VULNHUNTER_WEB_DATABASE: ${{ runner.temp }}/vh-ui/web.sqlite3
      VULNHUNTER_AUTHORIZATION_DATABASE: ${{ runner.temp }}/vh-ui/auth.db
      VULNHUNTER_GOVERNANCE_DATABASE: ${{ runner.temp }}/vh-ui/governance.db
      VULNHUNTER_AGENT_DATABASE: ${{ runner.temp }}/vh-ui/agent.db
      VULNHUNTER_APPROVAL_DATABASE: ${{ runner.temp }}/vh-ui/approvals.sqlite3
      VULNHUNTER_AGENT_ACTIVITY_ROOT: ${{ runner.temp }}/vh-ui/activity
      VULNHUNTER_SECURITY_EVIDENCE_ROOT: ${{ runner.temp }}/vh-ui/evidence
      VULNHUNTER_MOBILE_ARTIFACT_ROOT: ${{ runner.temp }}/vh-ui/mobile
      VULNHUNTER_ADVERSARY_LAB_DATABASE: ${{ runner.temp }}/vh-ui/lab.sqlite3
      VULNHUNTER_UI_MANIFEST: ${{ runner.temp }}/vh-ui/ui-manifest.json
      VULNHUNTER_UI_OUTPUT: ${{ runner.temp }}/vh-ui/screenshots
      VULNHUNTER_UI_BASE_URL: http://127.0.0.1:8767
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
          cache: pip
      - uses: actions/setup-node@v5
        with:
          node-version: "22"
      - name: Install application and audit tools
        run: |
          python -m pip install --upgrade pip
          python -m pip install -e .
          python -m pip install pytest pytest-asyncio pytest-django
          npm install --no-save playwright@1.55.0
          npx playwright install --with-deps chromium
      - name: Prepare deterministic local audit data
        run: |
          mkdir -p "${{ runner.temp }}/vh-ui"
          python manage.py migrate --noinput
          python tests/ui/prepare_visual_audit.py
      - name: Start local web application
        run: |
          python manage.py runserver 127.0.0.1:8767 --noreload > "${{ runner.temp }}/vh-ui/server.log" 2>&1 &
          for attempt in $(seq 1 40); do
            if curl --fail --silent http://127.0.0.1:8767/health/ > /dev/null; then exit 0; fi
            sleep 1
          done
          cat "${{ runner.temp }}/vh-ui/server.log"
          exit 1
      - name: Capture and validate responsive product UI
        run: node .playwright-validate.cjs
      - name: Upload visual audit evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: vulnhunter-ui-audit
          path: |
            ${{ runner.temp }}/vh-ui/screenshots
            ${{ runner.temp }}/vh-ui/server.log
          if-no-files-found: error
          retention-days: 7
''',
)

write(
    "tests/unit/test_ui_audit_repairs.py",
    '''from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model

from test_web_app import _bootstrap_identity, _mapped_user

from vulnhunter.agent.store import AgentStore
from vulnhunter.web.models import WebUserMapping
from vulnhunter.web.services import intelligence_status, navigation_for


@pytest.mark.django_db
def test_navigation_exposes_real_workspaces_and_highlights_every_detail_route(web_paths) -> None:
    user = get_user_model().objects.create_user(username="navigation-audit")
    WebUserMapping.objects.create(user=user, governance_identity_id="admin-a", product_roles=["system-administrator", "campaign-operator", "campaign-approver", "reviewer", "adjudicator", "security-auditor", "model-analyst"])
    entries = {str(item["label"]): item for item in navigation_for(user)}
    assert "Approval Centre" in entries
    assert "Mobile Analysis" in entries
    assert "web-finding-detail" in entries["Findings"]["active_routes"]
    assert "web-review-detail" in entries["Review Queue"]["active_routes"]
    assert "web-adjudication-detail" in entries["Adjudications"]["active_routes"]
    assert "web-release-detail" in entries["Releases"]["active_routes"]
    assert "web-dataset-detail" in entries["Datasets"]["active_routes"]
    assert "web-model-detail" in entries["Models"]["active_routes"]
    assert "web-pilot-plan-download" in entries["Reports"]["active_routes"]
    assert "web-mobile-analysis" not in entries["Settings"]["active_routes"]


@pytest.mark.django_db
def test_settings_page_renders_real_posture_without_exposing_secret_paths(client, web_paths, settings) -> None:
    _bootstrap_identity(web_paths)
    AgentStore.initialize_database(web_paths / "agent.db")
    user = _mapped_user(username="settings-audit", password="password-1234", product_roles=["system-administrator", "security-auditor"], governance_identity="admin-a")
    client.force_login(user)
    response = client.get("/settings/")
    assert response.status_code == 200
    for marker in (b"Settings &amp; readiness", b"Operator identity", b"Activation gates", b"Core capability health", b"Browser security posture", b"Configuration workspaces"):
        assert marker in response.content
    assert str(Path(settings.VULNHUNTER_GROQ_API_KEY_FILE)).encode() not in response.content
    assert b"password-1234" not in response.content
    assert b"Traceback" not in response.content


@pytest.mark.django_db
def test_pilot_report_downloads_use_existing_safe_exporter(client, web_paths) -> None:
    _bootstrap_identity(web_paths)
    user = _mapped_user(username="report-audit", password="password-1234", product_roles=["security-auditor"], governance_identity="admin-a")
    client.force_login(user)
    plan = SimpleNamespace(title="Local pilot", model_dump=lambda mode: {"plan_id": "local-pilot", "title": "Local pilot"})
    report = SimpleNamespace(plan_sha256="a" * 64, report_sha256="b" * 64, model_dump=lambda mode: {"valid": True, "plan_sha256": "a" * 64})
    record = SimpleNamespace(plan_id="local-pilot", plan=plan, report=report)
    with patch("vulnhunter.web.report_views.get_pilot_plan_record", return_value=record):
        json_response = client.get("/reports/plans/local-pilot/download/json/")
        html_response = client.get("/reports/plans/local-pilot/download/html/")
    assert json_response.status_code == 200
    assert json_response["Content-Type"].startswith("application/json")
    assert "attachment" in json_response["Content-Disposition"]
    assert len(json_response["X-VulnHunter-Artifact-SHA256"]) == 64
    assert b'"plan_id": "local-pilot"' in json_response.content
    assert html_response.status_code == 200
    assert html_response["Content-Type"].startswith("text/html")
    assert b"VulnHunter pilot plan" in html_response.content
    assert client.get("/reports/plans/local-pilot/download/pdf/").status_code == 404


def test_graphify_status_honours_explicit_execution_flag(settings) -> None:
    settings.VULNHUNTER_GRAPHIFY_EXECUTION_ENABLED = True
    settings.VULNHUNTER_GROQ_ENABLED = False
    observed: dict[str, object] = {}
    class FakeGraphify:
        def __init__(self, **kwargs): observed.update(kwargs)
        def load_artifact(self, path, *, repository_root): return SimpleNamespace(graph_sha256="c" * 64, nodes=())
    with patch("vulnhunter.web.services.GraphifyAdapter", FakeGraphify):
        rows = intelligence_status()
    assert observed["execution_enabled"] is True
    assert rows[0]["state"] == "READY_ENABLED"


def test_browser_audit_configuration_has_no_stale_routes() -> None:
    script = Path(".playwright-validate.cjs").read_text(encoding="utf-8")
    workflow = Path(".github/workflows/ui-quality.yml").read_text(encoding="utf-8")
    assert "/oracle/" not in script
    assert "ui-reference-run" not in script
    assert "VULNHUNTER_UI_MANIFEST" in script
    assert "overflowX" in script
    assert "unnamedControls" in script
    assert "playwright@1.55.0" in workflow
''',
)

print("UI audit repairs applied")
