# VulnHunter Web Application

## Purpose

The VulnHunter web application is a local, authenticated, server-rendered
security-operations workspace for authorized private-laboratory work. It exposes
real repository-backed authorization, assessment, approval, evidence,
verification, independent review, adjudication, campaign, release, dataset,
reporting, role, skill, mobile-analysis, and audit state.

The browser is a governed control surface, not a second security control plane.
Backend authorization, policy, digest binding, evidence integrity, deterministic
verification, reviewer independence, and release gates remain authoritative.

The application is not a public scanning service, an unrestricted exploitation
console, or an autonomous publication system.

## UI implementation

The current product follows the locked `docs/design/VULNHUNTER_UI_CONTRACT.md`
and is conversation/task-first rather than dashboard-first:

- `280px` desktop task/sidebar shell and `60px` top bar;
- warm cream dotted working canvas, near-black text/borders, dusty-pink accent,
  and compact dark task-focused sidebar;
- square or nearly-square controls with hard zero-blur offset shadows;
- conversation as the primary operating surface, with task stages, tool receipts,
  approvals, findings, evidence and recovery shown contextually when practical;
- dedicated pages as deep views of the same persisted state rather than competing
  workflows;
- maximum content width of `1600px` on specialist pages while the conversation
  workspace may use the full governed application frame;
- stage-based status rather than invented progress percentages;
- backend-derived counts and states rather than demonstration records;
- accessible focus indicators, keyboard-operable contextual panels and
  reduced-motion support;
- responsive mobile behavior based on an off-canvas task drawer and one-column
  conversation workspace rather than a compressed desktop dashboard.

The standalone frontend prototype and external references are interaction or
visual references only. The following behaviours are intentionally not carried
into production:

- JavaScript-only authentication;
- prefilled demonstration credentials;
- browser-controlled role switching;
- hard-coded findings, approvals, scans, or activity;
- inline event handlers;
- simulated execution or publication controls;
- hidden chain-of-thought rendering;
- unsupported provider/model/account-tier controls;
- decorative blue glow, glassmorphism or generic rounded SaaS styling.

All state-changing forms are Django POST requests with CSRF protection and
server-side permission enforcement. Website and APK work now begin in the same
assessment workspace. The historical `/scans/new/` and `/mobile-analysis/`
paths remain navigation-compatible aliases only; they do not maintain a second
form, upload surface, or backend workflow.

## Current product boundary

Implemented browser surfaces include:

- authenticated assessment workspace and system readiness;
- authorization registry and detail inspection with confirmed, append-only revocation;
- bounded assessment creation and assessment workspaces;
- exact digest-bound approval decisions;
- signed passive Nuclei worker-pilot visibility and cancellation controls;
- persisted finding lists and evidence detail workspaces;
- identity-scoped independent review queues;
- governed review submission using the separate governance credential;
- identity-scoped adjudication queues and immutable dispute resolution;
- campaign, readiness, release-assessment, and dataset-quality workspaces;
- model-neutral intelligence component status and authority contracts;
- reports and renderer readiness;
- audit, role, skill, tool, settings, and unified mobile static-analysis state;
- controlled synthetic active-validation workspaces.

Activation-gated or environment-dependent capabilities include:

- real Nuclei execution in a separately configured worker boundary;
- optional sanitized advisory analysis;
- repository graph generation or refresh;
- PDF rendering;
- production deployment acceptance;
- dynamic Android laboratory execution.

The interface must show an honest unavailable, disabled, empty, or blocked
state when one of these capabilities is not activated.

## Exact local preview command

First generate a local-only secret in your shell session or private environment
file. Do not commit it:

```bash
export VULNHUNTER_WEB_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Inspect the default Django user model without printing credentials:

```bash
VULNHUNTER_WEB_DEBUG=true python manage.py shell -c \
  'from django.contrib.auth import get_user_model; U=get_user_model(); print(U.USERNAME_FIELD, U.objects.count())'
```

Bootstrap a governance administrator through the hidden-prompt governance CLI
when the registry is empty, then run first-time setup in order:

```bash
python -m vulnhunter.governance identity bootstrap \
  --reviewer <reviewer-id> --display-name "<display-name>" \
  --governance-database governance.db
python manage.py migrate
VULNHUNTER_WEB_DEBUG=true python manage.py vh_init_agent_store
python manage.py vh_create_web_user \
  --username <local-user> \
  --governance-identity <reviewer-id> \
  --product-role security-auditor
python scripts/run_local_preview.py
```

Repeat startup in a fresh shell using the same private secret:

```bash
python manage.py migrate
python scripts/run_local_preview.py
```

The preview command is for local development only. It does not make the
application safe for public exposure.

## Identity and authority

Each Django account maps to:

- one active governed identity from the governance store;
- one or more product-surface roles from the product-interface registry;
- optional specialist registry role or skill references.

The web layer verifies the mapping, product action, governed identity, and
identity status on every protected surface. A browser dropdown or request
parameter cannot grant a role.

Independent review and adjudication use an additional governance credential.
The credential is submitted only to authenticate the governed decision and is
not persisted by the web application.

## Secure defaults

- Django authentication and session middleware;
- `HttpOnly` session and CSRF cookies;
- `SameSite=Lax` cookies;
- CSRF tokens on state-changing forms;
- no browser-owned authorization or approval authority;
- private-laboratory targeting rules enforced by backend validators;
- no fake progress, findings, evidence, review or release state;
- no hidden chain-of-thought or private reasoning rendered to the browser;
- CSP and other web hardening remain backend/middleware owned.
