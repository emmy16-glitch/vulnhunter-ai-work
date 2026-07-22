# VulnHunter Web Application

## Purpose

The VulnHunter web application is a local, authenticated, server-rendered
security-operations console for authorized private-laboratory work. It exposes
real repository-backed authorization, assessment, approval, evidence,
verification, independent review, adjudication, campaign, release, dataset,
reporting, role, skill, mobile-analysis, and audit state.

The browser is a governed control surface, not a second security control plane.
Backend authorization, policy, digest binding, evidence integrity, deterministic
verification, reviewer independence, and release gates remain authoritative.

The application is not a public scanning service, an unrestricted exploitation
console, or an autonomous publication system.

## UI implementation

The current console uses the approved VulnHunter dark operational design:

- `264px` desktop sidebar and `64px` top bar;
- maximum content width of `1600px`;
- reusable metric cards, status badges, tables, evidence panels, timelines,
  forms, empty states, and responsive workspaces;
- a private-lab environment marker;
- stage-based status rather than invented progress percentages;
- backend-derived counts and states rather than demonstration records;
- accessible focus indicators and reduced-motion support.

The standalone frontend prototype was used only as a visual reference. The
following prototype behaviours were intentionally not carried into production:

- JavaScript-only authentication;
- prefilled demonstration credentials;
- browser-controlled role switching;
- hard-coded findings, approvals, scans, or activity;
- inline event handlers;
- simulated execution or publication controls.

All state-changing forms are Django POST requests with CSRF protection and
server-side permission enforcement.

## Current product boundary

Implemented browser surfaces include:

- authenticated dashboard and system readiness;
- authorization inspection;
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
- audit, role, skill, tool, settings, and mobile static-analysis surfaces;
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
- secure cookies when HTTPS mode is enabled;
- CSRF middleware for state-changing requests;
- `X-Frame-Options: DENY`;
- `X-Content-Type-Options: nosniff`;
- strict same-origin Content Security Policy;
- template auto-escaping;
- no inline JavaScript requirement;
- private, no-store caching on sensitive workspaces;
- backend redaction before persistence and presentation;
- only health, readiness, and login endpoints are unauthenticated as configured.

## Canonical routes

### Overview and collection

- `/`
- `/status/`
- `/audit/`
- `/authorizations/`
- `/scans/new/`
- `/scans/`
- `/scans/<run_id>/`
- `/agent/runs/<run_id>/activity/`
- `/agent/runs/<run_id>/activity/stream/`
- `/agent/runs/<run_id>/stop/`

### Findings and independent review

- `/findings/`
- `/findings/<finding_id>/`
- `/reviews/`
- `/reviews/<assignment_reference>/`
- `/adjudications/`
- `/adjudications/<assignment_reference>/`

Finding identifiers are resolved against findings visible to the current actor.
Review and adjudication references are bounded prefixes of integrity-checked
assignment hashes and must resolve to exactly one stored assignment.

### Governance and intelligence

- `/campaigns/`
- `/campaigns/<campaign_id>/`
- `/readiness/<campaign_id>/`
- `/releases/`
- `/releases/<campaign_id>/`
- `/datasets/`
- `/datasets/<campaign_id>/`
- `/models/`
- `/models/<component_id>/`

The release and dataset detail pages are currently read-only assessments. They
do not expose decorative publication, export, training, or promotion actions
without a safe backend contract.

### Operations and assurance

- `/approvals/`
- `/approvals/<request_id>/`
- `/approvals/<request_id>/decision/`
- `/reports/`
- `/security-tools/`
- `/advanced-assessment/`
- `/mobile-analysis/`
- `/active-validation/<lab_id>/`
- `/roles/`
- `/skills/`
- `/settings/`

## Approval and cancellation boundaries

Supported now:

- exact plan-digest approval decisions from the browser;
- rejection, information-required, and conditional decision states supported by
  the approval ledger;
- CSRF-protected decision submission;
- bounded run cancellation;
- signed worker-spool cancellation requests;
- append-only activity and approval audit events.

Not provided as general browser controls:

- arbitrary reconstruction and resume of any persisted runtime task;
- manual operator pause without a backend transition contract;
- alteration of an already recorded immutable review or adjudication;
- release publication without a dedicated authorized service contract.

Approval of a plan does not itself execute a scanner. Execution still requires
worker readiness, explicit activation, and the isolated worker boundary.

## Findings, review, and adjudication

The finding workspace displays only data exposed by the authenticated product
read model. Scanner output remains candidate evidence.

The review workspace:

- verifies that the signed-in governed identity is one of the assigned primary
  reviewers;
- opens only the integrity-bound scan repository referenced by the assignment;
- rejects a symbolic-link database target;
- hides other reviewers' decisions until the current reviewer submits;
- requires the governance credential;
- records one immutable decision and attestation.

The adjudication workspace:

- verifies the assigned adjudicator identity;
- requires exactly two conflicting primary decisions;
- requires the adjudicator to remain distinct from both primary reviewers;
- records an immutable final outcome, rationale, and attestation.

## Intelligence boundary

The interface is model-neutral. Intelligence components may provide bounded
context, sanitized advisory proposals, or deterministic verification status.
They cannot:

- authorize targets;
- expand scope;
- approve plans;
- execute scanners, shells, browsers, or connectors;
- declare a candidate finding final by themselves;
- adjudicate human disagreement;
- publish findings or datasets;
- modify policy.

Private source code, credentials, tokens, customer data, private targets,
authorization records, unpublished findings, and raw evidence remain denied
from remote advisory routing. Deterministic workflows continue when optional
advisory analysis is disabled or unavailable.

## Static assets

Primary style and interaction files include:

```text
web/app.css
web/activity.css
web/product.css
web/operational.css
web/workspaces.css
web/console.css
web/intelligence.css
web/app.js
web/activity.js
web/assessment-modal.js
```

The Content Security Policy requires scripts and styles to be served from the
application origin. New UI behaviour should use these static files instead of
inline handlers.

## Verification commands

Focused checks:

```bash
python -m ruff check vulnhunter/web tests/unit/test_web_app.py
python -m ruff format --check vulnhunter/web tests/unit/test_web_app.py
python -m compileall -q vulnhunter/web
VULNHUNTER_WEB_SECRET_KEY=local-check-secret python manage.py check
VULNHUNTER_WEB_SECRET_KEY=local-check-secret python manage.py findstatic \
  web/app.css web/console.css web/workspaces.css web/intelligence.css
python -m pytest -q tests/unit/test_web_app.py
```

Repository verification remains the final gate:

```bash
python -m ruff check .
python -m ruff format --check .
python -m compileall -q vulnhunter scripts
python scripts/validate_scanner_compatibility.py
python scripts/project_audit.py --strict
python -m pytest -q
```

## Known limitations

- The web product is local/private-lab oriented and is not yet approved for
  public Internet exposure.
- Real scanner, advisory-provider, PDF-renderer, graph-refresh, and dynamic
  Android acceptance depend on the operator environment.
- Finding evidence detail is limited to fields and artifacts exposed by the
  current product read model.
- Release and dataset workspaces are read-only until dedicated authorized write
  contracts are implemented.
- Formal backup, external signing, retention, migration, and disaster recovery
  remain operational work.
- Production SSO, MFA, hardware-backed identity, and independently protected
  signing keys are not yet implemented.
