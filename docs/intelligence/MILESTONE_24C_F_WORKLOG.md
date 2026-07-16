# Combined Milestone 24C-24F Worklog

## Verified baseline

- Inspection date: 2026-07-10 UTC
- Repository root: `/home/okunlola_labs/Projects/vulnhunter-ai`
- Required branch: `milestone-24c-f-secure-operational-web`
- Active branch at inspection: `milestone-24c-f-secure-operational-web`
- Baseline HEAD at inspection: `942b1c0 Add bounded agent activity timeline foundation`
- Working tree before edits: clean
- Verified milestone lineage present in current history:
  - `234219f Add operational product application layer`
  - `5ec820c Add controlled pilot preparation and validation`
  - `942b1c0 Add bounded agent activity timeline foundation`
- Verified required foundations present:
  - `vulnhunter/product/`
  - `vulnhunter/pilot/`
  - `vulnhunter/agent_activity/`
  - `vulnhunter/agent/`
  - `vulnhunter/governance/`
  - `vulnhunter/authorization/`
  - `vulnhunter/roles/`
  - `config/product_interface/`
  - `docs/product/`

## Read-only inspection summary

- `pyproject.toml` currently defines a Python 3.11+ setuptools project with no
  web framework installed.
- `vulnhunter.product.ProductApplicationService` already exposes real read-only
  summaries for system status, dashboard data, campaigns, readiness, roles,
  skills, and bounded agent runs.
- `vulnhunter.agent_activity` already provides:
  - immutable event models;
  - append-only per-run JSONL persistence;
  - redaction and hidden-reasoning suppression;
  - safe HTML and JSON read models;
  - same-origin polling JavaScript.
- `vulnhunter.agent.controller.AgentController` already supports real
  approval-resume and cancel transitions in the runtime store.
- `vulnhunter.pilot` already provides read-only pilot-plan loading, validation,
  canonical hashes, and a synthetic example plan.
- `vulnhunter.governance` already provides authenticated local identities,
  campaigns, assignments, attestations, releases, and immutable audit events.
- `config/product_interface/` and `docs/product/` are the authoritative browser
  product blueprint and design/token inputs.
- `docs/adr/0017-product-application-layer-before-web-framework.md` records the
  previously accepted blocker that browser work required an approved framework.

## Discovered reusable services

- `ProductApplicationService.load_status()` for store/runtime/spec readiness.
- `ProductApplicationService.load_dashboard()` for real dashboard counts and
  audit summaries.
- `ProductApplicationService.list_campaigns()` and `get_campaign()` for governed
  campaign views.
- `ProductApplicationService.list_roles()`, `get_role()`, `list_skills()`, and
- `get_skill()` for Role and Skill Registry views.
- `ProductApplicationService.list_agent_runs()` and `get_agent_run()` for
  bounded runtime summaries.
- `GovernanceStore` and governance service functions for authoritative identity,
  campaign, assignment, and audit access.
- `AuthorizationStore` for authorization status summaries.
- `RoleRegistry.from_path()` for immutable registry inspection.
- `AgentActivityService.feed()` and `snapshot_to_public_dict()` for polling
  responses.
- `AgentActivityService.request_stop()` for append-only stop-request evidence.
- `AgentController.cancel()` and `approve_and_resume()` for supported runtime
  control transitions.
- `load_pilot_plan()` and `assess_pilot_plan()` for read-only pilot-plan
  presentation.

## Dependency changes

- Add `Django` as the approved secure server-rendered web framework.
- Add `pytest-django` under dev dependencies if required for Django test
  integration.
- Do not add any Node toolchain, frontend framework, WebSocket stack, Redis,
  Celery, DRF, or other browser dependency unless a concrete blocker appears.

## Web architecture

- Thin Django layer only:
  - Django settings, auth, session, CSRF, templates, and static assets.
  - Web adapters that translate Django requests into calls to existing
    `vulnhunter.product`, `vulnhunter.agent_activity`, `vulnhunter.agent`,
    `vulnhunter.pilot`, `vulnhunter.governance`, and `vulnhunter.authorization`
    services.
- No duplicate governance or readiness logic in views or templates.
- No direct mutation of authoritative VulnHunter stores from views.
- Django database limited to:
  - auth users;
  - sessions;
  - migration metadata;
  - narrow web identity mapping only.
- Existing domain data remains in the current SQLite stores and config files.

## Security boundaries

- Default bind address must remain loopback-only.
- `DEBUG` must remain environment-driven and off by default.
- `SECRET_KEY` must come from environment and never be committed.
- Local startup requires a privately generated `VULNHUNTER_WEB_SECRET_KEY`
  before `migrate`, local user creation, and `runserver --insecure 127.0.0.1:8000`.
- `--insecure` is restricted to loopback-only Django development static-file
  serving and must never be used for public or production deployment.
- Session and CSRF cookies must remain `HttpOnly`, `SameSite=Lax` or stricter,
  and `Secure` when HTTPS mode is enabled.
- Every protected route must enforce backend authorization, not hidden buttons.
- Untrusted content must stay escaped and inert; no `safe` rendering of runtime,
  evidence, report, or activity text.
- Activity and pilot views must rely on existing redaction/safe-rendering
  boundaries.
- No external network access during page rendering.
- Health endpoint is the only intentionally unauthenticated route besides login.

## URL and page map

- `/health/` minimal local health endpoint.
- `/login/` and `/logout/`.
- `/` dashboard.
- `/status/` system status.
- `/campaigns/` and `/campaigns/<campaign_id>/`.
- `/readiness/<campaign_id>/`.
- `/roles/` and `/roles/<role_id>/`.
- `/skills/` and `/skills/<skill_id>/`.
- `/agent/runs/` and `/agent/runs/<run_id>/`.
- `/agent/runs/<run_id>/activity/` polling endpoint.
- `/pilot/plans/` and `/pilot/plans/<plan_id>/`.
- `/pilot/plans/<plan_id>/validation/`.
- Control endpoints only where real backend support exists, likely limited to:
  - stop request / cancel bounded run;
  - approval resume for paused approval runs.

## Authentication design

- Use Django authentication for browser sessions.
- Add a narrow mapping from Django user to:
  - governance identity ID when one exists;
  - one or more product-surface role IDs;
  - optional allowed specialist role/skill references for control actions.
- Require explicit human creation of Django users through Django's safe user
  creation flow or a management command that demands interactive input.
- No default credentials, seeded users, fixture passwords, or committed secrets.

## Authorization design

- Route authorization enforced server-side with decorators/mixins/services.
- Fail closed when:
  - Django identity mapping is missing;
  - mapped governance identity is missing, disabled, or revoked when required;
  - requested product role is missing or not granted;
  - runtime control requires a specialist role/skill state that is missing or
    inactive.
- Read-only pages use product-surface role checks.
- Consequential bounded-run controls additionally validate:
  - mapped governance identity;
  - product-surface role permission;
  - relevant registry role/skill status where applicable;
  - runtime task state;
  - existing backend controller/service contract.

## Activity polling design

- Reuse `AgentActivityService.feed()` and `snapshot_to_public_dict()`.
- Authenticated GET endpoint:
  - accepts `after_sequence`;
  - returns only events after that sequence;
  - returns terminal state flag from the real event stream;
  - never fabricates percentages;
  - stops polling client-side when terminal.
- Agent run detail page embeds the existing safe activity JS/CSS and timeline
  container.
- Timeline metadata remains redacted, escaped, and expandable.

## Audit design

- Display real immutable evidence references from:
  - governance events;
  - product dashboard summaries;
  - agent task audit hashes;
  - activity event audit references;
  - pilot plan/report hashes.
- Consequential controls must flow through existing runtime and activity
  services so authoritative audit evidence is created by backend components.
- If a requested control cannot produce authoritative audit evidence, render it
  as unavailable instead of simulating it.

## Test strategy

- Add Django settings and integration tests for:
  - boot and secure defaults;
  - auth/session/CSRF behaviour;
  - protected page redirects and denials;
  - product page rendering against empty and fixture-backed stores;
  - activity polling, ordering, filtering, and terminal behaviour;
  - inert rendering for HTML, script, prompt-injection, shell-looking, and
    credential-like input;
  - supported and unsupported consequential controls;
  - accessibility landmarks and safe markup assertions.
- Reuse existing unit-test fixture patterns for governance, product, and agent
  runtime data.

## Rollback strategy

- Revert the Django package wiring, web app, templates, and static assets as one
  focused architectural change.
- Preserve existing product, pilot, agent activity, governance, and runtime
  foundations.
- Remove the Django-only database and migrations if the web layer is rolled
  back.
- Re-run focused web/product/agent/pilot verification and the project audit.

## Explicit non-goals

- No public or external scanning.
- No connector activation.
- No DRF, WebSockets, Redis, Celery, or Node build pipeline.
- No automatic approval, release, adjudication, or campaign mutation.
- No model training or promotion.
- No direct browsing or editing of raw unredacted evidence.
- No hidden reasoning or prompt material display.
- No production deployment or cloud setup.
