# VulnHunter Web Application

## Purpose

The VulnHunter web application is a local, authenticated, server-rendered
operational surface for inspecting real repository-backed authorization,
governance, readiness, role/skill registry, bounded-agent, pilot-plan, and
audit data.

It is not a public deployment target and it does not authorize collection,
approve campaigns, execute public scans, or display hidden reasoning.

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

The current default user model uses `username` as `USERNAME_FIELD`. Bootstrap a
governance administrator through the hidden-prompt governance CLI if the registry
is empty, then run first-time setup in order:

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

Repeat startup in a fresh shell uses the same local secret from the shell
environment or your private env file, then:

```bash
python manage.py migrate
python scripts/run_local_preview.py
```

Expected default address:

- guest: `http://10.0.2.15:8002/`
- existing host forward: `http://127.0.0.1:18002/`

The preview script binds guest `0.0.0.0:8002` only for the explicitly provided
QEMU host forward, uses an ephemeral development-only secret, disables HTTPS mode,
and allowlists localhost/127.0.0.1/10.0.2.15. It is not a production command.

`--insecure` is Django's local-development static-file serving option. It is
used here only because this loopback-only milestone keeps `DEBUG` disabled by
default. It does not disable VulnHunter authentication, session, authorization,
or CSRF protections. Never use this command for public or production
deployment.

## First-time local setup

The command prompts interactively for the password and does not store
credentials in the repository.

To update an existing mapping:

```bash
python manage.py vh_map_web_user \
  --username <local-user> \
  --governance-identity <reviewer-id> \
  --product-role security-auditor
```

## Environment variables

- `VULNHUNTER_WEB_SECRET_KEY`
  Required when `VULNHUNTER_WEB_DEBUG` is not enabled.
- `VULNHUNTER_WEB_DEBUG`
  Defaults to `false`.
- `VULNHUNTER_WEB_HTTPS`
  Enables secure-cookie and HTTPS-oriented settings when true.
- `VULNHUNTER_WEB_ALLOWED_HOSTS`
  Defaults to `127.0.0.1,localhost,testserver`.
- `VULNHUNTER_WEB_TRUSTED_ORIGINS`
  Optional comma-separated CSRF trusted origins.
- `VULNHUNTER_WEB_DATABASE`
  Defaults to `.local/vulnhunter-web.sqlite3`.
- `VULNHUNTER_AUTHORIZATION_DATABASE`
  Defaults to `authorizations.db`.
- `VULNHUNTER_GOVERNANCE_DATABASE`
  Defaults to `governance.db`.
- `VULNHUNTER_AGENT_DATABASE`
  Defaults to `.local/runtime/agent/agent.db`; initialize it explicitly with
  `vh_init_agent_store`.
- `VULNHUNTER_AGENT_ACTIVITY_ROOT`
  Defaults to `.local/agent-activity`.
- `VULNHUNTER_ROLE_REGISTRY_ROOT`
  Defaults to `config/roles`.
- `VULNHUNTER_RUNTIME_CONFIG`
  Defaults to `config/agent_runtime/runtime.json`.
- `VULNHUNTER_PRODUCT_SPEC_ROOT`
  Defaults to `config/product_interface`.
- `VULNHUNTER_PILOT_PLAN_ROOT`
  Defaults to `config/pilot`.

## Secure defaults

- Authenticated session boundary uses Django auth.
- `HttpOnly` session and CSRF cookies.
- `SameSite=Lax` cookies.
- Secure cookies only when HTTPS mode is enabled.
- CSRF middleware enabled for state-changing requests.
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- strict same-origin Content Security Policy for scripts, styles, forms, and
  polling.
- Referrer policy via Django security settings.
- Only `/health/` and `/login/` are unauthenticated.

## Identity mapping

Each Django user maps to:

- one governed identity ID from the governance store;
- one or more product-surface role IDs from
  `config/product_interface/role_permissions.json`;
- optional specialist registry role/skill references for future narrowing.

The mapping is stored only in the Django web database through
`vulnhunter.web.models.WebUserMapping`.

The full Role and Skill Registry is not duplicated into Django models.

## URL and page map

- `/health/`
- `/login/`
- `/logout/`
- `/`
- `/status/`
- `/campaigns/`
- `/campaigns/<campaign_id>/`
- `/readiness/<campaign_id>/`
- `/roles/`
- `/roles/<role_id>/`
- `/skills/`
- `/skills/<skill_id>/`
- `/agent/runs/`
- `/agent/runs/<run_id>/`
- `/agent/runs/<run_id>/activity/?after_sequence=<n>`
- `/agent/runs/<run_id>/stop/`
- `/pilot/plans/`
- `/pilot/plans/<plan_id>/`
- `/pilot/plans/<plan_id>/validation/`

## Service integration

Primary read path:

```text
Django view
  -> vulnhunter.web.services
  -> vulnhunter.product.ProductApplicationService
  -> authorization / governance / readiness / registry / agent stores
```

Additional read-only integrations:

- pilot plans through `vulnhunter.pilot`
- activity polling through `vulnhunter.agent_activity`

The web layer does not duplicate readiness, governance, or registry policy.

## Live activity polling

- Polling is authenticated same-origin GET.
- The endpoint returns only events after `after_sequence`.
- Event payloads come from the existing `vulnhunter.agent_activity` redaction
  boundary.
- Polling stops when the run reaches a terminal activity state.
- No invented progress percentage is displayed.

## Redaction and untrusted content

- Django template auto-escaping remains enabled.
- No untrusted content is rendered with `safe`.
- Activity summaries and metadata are redacted and hidden-reasoning fields are
  omitted before persistence.
- Pilot-plan, role, skill, campaign, and evidence-like text is rendered as inert
  text only.

## Approval and stop boundaries

Supported now:

- bounded-run stop confirmation surface;
- authenticated POST stop action with CSRF;
- append-only stop request event in the activity log;
- bounded task cancellation through the existing agent controller.

Unavailable now:

- approval resume from the browser;
- approval rejection from the browser;
- manual operator pause.

These remain unavailable because the current backend does not expose a safe
general runtime-reconstruction contract for persisted tasks, and it does not
provide distinct rejection or operator-pause transitions.

## Pilot-plan presentation

Pilot-plan pages are read-only.

The interface explicitly preserves this separation:

- plan validation
- pilot authorization
- pilot execution
- dataset release
- model-training approval

These are not equivalent.

## Local database handling

- Django database default: `.local/vulnhunter-web.sqlite3`
- Authoritative domain stores remain separate:
  - `authorizations.db`
  - `governance.db`
  - `.local/runtime/agent/agent.db`
- Generated local database files remain ignored by Git.

## Test commands

Focused web and integration slice:

```bash
python -m pytest -q tests/unit/test_agent_controller_activity.py tests/unit/test_web_app.py
```

Repository verification remains the required final gate:

```bash
python -m ruff check .
python -m ruff format --check .
python -m compileall -q vulnhunter
VULNHUNTER_WEB_SECRET_KEY=local-check-secret python manage.py check
VULNHUNTER_WEB_SECRET_KEY=local-check-secret python manage.py makemigrations --check --dry-run
VULNHUNTER_WEB_SECRET_KEY=local-check-secret python manage.py findstatic \
  web/app.css web/activity.css web/app.js web/activity.js
python scripts/project_audit.py
python -m pytest -q
```

## Known limitations

- The web product is local-only and not production-hardened for Internet
  exposure.
- Browser approval resume, approval rejection, and operator pause are
  intentionally unavailable.
- Existing product-interface blueprint JSON remains broader than the current
  implemented web route set.
- The default specialist registry remains planned/untrusted, so operational trust
  still depends on explicit human review and repository policy.
