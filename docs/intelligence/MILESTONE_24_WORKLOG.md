# Milestone 24 Worklog

## Verified baseline

- Inspection date: 2026-07-10 UTC
- Repository root: `/home/okunlola_labs/Projects/vulnhunter-ai`
- Required branch requested: `milestone-24-operational-product-console`
- Active branch after inspection: `milestone-24-operational-product-console`
- Baseline HEAD at inspection: `fa330e4 Add bounded security agent runtime foundation`
- Working tree before edits: clean

## Read-only inspection record

- `pyproject.toml` defines a Python-only application with `httpx`, `httpcore`,
  `pydantic`, `typer`, `SQLAlchemy`, and `beautifulsoup4`.
- No existing web framework, template engine, asset pipeline, session stack, or
  CSRF mechanism is installed or configured.
- No operational templates or static frontend assets exist in the repository.
- `config/product_interface/` and `docs/product/` are blueprint/specification
  artifacts. They explicitly describe planned product pages and intended API
  contracts, not implemented endpoints.
- `vulnhunter/product_spec/` loads and validates the product specification only.
- `config/agent_runtime/` and `vulnhunter/agent/` provide a bounded runtime
  foundation with deterministic policy, immutable audit storage, task control,
  and a safe demo CLI.
- `config/roles/` and `vulnhunter/roles/` provide a read-only versioned role and
  skill registry. Current registry status remains planned/untrusted.
- `vulnhunter/governance/`, `vulnhunter/authorization/`,
  `vulnhunter/observations/`, and `vulnhunter/ml/` provide real domain and
  persistence services that can back read models today.
- `.github/workflows/quality.yml` and `scripts/project_audit.py` remain the
  authoritative quality gate definitions.

## Architecture discovered

### Existing reusable components

- Authorization registry store and validation service.
- Governance registry store and governed campaign lifecycle service.
- Read-only pilot readiness assessment.
- Scan repository and governed review-case queries.
- Role/skill registry loading, validation, fingerprinting, and action
  evaluation.
- Bounded agent runtime configuration loading, task persistence, audit-chain
  verification, policy evaluation, approval pause/resume, and cancel controls.
- Product-interface blueprint loader and validation.

### Missing components

- Browser-capable web framework.
- Safe server rendering layer.
- Session/authentication middleware for interface actors.
- CSRF protection for consequential browser actions.
- Route/controller layer implementing the product blueprint.
- Operational templates, static assets, and component system.

## Verified backend capabilities

### Genuinely implemented now

- Authorization inspection and validation.
- Campaign inspection, assignments, attestations, releases, and audit events.
- Pilot readiness assessment from governed data.
- Role and skill registry inspection and policy decisions.
- Agent task inspection, approval resume, cancel, and audit verification.

### Specification-only today

- Product API resources under `/api/v1/...`.
- Browser navigation shell and page routing.
- Product session resource and logout flow.
- Browser approval queue and controlled HTML forms.
- Route-level object authorization for browser actors.

## Security and boundary findings

- The interface cannot safely be implemented as an ad hoc browser server inside
  this milestone without adding an approved framework and browser security
  primitives.
- Existing governance identity authentication is domain-level and CLI/service
  oriented. It is not yet a browser session/authentication mechanism.
- Client-side visibility cannot be trusted and must not become authorization.
- Role registry entries are currently planned/untrusted; runtime use must remain
  explicitly non-operational unless validated and promoted by policy.

## Architectural decision for this repository state

Implement the framework-independent application/read-model boundary now, backed
by real repositories and services, and expose it through a controlled local CLI
surface. Do not invent a browser server, session layer, or template runtime in
the absence of an approved dependency.

Document the smallest safe next dependency required for a browser shell as a
human approval point.

## Implementation phases

### Phase 0

- [x] Mandatory read-only architecture inspection
- [x] Baseline verification and branch alignment
- [x] Worklog creation

### Phase 1

- [x] Add typed product read models
- [x] Add product application services over existing stores
- [x] Integrate role/skill registry and bounded agent runtime summaries
- [x] Fail closed on missing or invalid stores/configuration

### Phase 2

- [x] Add controlled local product CLI surface over read models
- [x] Expose dashboard, campaign/readiness, role/skill, and agent-console views
- [x] Expose unsupported browser-specific capabilities as unavailable
- [ ] Browser shell, route/controller layer, and authenticated approval UI
  remain blocked pending approval of a safe web framework plus session and
  CSRF protections.

### Phase 3

- [x] Add focused tests for product services and CLI surfaces
- [x] Add inert-untrusted-content tests
- [x] Run milestone verification sequence

## Files expected to change

- `docs/intelligence/MILESTONE_24_WORKLOG.md`
- `docs/intelligence/CURRENT_STATE.md`
- `docs/intelligence/SYSTEM_ARCHITECTURE.md`
- `docs/intelligence/TECHNICAL_DEBT.md`
- `docs/intelligence/ROLE_AND_SKILL_REGISTRY.md`
- `docs/intelligence/BOUNDED_SECURITY_AGENT_RUNTIME.md`
- `docs/adr/0014-*.md` if required by the final boundary decision
- `vulnhunter/agent/models.py`
- `vulnhunter/agent/store.py`
- `vulnhunter/cli.py`
- `vulnhunter/product/*`
- `tests/unit/test_product_*`
- existing tests adjusted only where the new boundary is intentionally integrated

## Backend boundaries

- Product layer reads through `AuthorizationStore`, `GovernanceStore`,
  `ScanRepository`, `RoleRegistry`, `AgentStore`, runtime config loading, and
  readiness assessment.
- Product layer must not directly mutate SQLite tables.
- Consequential runtime actions remain backend-controlled and audit-backed.
- Browser-specific mutation surfaces remain out of scope until a safe framework
  is approved.

## Safety risks

- Inventing browser auth/session handling locally would weaken the product
  boundary.
- Surfacing role-registry entries as operational despite planned/untrusted status
  would misstate trust.
- Conflating blueprint-only pages with implemented capabilities would fabricate
  product state.
- Rendering evidence unsafely could turn untrusted content into instructions.

## Test plan

- Product status with missing and available stores.
- Dashboard summaries with empty data and governed fixture data.
- Campaign detail and readiness summaries.
- Role/skill summaries including disabled/untrusted handling.
- Agent run summaries for denied, approval-required, approved, paused, and
  cancelled flows.
- Inert rendering of instruction-like evidence strings.
- CLI surface verification for empty, unavailable, denied, and successful
  read-only outputs.

## Rollback approach

- Revert the `vulnhunter.product` package and CLI wiring as one focused change.
- Revert the agent-runtime schema additions only if they are not required by
  existing persisted tasks.
- Re-run focused product tests, agent tests, role-registry tests, and full
  verification.

## Explicit non-goals

- No public or external scanning.
- No new browser server without dependency approval.
- No connector activation.
- No model training or promotion.
- No automatic approvals, releases, adjudications, or campaign decisions.
- No direct database mutations from a route or template layer.

## Verification outcome

- Focused product service tests: passed.
- Focused product CLI tests: passed.
- Existing product-interface specification tests: passed.
- Existing agent-runtime tests: passed.
- Existing role-registry tests: passed.
- Existing governance/readiness tests: passed.
- Full Ruff check: passed.
- Full Ruff format check: passed.
- Compile validation: passed.
- Full pytest run: passed.
- Project audit: 1 warning, `Working tree is not clean`, caused by the
  required uncommitted milestone changes because this task forbids committing.
