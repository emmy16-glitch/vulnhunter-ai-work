# VulnHunter Project Intelligence Pack

**Status:** CURRENT DOCUMENT INDEX / AUTHORITY MAP

This directory is VulnHunter's model-agnostic project memory. It contains current architecture/status/governance documents plus historical milestone evidence.

It must not become a collection of competing “single sources of truth.”

---

## 1. Start here

Every human or coding agent starts with:

1. repository-root `AGENTS.md`;
2. [Current state](CURRENT_STATE.md);
3. [Dependency-ordered roadmap](ROADMAP.md);
4. [Master architecture](VULNHUNTER_MASTER_ARCHITECTURE.md);
5. the focused product/security contracts relevant to the task.

For browser/UI work, follow the exact read order in `AGENTS.md` and `vulnhunter/web/AGENTS.md`.

For public website work, read `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

For long-running task/activity work, read `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 2. Current product/security owners

### Product/workspace

- [Product definition](PRODUCT_DEFINITION.md)
- [Chat-first workspace](../product/CHAT_FIRST_WORKSPACE.md)
- [Live execution activity](../product/LIVE_EXECUTION_ACTIVITY.md)
- [Public target assessment](../product/PUBLIC_TARGET_ASSESSMENT.md)
- [Source Hunt](../product/SOURCE_HUNT.md)
- [Governed Nuclei integration](../product/NUCLEI_INTEGRATION.md)
- [AI provider routing/privacy](../product/AI_ROUTING.md)
- [LLM/provider readiness](../product/LLM_RUNTIME_READINESS.md)
- [Advisory reasoning](../product/ADVISORY_REASONING.md) — specialist/legacy Groq pipeline, not global provider authority

### Browser/design

- `docs/design/VULNHUNTER_UI_CONTRACT.md`
- `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`
- `docs/design/references/manifest.json`
- `docs/design/DEPRECATIONS.md`
- `docs/product/UI_ACCEPTANCE_CRITERIA.md`
- `docs/product/UI_QUALITY_ASSURANCE.md`
- `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`

### Authorization/security

- [Explicit target authorization](TARGET_AUTHORIZATION.md)
- [Connection pinning](CONNECTION_PINNING.md)
- [Security boundaries](SECURITY_BOUNDARIES.md)
- [ADR index](../adr/README.md)

### Human review/data governance

- [Data and review](DATA_AND_REVIEW.md)
- [Independent review](INDEPENDENT_REVIEW.md)
- [Governed collection/review](GOVERNED_COLLECTION_AND_REVIEW.md)
- `docs/DATA_QUALITY.md`

### ML/intelligence

- [ML and Hugging Face production architecture](ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)
- [ML governance](ML_GOVERNANCE.md)
- `docs/ML_PIPELINE.md`
- `docs/MODEL_SELECTION.md`

### Engineering/operations

- [Testing strategy](TESTING_STRATEGY.md)
- [Bounded orchestration](ORCHESTRATION_LOOP.md)
- [Transactional autoresearch](AUTORESEARCH_ENGINE.md)
- [Unattended operations](UNATTENDED_OPERATIONS.md)
- [Technical debt](TECHNICAL_DEBT.md)

---

## 3. Status authority

Only these documents should be used to answer “what is implemented now?” and “what comes next?” at a high level:

- `CURRENT_STATE.md` — actual runtime classification;
- `KNOWN_FAILURES.md` — current unresolved limitations;
- `ROADMAP.md` — current dependency order.

Architecture/design documents describe required behavior. Documentation alone does not make runtime capability implemented.

Use explicit state language:

```text
CONTRACT APPROVED
RUNTIME NOT COMPLETE
RUNTIME PARTIAL
RUNTIME IMPLEMENTED
AUTOMATED ACCEPTANCE COMPLETE
MANUAL EVIDENCE PENDING
IMPLEMENTED AND VERIFIED
```

Avoid an unqualified `complete` when scopes differ.

---

## 4. Current top-level product decisions

### Authorised public targets

The product supports explicitly authorised private and public website targets.

```text
authorised private target → supported product class
authorised public target  → supported product class
arbitrary public target   → prohibited
```

Current runtime is still narrower: the current passive Nuclei worker is private-only until the public transport/worker programme is implemented and accepted.

Never implement public support by globally relaxing scope checks or deleting private-worker protections.

### Persisted live execution

Queued/running work must expose truthful persisted operational activity in the originating workspace.

A generic “backend is running; go elsewhere” message is not the finished product.

### UI Contract V2

The conversation/task-first UI contract is authoritative. Existing templates/CSS/tests may still contain migration debt and are not visual authority.

### Provider authority

Global provider policy is provider-neutral and currently includes optional Groq and Hugging Face families where configured. Source Hunt may remain Groq-specific.

Models never become authorization/execution/verification/review/publication authority.

---

## 5. Historical documents

Files named like:

```text
MILESTONE_*
TOTAL_PROGRAMME_*
older handoffs / execution trackers / historical future plans
```

are **historical provenance unless a current authority explicitly says otherwise**.

They may explain why a capability exists or preserve acceptance evidence from an earlier baseline, but they must not override current state, roadmap, security contracts or UI contracts.

`VULNHUNTER_FUTURE_MASTER_PLAN.md` is explicitly retired as a current authority source.

Do not start a new agent session by reading a historical milestone and treating it as the current roadmap.

---

## 6. Non-duplication rule

Do not create another document that claims to replace any of these owners:

- target/public authorization → `TARGET_AUTHORIZATION.md` + `PUBLIC_TARGET_ASSESSMENT.md`;
- live task telemetry → `LIVE_EXECUTION_ACTIVITY.md`;
- browser visual/interaction design → locked `docs/design/` contracts;
- current implementation status → `CURRENT_STATE.md`;
- dependency order → `ROADMAP.md`;
- unresolved limitations → `KNOWN_FAILURES.md`;
- provider routing/privacy → `AI_ROUTING.md`;
- Source Hunt → `SOURCE_HUNT.md`;
- ML governance/architecture → existing ML owners.

When a cross-cutting change affects multiple owners, update all relevant owners in the same implementation sequence.

---

## 7. Maintenance requirements

A change that modifies any of the following must reconcile the corresponding owner documents:

- public/private target classes;
- authorization evidence/approval;
- scanner/worker transport;
- task/activity events;
- Source Hunt snapshot/path semantics;
- APK worker state;
- selected-assessment projection;
- browser shell/navigation/components;
- responsive/accessibility behavior;
- evidence/finding/review/report lifecycle;
- AI provider routing/readiness;
- ML dataset/model/registry lifecycle;
- implementation status/dependency order/known limitations.

At minimum, after a significant capability lands ask:

1. Did `CURRENT_STATE.md` change?
2. Did `KNOWN_FAILURES.md` change?
3. Did `ROADMAP.md` change?
4. Did a security/product contract change?
5. Did UI acceptance need a new regression scenario?

---

## 8. Repository audit

Run the repository audit after meaningful changes when the current engineering contract requires it:

```bash
python scripts/project_audit.py
```

Generated audit files under `artifacts/project-audit/` are evidence, not authority.

Maintained source documents and runtime/test evidence remain authoritative.
