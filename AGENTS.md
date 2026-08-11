# VulnHunter AI — Permanent Agent Operating Manual

**STATUS: BINDING FOR THE ENTIRE REPOSITORY**

This file is the first authority every human or coding agent must read before changing VulnHunter.

---

## 1. Product identity

VulnHunter AI is an **authorised security-assessment platform** for private/laboratory targets, owner-controlled public targets, and other public targets covered by explicit written/program authorization.

The product combines deterministic scope and execution controls, evidence provenance, bounded scanners, human authority, optional advisory AI, source-code analysis, mobile analysis and a conversation/task-first browser workspace.

**Public Internet does not mean ungoverned.** VulnHunter may assess an authorised public target, but it must never scan an arbitrary public target merely because a URL was supplied.

---

## 2. Non-negotiable security boundary

VulnHunter may support:

- exact private and public target normalization;
- explicit time-limited authorization records;
- owner-controlled public-target self-attestation where product policy permits it;
- independently approved client/third-party targets;
- bug-bounty/Vulnerability Disclosure Programme targets within the exact programme scope;
- bounded passive HTTP/security collection;
- reviewed Nuclei execution through a governed worker;
- evidence normalization and deterministic verification;
- Source Hunt against exact approved source snapshots;
- APK/static analysis and separately governed dynamic/active validation where implemented;
- human review, adjudication and publication governance;
- reproducible ML/retrieval experiments and advisory model assistance.

VulnHunter must not:

- scan an arbitrary or unverified public target;
- infer permission from a URL, chat message, model output or screenshot;
- weaken scope/authorization to make a workflow succeed;
- permit DNS rebinding or redirects to pivot from a public target into private, loopback, link-local or metadata networks;
- brute-force credentials without a separately approved product contract;
- perform destructive actions, denial of service, persistence or data destruction;
- upload or execute arbitrary payloads against a target;
- bypass authentication/access control merely to continue a scan;
- let an AI model grant authorization, approval, verification, severity, review, merge, release or publication authority;
- persist raw secrets, authentication values, cookies, private keys or unredacted sensitive data;
- present benchmark/model scores as real-world production performance without the required governed evidence.

When the requested change would weaken one of these boundaries, stop and report the exact conflict.

---

## 3. Mandatory product/security documents

Before substantial work, read the documents relevant to the affected boundary.

### Website/private/public target work

1. `docs/product/PUBLIC_TARGET_ASSESSMENT.md`
2. `docs/product/LIVE_EXECUTION_ACTIVITY.md`
3. `docs/product/CHAT_FIRST_WORKSPACE.md`
4. relevant authorization/scope/scanner implementation and tests

### Source Hunt

1. `docs/product/SOURCE_HUNT.md`
2. `docs/product/LIVE_EXECUTION_ACTIVITY.md`
3. `docs/product/CHAT_FIRST_WORKSPACE.md`
4. exact source-processing, snapshot, provider and queue implementation/tests

### Browser UI

Read in this exact order:

1. this file;
2. `vulnhunter/web/AGENTS.md`;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
5. `docs/design/references/manifest.json`;
6. `docs/design/DEPRECATIONS.md`;
7. `docs/product/CHAT_FIRST_WORKSPACE.md`;
8. `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
9. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
10. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
11. relevant backend routes, commands, projections, persisted state and tests.

### ML/intelligence work

Read the current-state/roadmap owners and the exact ML governance/architecture documents. Do not infer implementation status from an older programme document.

---

## 4. Authority order

When sources disagree, use this order:

1. security/authorization/runtime invariants in code and this operating manual;
2. explicit current product contracts;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md` for visual/interaction rules;
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md` for frontend implementation discipline;
5. approved reference manifest;
6. current-state/roadmap owners;
7. specialist/historical architecture documents;
8. current implementation/tests only as evidence of what exists;
9. agent preference — never authority.

Old screenshots, old CSS, stale tests and historical docs do not override a newer binding contract.

---

## 5. Public-target rules

Public-target support is a permanent product requirement, but it must be implemented through a distinct governed path.

Required invariants:

- exact target URL, protocol, port and path boundary;
- explicit owner/controller and approver identity;
- evidence reference and purpose;
- exact approved scan profile and expiry;
- explicit public/private address classification;
- connection-time DNS/address containment;
- no mixed public/private resolution;
- no localhost, loopback, link-local, metadata or unsupported special-use destination;
- approved-address pinning or an equivalent reviewed containment mechanism;
- original hostname preserved for HTTP Host, TLS SNI and certificate validation;
- every redirect independently revalidated;
- worker policy explicitly declares whether it supports public execution;
- a private-only worker continues to reject public jobs;
- browser/chat cannot toggle a worker into public mode.

**Do not implement public support by globally setting `allow_public=True`, deleting private-target assertions, or bypassing the worker policy.**

The complete contract is `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

---

## 6. Authorization rules

Technical scope validation and permission are separate.

Every executable website assessment must present an active authorization record that covers the exact target and requested limits/profile.

Authorization must be validated before creating a network-execution job.

Expired, revoked, mismatched, tampered or over-limit authorization fails closed.

Authorization events are append-only and redacted.

Self-authorization may exist only for an owner-controlled target under an explicit product policy. Client/third-party/bounty scope must use an appropriate independent/written authorization basis.

Do not store secrets inside the evidence reference.

---

## 7. Scope and transport rules

A raw unvalidated URL must not reach network execution.

For private and public targets:

- only supported schemes are accepted;
- embedded URL credentials are prohibited;
- scheme, hostname, port and segment-aware path boundaries remain exact;
- `/app` must not authorize `/application`;
- redirects are disabled by default or manually revalidated;
- connection-time DNS/address state must remain inside the authorized set/policy;
- Host/TLS identity must remain the original hostname when address pinning is used;
- a public hostname must not rebind to private/metadata space;
- response bodies, requests, timeouts, retries and cancellation remain bounded;
- automatic updates, public OAST, cloud upload and arbitrary command arguments remain prohibited unless a separate reviewed contract explicitly changes them.

---

## 8. Scanner/worker rules

The browser prepares and approves plans; it does not execute scanner subprocesses directly.

Worker capability is explicit and immutable for a job.

A worker must validate:

- authorization/plan/approval identity;
- target class it is permitted to handle;
- exact profile;
- template manifest/digests;
- rate/concurrency/timeout/output limits;
- cancellation/expiry;
- evidence output root;
- transport containment.

The current private-lab worker safety assertions are not expendable. Public support requires a reviewed public-capable execution boundary, not a permissive flag flip.

---

## 9. Live execution is mandatory product behavior

Any long-running task that is queued/running must project meaningful persisted activity into the same workspace.

The user should be able to understand:

- current stage;
- completed stages;
- next stages;
- active worker/tool where known;
- real receipts/evidence/candidate counts;
- blockers/failures/recovery;
- preserved state;
- available safe action.

The product must not respond only with “backend is executing; go elsewhere to check.”

Do not expose hidden chain-of-thought. Render safe operational telemetry only.

The binding contract is `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 10. Source Hunt rules

Source Hunt binds to an exact repository root, revision, eligible-file snapshot hash and permitted paths.

Remote source processing requires an exact time-limited approval and password re-authentication where the browser contract requires it.

The current deterministic mapper is Python-first. Unsupported languages/ambiguous paths must not be silently treated as covered.

Source Hunt must perform preflight before queueing and should surface file/byte/eligibility limits before the user receives a generic queue failure.

Permitted paths must eventually constrain the snapshot/processing boundary in a way that is technically enforceable; do not imply that a form field narrowed the snapshot when runtime still scanned the entire repository root.

Groq/model output may propose hypotheses, falsify them, assess capability and propose remediation. It cannot authorize processing, verify a finding, set severity, edit/merge code or publish.

---

## 11. APK/mobile rules

Uploading an APK never means executing it.

Static tools operate on an immutable validated artifact and persist individual tool receipts.

Dynamic execution remains separately governed and environment-gated.

Tool failures preserve partial evidence and do not fabricate findings.

---

## 12. Evidence and human authority

Scanner observations and model hypotheses are evidence/candidates, not proof.

Human review remains authoritative where the governance contract requires it.

New governed real observations require the configured independent review/adjudication path.

Predictions must never mutate review labels.

Evidence shown to users/reviewers must be redacted and assessment-scoped.

---

## 13. Sensitive-data rules

Redact before logging, persistence, prompts, exports or exceptions cross a trust boundary.

Protected examples include:

- authorization headers;
- cookies/session identifiers;
- passwords/secrets;
- API keys/tokens;
- private keys;
- embedded URL credentials;
- unnecessary emails/PII;
- payment-card-like values.

Raw response bodies may exist only as bounded short-lived values under the relevant execution policy.

---

## 14. AI/provider authority

The current provider inventory is governed by `docs/product/AI_ROUTING.md` and current code. Do not reintroduce stale “Groq is the only provider everywhere” language when other approved advisory provider families exist.

Provider/model controls never override deterministic policy.

Models propose/retrieve/explain. VulnHunter validates/enforces/records authority.

Source Hunt may remain Groq-specific when the Source Hunt contract says so.

---

## 15. Machine-learning rules

Do not train on unreviewed/ineligible observations.

Preserve release provenance, application-family isolation, calibration/OOD/abstention boundaries, model registry state and human authority as implemented by the current Programme 3 contracts.

Never tune against a locked external holdout.

Never describe a raw posterior as calibrated real-world confidence.

Never claim real-world performance from synthetic benchmark evidence.

---

## 16. Engineering workflow

Substantial delivery must follow `docs/engineering/TEST_ENGINEERED_BATCH_DELIVERY.md` where applicable.

Before changing code:

1. inspect current `main`, open PRs, recent commits and CI;
2. read relevant implementation, tests and public exports;
3. identify trust/security/data-flow boundaries;
4. define failure behavior before happy-path behavior;
5. identify the authoritative state owner;
6. define mobile/browser behavior for product-facing changes;
7. decide exact verification evidence.

During implementation:

- make one coherent dependency-aligned change;
- use typed immutable models at trust boundaries;
- redact before persistence/output;
- avoid hidden network calls in unit tests;
- keep external dependencies minimal;
- preserve backward compatibility unless migration is intentional/documented;
- never weaken a test/security gate merely to make a change pass.

Required repository checks before claiming completion:

```bash
python -m ruff format .
python -m ruff check .
python -m compileall -q vulnhunter
python -m pytest -q
python -m ruff format --check .
git diff --check
git status --short
```

Run additional browser/phone/worker/public-target/Source-Hunt gates required by the affected contract.

Do not claim completion when you cannot run required checks; report that limitation explicitly.

---

## 17. Frontend/UI governance

VulnHunter is a conversation/task-first security workspace, not an admin dashboard with a chatbot attached.

Reference roles are fixed:

- **MonkeyCode:** task/workspace structure and interaction behavior only;
- **Beautiful UI:** AI-native component/microinteraction patterns only;
- **VulnHunter:** functionality, authority, terminology, branding and warm cream/off-white dotted + dusty-pink + compact-dark-sidebar identity.

The current UI implementation is not design authority.

Explicitly rejected patterns include:

- four large Authorization/Scope/Approval/Active cards on ordinary chat;
- the wide Source Hunt/Search/Export/History/New workspace toolbar;
- KPI-card walls as the workspace;
- giant dark Source Hunt/admin surfaces;
- desktop composition squeezed onto phone;
- clipped phone controls/horizontal page overflow;
- tiny low-contrast conversation text;
- permanent context panels when not opened;
- another late-loaded global CSS patch layer;
- hidden chain-of-thought.

Follow the full read order in section 3.

---

## 18. Testing requirements

Every security-sensitive change needs:

- expected-success test;
- blocked/failure test;
- regression test for the motivating defect;
- deterministic/offline inputs where practical.

Public-target changes additionally require the complete containment tests in `PUBLIC_TARGET_ASSESSMENT.md`.

Live-execution changes require reconnect/deduplication/persisted-event acceptance from `LIVE_EXECUTION_ACTIVITY.md`.

Browser UI work requires real browser evidence at representative desktop/tablet/phone widths and backend-connected state truth.

---

## 19. Status/documentation truth

Documentation must distinguish:

- product requirement/contract;
- implemented runtime capability;
- implemented but unverified/manual evidence pending;
- planned/not complete;
- known failure/blocker.

Do not classify documentation as implementation.

`docs/intelligence/CURRENT_STATE.md` is the current implementation-status owner. `docs/intelligence/ROADMAP.md` owns dependency order. `docs/intelligence/KNOWN_FAILURES.md` owns unresolved limitations.

When a PR merges, reconcile those owners so they do not claim already-merged work is pending or already-broken work is complete.

---

## 20. Mandatory stop/escalation conditions

Stop and report when:

- target authorization is absent/ambiguous;
- public-target support would require weakening DNS/address containment;
- Host/SNI/certificate semantics cannot be preserved under the chosen pinning design;
- the scanner performs an uncontrollable second DNS resolution;
- a redirect/DNS result escapes the exact target boundary;
- secrets appear in tracked files/output;
- working tree/baseline differs from assumptions;
- tests fail for unknown reasons;
- a change requires data leakage or holdout contamination;
- destructive behavior is requested without an explicit approved contract;
- a dependency/design choice cannot be justified.

Escalation means preserving evidence and stating the blocker. It never means silently broadening permission.

---

## 21. Definition of done

A milestone is done only when:

- architecture/security boundaries remain coherent;
- implementation matches the current product contracts;
- relevant tests/gates pass;
- browser/phone evidence exists when required;
- documentation/status owners are reconciled;
- known limitations are recorded;
- no temporary/sensitive artifacts are tracked;
- claims are supported by evidence;
- Git contains focused reviewable changes.
