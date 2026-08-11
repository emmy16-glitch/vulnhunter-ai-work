# VulnHunter Web Application

**Status:** CURRENT BROWSER PRODUCT ARCHITECTURE  
**Visual authority:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Workflow:** `docs/product/CHAT_FIRST_WORKSPACE.md`  
**Live activity:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`  
**Public targets:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`

## 1. Purpose

The VulnHunter web application is an authenticated **conversation/task-first security-assessment workspace**.

It projects real repository-backed state for:

- website target/authorization/assessment workflows;
- authorised private and public target classes;
- immutable plans/decisions;
- worker execution/activity;
- Source Hunt;
- APK/mobile analysis;
- evidence/findings/verification;
- independent review/adjudication;
- campaigns/releases/datasets;
- reports/audit/settings;
- optional advisory intelligence.

The browser is a governed control surface, not a second security-control plane.

Backend authorization, worker capability, task state, evidence integrity, verification, human review and release/publication gates remain authoritative.

---

## 2. Product composition

### Desktop

```text
compact task/chat sidebar
→ main conversation + task timeline + live activity
→ persistent composer
→ optional contextual detail drawer
```

### Mobile

```text
overlay task/chat drawer
→ one-column conversation + task timeline + live activity
→ persistent composer
→ full-width context/activity/evidence sheet or deep view
```

The web product is **not** a permanent dark operations dashboard.

The locked visual identity is the warm cream/off-white dotted VulnHunter workspace with dusty-pink accents, compact dark sidebar, near-black technical text/borders, square/nearly-square geometry and hard zero-blur offset shadows.

Do not revive older dark-console/KPI/dashboard patterns from historical screenshots/templates/tests.

---

## 3. Current implementation versus target product

The browser/runtime already contains significant workspace, authorization, assessment, evidence, review, Source Hunt, APK and governance infrastructure.

However, current status must be read from `docs/intelligence/CURRENT_STATE.md`.

In particular:

- UI Contract V2 is authoritative but migration of all old presentation is still incomplete;
- rich live execution activity is partial across workflows;
- authorised public targets are an approved product class, but the current passive Nuclei worker is still private-target-only until the public transport programme lands.

The UI must show those limitations truthfully.

---

## 4. Website target flow

Canonical browser flow:

```text
user enters target in conversation
→ normalize/classify target
→ resolve exact authorization
→ authorization-required card if missing
→ verify worker capability
→ immutable plan
→ required confirmation/approval
→ queue worker
→ live persisted activity
→ evidence/findings/verification
→ report/review state
```

Private/public target classes use the same workspace semantics.

A public URL is never permission.

If a public target is authorized but the current worker is private-only, show a blocker instead of a fake queued/running state.

---

## 5. Public-target browser behavior

Example authorization state:

```text
Authorization required
Target  https://example.com/
Class   Public
Port    443
Path    /

No active authorization covers this exact target.
[Review authorization]
```

Example current runtime blocker:

```text
✓ Authorization verified
! Public execution unavailable
  Configured worker supports private targets only.
```

After a public-capable worker is implemented, the same task proceeds through the exact plan and live execution contract.

The browser must never:

- create permission by toggling `allow_public`;
- bypass backend authorization;
- switch worker target-class capability;
- disable DNS/address containment;
- imply success before worker/backend state exists.

---

## 6. Long-running execution

Queued/running tasks must update one stable task group in the originating workspace.

Where persisted state exists, show:

- current stage;
- completed/pending stages;
- active worker/tool;
- safe current target/file/artifact;
- real receipts/evidence/candidate counts;
- latest activity;
- blocker/failure/recovery state;
- preserved work;
- supported action.

Do not force the user to navigate to another page just to know whether the task is alive.

A separate Activity/Inspector view may provide technical detail, but it must render the same persisted event stream.

---

## 7. Source Hunt browser flow

Canonical flow:

```text
repository request in conversation
→ resolve approved root
→ deterministic preflight
→ exact revision/snapshot/path boundary
→ source-processing approval + password re-authentication
→ queue worker
→ live snapshot/inventory/hunt/falsification/capability activity
→ remediation/result
→ return to original conversation
```

The specialist setup page may collect exact fields but must not become a giant competing dark dashboard.

Preflight should expose predictable file/byte blockers before full submission where possible.

See `docs/product/SOURCE_HUNT.md`.

---

## 8. APK/mobile browser flow

Website and APK work use the same workspace shell.

APK flow:

```text
attach APK
→ resumable upload
→ upload complete / integrity validation
→ immutable artifact/assessment identity
→ static tool execution where configured
→ live tool receipts
→ evidence/findings/verification
→ optional separately governed dynamic path
```

Uploading does not execute the APK.

100% upload does not mean analysis complete.

---

## 9. Contextual product surfaces

Use contextual in-chat/task objects before forcing navigation:

- authorization card;
- exact-plan confirmation card;
- independent approval card;
- task rows;
- tool chips;
- live activity disclosure;
- upload/integrity card;
- evidence/context card;
- finding card;
- remediation/recommendation card;
- report-ready card;
- recovery/failure/cancellation state.

Large/identity-bound detail may open a specialist route/drawer/sheet and must project its persisted result back to the same task.

---

## 10. Navigation

Everyday navigation prioritizes:

```text
+ New assessment
Chats / Tasks
current/recent tasks
Task history
Manage
Settings
user / role
```

Specialist capabilities such as Authorizations, Source Hunt, Findings, Review Queue, Campaigns, Releases, Datasets, Audit and Reports are progressively disclosed rather than all competing as equal permanent navigation items.

Historical dashboard-flow hierarchies are not current product authority.

---

## 11. Composer

Primary composer remains simple:

```text
Attach / add
Text input
Send
```

The composer remains usable during supported long-running work.

Provider/readiness/diagnostics belong behind progressive disclosure/settings.

Follow-up instructions may be visibly queued where backend supports it.

---

## 12. Secure browser defaults

Preserve:

- Django/server authentication;
- CSRF protection for state changes;
- secure/session cookie policy appropriate to deployment;
- no browser role escalation;
- same-origin/content-security controls;
- template escaping;
- no secret-bearing debug output;
- redaction before presentation/persistence;
- no-store/private caching on sensitive surfaces;
- backend permission checks regardless of navigation visibility.

A hidden/disabled control is not a security control.

---

## 13. Identity and authority

Each authenticated account maps to the current governance/product identity model.

Browser parameters/dropdowns cannot grant roles.

Authorization, independent approval, review and adjudication remain distinct decisions.

Where step-up/governance credentials are required, they authenticate the decision and must not be persisted or echoed.

---

## 14. Approval and cancellation

Plan confirmation/approval references an exact immutable plan/action identity.

Approval does not by itself bypass worker readiness/capability.

Cancel is shown only when the backend supports safe cancellation.

There is no generic Pause control unless an explicit backend pause/resume contract exists.

Reconnect restores persisted state and never silently restarts work.

---

## 15. Findings/evidence/reports

All contextual specialist data remains bound to the selected assessment/workspace.

Scanner/model output remains candidate evidence until deterministic/human authority says otherwise.

Zero findings must not erase evidence, activity or history.

Reports/export controls appear only when current persisted readiness supports them.

Demo/seeded records must not appear as if they belong to the selected user assessment.

---

## 16. AI/provider presentation

Global provider policy is owned by `docs/product/AI_ROUTING.md`.

Do not add a provider/model picker to ordinary chat merely because a reference UI has one.

Provider/model state is provenance/configuration, not security authority.

Safe activity may say:

```text
Reviewing persisted evidence…
Waiting for advisory provider…
```

Never render hidden chain-of-thought/private reasoning.

---

## 17. Current canonical routes

Routes are repository-backed implementation details and may evolve. Agents must inspect `vulnhunter/web/urls.py` before editing/navigation claims.

Important route families include the assessment workspace, authorizations, scans/assessment details, activity endpoints, findings, reviews/adjudications, campaigns/releases/datasets, approvals, reports, Source Hunt, mobile compatibility routes, active validation, roles/skills/settings and readiness/audit surfaces.

Do not duplicate a route/workflow merely because an older document lists a historical standalone page.

Use route names/current code as source of truth rather than copying a stale route list from documentation.

---

## 18. Local development

Use the current repository setup/startup documentation and command help for exact environment commands.

Never commit secret keys/provider tokens/passwords.

A local development preview does not make the service safe for public exposure.

Public **target assessment** and public **deployment/exposure of VulnHunter itself** are separate concerns.

---

## 19. Browser acceptance

Browser/UI completion requires applicable tests from:

- `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
- `docs/product/UI_QUALITY_ASSURANCE.md`;
- `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`;
- `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
- `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

Representative widths include approximately:

`360`, `390`, `412`, `768`, `1024`, `1280`, `1440` CSS pixels.

A public-target success screenshot is forbidden until the runtime can truly execute that path. Until then, verify the truthful blocker.

---

## 20. Final rule

The browser is acceptable only when **security authority, target class, worker capability, persisted task/activity state, evidence ownership and canonical design all agree**.
