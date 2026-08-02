# Known Failures and Limitations

## 1. Initial baseline model under-detected confirmed findings

The first controlled benchmark baseline produced high precision but very low
recall. The pipeline worked, but the model predicted the confirmed class too
rarely to be practically useful.

Response:

- preserve the weak artifact as an honest baseline;
- add privacy-safe features;
- compare estimators and thresholds using training scans only;
- inspect locked-holdout errors without tuning against them.

## 2. Synthetic benchmark performance is not real-world performance

The controlled benchmark uses known scenarios and deliberately structured
signals. Strong scores validate experiment plumbing and reproducibility, not
generalisation to real applications.

## 3. Historical DNS time-of-check/time-of-use gap — resolved

Earlier releases revalidated DNS before a request but allowed the HTTP stack to
resolve the hostname again while opening the socket. The transport now resolves
at connection time, connects directly to an approved IP, verifies the peer,
preserves the original hostname for HTTP/TLS, and disables keep-alive reuse
between independently pinned requests.

## 4. Passive observations do not prove exploitability

Missing headers, debug indicators, directory-style pages, and technology
disclosures require context. VulnHunter intentionally keeps deterministic
verification and human review authoritative.

## 5. Real application diversity remains limited

The control plane can govern diverse campaigns, but the project has not yet
produced a sufficiently broad real dataset spanning frameworks, deployment
stacks, authentication states, proxies, custom errors, and application
families.

## 6. Historical and benchmark single-review labels remain

New governed real observations require two authenticated assigned reviewers
and, when needed, an independent adjudicator. Historical and controlled
benchmark labels remain single-review records for reproducibility and cannot
qualify for a governed campaign release without matching attestations.

## 7. Local artifact lifecycle is not fully operationalised

Databases, campaign releases, scanner evidence, model artifacts, and experiment
evidence are local operational files. Formal backup, retention, migration,
external signing, restore, and release procedures remain future work.

## 8. Web UI is implemented but not every backend capability has a browser write contract

The authenticated Django console now covers dashboard, authorizations,
assessments, approvals, findings, review, adjudication, campaigns, releases,
datasets, intelligence status, reports, audit, tools, roles, skills, settings,
mobile static analysis, and controlled active validation.

The interface deliberately remains read-only where the backend does not expose
a safe write contract. In particular:

- release assessment does not provide a publication button;
- dataset quality does not start export or training;
- intelligence pages do not start inference, training, graph refresh, or model
  promotion;
- opening a scanner page does not activate the worker;
- dynamic Android execution remains environment-gated.

This is intentional fail-closed behaviour, not a decorative missing control.

## 9. Finding detail is bounded by the current product read model

The finding workspace can display only fields and artifacts exposed by the
authenticated product service. Evidence that is retained internally but not in
the read model remains unavailable to the browser until a reviewed, redacted
contract is added.

## 10. Orchestration and research isolation are not kernel sandboxes

Fixed shell-free verifiers, worktrees, protected hashes, role separation, and
deterministic rejection make evaluator gaming visible, but repository code
still runs under the local account. Stronger isolation requires a dedicated
low-privilege user, container, VM, or operating-system sandbox.

## 11. Outer-loop guidance is intentionally non-executable

The meta-search layer proposes strategy changes rather than injecting Python.
This limits autonomy but prevents the outer loop from mutating its evaluator or
security boundaries.

## 12. Runtime permissions do not replace operating-system controls

The unattended control plane enforces tools, paths, commands, network,
connectors, secrets, and destructive permissions in application code. It cannot
protect the host from code that already executes with equivalent
operating-system privilege.

## 13. Local authentication is not external identity proof

Reviewer secrets use scrypt and actions are identity-bound, but the local
registry does not provide SSO, MFA, hardware-backed keys, independent proof
that separate accounts belong to separate people, or protection from a
compromised administrator account.

## 14. Campaign integrity is hash-based, not digitally signed

Campaign records, assignments, attestations, releases, and events detect local
database tampering through deterministic hashes and a hash chain. They are not
yet signed by an independently protected external key, so portable authenticity
and non-repudiation are not established.

## 15. Historical scan-completion correlation gap — resolved

Earlier governed scan linking matched scan completion primarily by scan ID and
event order after a matching start event. The authorization completion event
now binds the authorization ID, normalized scan database, scan ID, normalized
target URL, and persisted scan snapshot hash. Campaign linking fails closed
when that tuple is missing, malformed, mismatched, or ordered before the
matching start event.

## 16. Real-world model evidence is still absent

The governed collection workflow is implemented, but meaningful performance
claims require actual collection across diverse authorized applications,
independent review, application-group-isolated development and holdout sets,
and an untouched external evaluation.

## 17. Optional advisory analysis is non-authoritative and environment-dependent

The platform remains usable without an advisory provider. Provider reachability,
quota, approved-model availability, privacy acceptance, and operator activation
remain external dependencies. Failure or malformed output must result in
abstention and cannot change authorization, verification, review, adjudication,
or release state.

## 18. Production deployment acceptance remains outstanding

The repository contains secure defaults, private secret-file support, health and
readiness checks, and deployment examples. A real production environment still
requires independent acceptance for TLS, proxy headers, database backups,
worker isolation, evidence retention, logging, key rotation, monitoring,
rollback, and incident response.

## 19. Assessment state can contradict across browser surfaces

A direct phone and desktop-site product review on 2026-08-02 exposed a case in
which an APK could be uploaded, validated, shown in the graph and queued for a
static analysis while the assessment inspector still reported `No active
assessment`, assessment history reported zero runs, findings reported zero, and
a later chat message reported that the worker failed.

This is not merely a visual defect. It means the user cannot identify which
surface is authoritative or whether the assessment was created and preserved.

Required response:

- establish one stable assessment identity immediately after artifact validation;
- bind chat, activity, inspector, history, findings, evidence, graph and reports
  to the same assessment projection;
- add invariant tests that prevent artifact-owned content from appearing under
  `No active assessment`;
- preserve partial evidence and terminal state across reconnects;
- implement the dependency-ordered programme in
  `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md`.

## 20. The conversation can repeat already satisfied prerequisites

The assistant can ask the user to upload an APK or explain the future upload
workflow while the selected APK is already uploading or has completed.

This occurs when model or fallback prose is generated without first resolving
the authoritative workspace and assessment state.

Required response:

- compose operational responses from the persisted workspace projection;
- verify that a required input is genuinely absent before requesting it;
- separate model explanation from backend state and allowed actions;
- add tests for in-progress, completed, replacement and resumed uploads.

## 21. Worker failures are too generic to support recovery

The current user-facing failure may state only that a governed worker did not
complete. It does not consistently identify the failed stage, tool, attempt,
reason category, preserved evidence, retry boundary, or operator action.

Required response:

- introduce typed product error categories;
- expose a redacted failure reference;
- show completed and preserved work;
- offer retry only when the backend supports a safe idempotent retry;
- retain prior failure receipts after a new attempt.

## 22. Long-running work lacks one coherent live task experience

Upload banners, cards, toasts, chat replies, inspector state and global pages can
all describe the same operation differently. The user does not receive one
credible timeline of completed, active, waiting, blocked and terminal stages.

Required response:

- project persisted activity into one updating task card;
- use understandable stages by default;
- expose technical node and worker details under an expandable activity view;
- show progress percentages only when measured from bytes or declared weighted
  stages;
- deduplicate activity events and visual indicators.

## 23. Mobile layout can compress the desktop inspector beside chat

Some phone screenshots show a deliberate mobile layout, while others show the
desktop conversation and inspector compressed into a narrow viewport. This
produces tiny text, clipped action rows, unreadable tables, horizontal overflow,
and excessive competition between the composer, bottom navigation and keyboard.

Required response:

- use one responsive shell;
- make the inspector a full-screen sheet, route or bottom sheet on phone;
- transform tables into cards;
- prevent horizontal overflow;
- verify keyboard, Android Back, safe-area, long text and desktop-site simulation;
- preserve chat scroll position when opening and closing specialist views.

## 24. Navigation contains competing duplicates

Findings and Graph are available in more than one primary navigation system,
while Analysis, Evidence, Reports and History appear both contextually and as
global destinations. The user cannot tell whether these views share state.

Required response:

- assign one primary location to each concept;
- use Chat, Activity, Findings and More as the mobile primary set;
- make desktop inspector tabs assessment-scoped;
- keep global Findings and Reports as cross-assessment indexes only;
- show Graph only when meaningful graph data exists.

## 25. The composer exposes too much infrastructure

The primary message area exposes attachment, reasoning level, provider selection,
provider status, prompt history, explanatory text, character count and bottom
navigation simultaneously. The keyboard can reduce the usable conversation area
further.

Required response:

- retain attachment, text, mode and send as the primary controls;
- move provider and advanced configuration behind progressive disclosure;
- show character count near the limit only;
- show worker state in the task card and provider readiness in settings;
- add keyboard-open responsive acceptance.

## 26. Governance terminology dominates normal task meaning

Correct internal phrases such as canonical worker state, persisted receipts,
exact snapshot, gated worker and release gate appear before ordinary user
language. This makes the product feel like an audit console rather than an AI
assistant, even when the underlying control is working correctly.

Required response:

- use ordinary task language in the primary layer;
- retain exact policy, digest, receipt and worker terminology under details;
- never hide a decision the user must make;
- standardise terminology across chat, activity, findings, evidence and report.

## 27. Empty and report pages are disconnected from the selected task

Zero-data pages use large repeated metric cards, while Reports may show a seeded
pilot record unrelated to the selected user assessment. A user can therefore
see an apparently valid report record while their active APK operation has no
clear report state.

Required response:

- use compact contextual empty states;
- filter contextual findings, evidence and reports to the selected assessment;
- display exact unmet requirements for each report format;
- label and separate seeded/demo records from user work;
- return all specialist views to their owning conversation and assessment.
