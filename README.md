# VulnHunter

VulnHunter is an **authorised security-assessment and verification platform** built around deterministic scope/authorization controls, bounded security tools, persisted evidence, human authority and a conversation/task-first workspace.

VulnHunter supports private/laboratory targets today and defines **authorised public-target assessment as a first-class product requirement**. Public Internet access is never equivalent to permission: public execution must remain bound to an exact authorization record, target, profile, transport policy and worker capability.

## Product principles

- authorization and scope are backend decisions, never chat/model decisions;
- a URL alone never grants testing permission;
- public and private targets are both explicit target classes;
- public-target execution must prevent DNS/redirect pivots into private, loopback, link-local or metadata networks;
- worker capability is explicit and cannot be toggled by browser input;
- long-running work must expose persisted live activity in the original workspace;
- scanner/model output is evidence or a candidate, not automatic vulnerability proof;
- deterministic verification and human review remain authoritative;
- AI providers are advisory and non-authoritative;
- hidden chain-of-thought is never rendered.

## Current runtime state

The repository currently provides, among other capabilities:

- authenticated conversation/task workspace for website, APK and source-repository work;
- exact target/protocol/port/address/profile authorization records;
- immutable Nuclei plans with digest-bound human decision;
- signed manager-to-worker spool with expiry/replay protection;
- a reviewed **private-target passive Nuclei worker path**;
- bounded timeout/cancellation/redaction/recovery controls;
- evidence normalization and deterministic verification;
- finding/review/adjudication/release governance;
- Python-first Source Hunt with exact repository snapshot and source-processing approval;
- resumable APK upload and bounded static-analysis tooling;
- optional advisory provider routing under `docs/product/AI_ROUTING.md`;
- responsive browser/UI foundations and canonical design governance.

### Important current limitation

**The current passive Nuclei worker is still private-target-only.** The product contract for safe authorised public-target execution is now defined in `docs/product/PUBLIC_TARGET_ASSESSMENT.md`, but public runtime execution must not be claimed complete until the worker implements and verifies the required public-host transport containment, including connection-time address control and original Host/TLS identity preservation.

Do not weaken the private worker simply to make a public URL run.

## Canonical website flow

Target-class-neutral product flow:

```text
URL supplied
→ normalize and classify target
→ resolve exact authorization
→ verify owner/approver/evidence/scope/expiry
→ verify worker capability for target class
→ prepare immutable bounded plan
→ required confirmation / independent approval
→ signed worker job
→ persisted live execution activity
→ evidence
→ candidate findings
→ deterministic verification
→ optional separately governed active validation
→ human review
→ report / governed release
```

For **private** targets, the current passive worker path may be used when configured and authorized.

For **public** targets, use the contract in `docs/product/PUBLIC_TARGET_ASSESSMENT.md`. Public runtime support remains incomplete until the public-capable worker boundary is implemented and accepted.

## Canonical Source Hunt flow

```text
repository intent
→ operator-approved repository root
→ preflight eligible files/bytes
→ exact revision and content snapshot
→ exact repository/revision/snapshot/path-bound processing approval
→ non-secret queued worker job
→ deterministic Python inventory and attack-surface mapping
→ model-assisted reconnaissance/hypothesis generation
→ independent falsification
→ capability filtering
→ evidence-bound remediation proposal
→ deterministic verification / developer-led fix flow
→ human review
→ conversation projection
```

Source Hunt must not become a black box after queueing. See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

## Live execution

Queued/running work must project meaningful persisted activity into the same conversation/task workspace.

The user should be able to see, when real backend state exists:

- current stage;
- completed/next stages;
- active worker/tool;
- safe current target/file/artifact;
- receipts/evidence/candidate counts;
- failures/recovery/preserved work;
- supported next action.

A generic “backend is running it; check another page” response is not sufficient.

The binding contract is `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

## Authorization boundary

Authorization records are explicit, time-limited and integrity-bound.

Supported authorization bases may include:

- owner-controlled target self-attestation where product policy permits it;
- client/third-party written testing approval;
- contract/ticket/statement-of-work authorization;
- bug-bounty or VDP scope references.

Public targets must never be authorized merely because they are public. Client/third-party/bounty scope must remain equal to or narrower than the external authorization.

## Public-target transport boundary

Public execution must preserve all of the following before it can be classified as implemented:

- exact hostname/scheme/port/path authorization;
- public/private address classification;
- connection-time DNS/address revalidation;
- approved-address pinning or equivalent containment;
- original hostname for HTTP Host, TLS SNI and certificate validation;
- every redirect independently revalidated;
- no mixed public/private resolution;
- no pivot to localhost/loopback/link-local/metadata/private space;
- explicit public capability in worker policy;
- bounded passive profile/rate/concurrency/templates.

See `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

## Browser product

The Assessment Workspace is the product centre of gravity.

Canonical structure:

```text
compact task/chat sidebar or mobile drawer
→ conversation + persisted task timeline
→ persistent composer
→ optional contextual evidence/finding/activity detail
```

The UI source of truth is:

1. `AGENTS.md`;
2. `vulnhunter/web/AGENTS.md`;
3. `docs/design/VULNHUNTER_UI_CONTRACT.md`;
4. `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`;
5. `docs/design/references/manifest.json`;
6. `docs/design/DEPRECATIONS.md`;
7. `docs/product/CHAT_FIRST_WORKSPACE.md`;
8. `docs/product/LIVE_EXECUTION_ACTIVITY.md`;
9. `docs/product/UI_ACCEPTANCE_CRITERIA.md`;
10. `docs/product/RESPONSIVE_AND_ACCESSIBILITY.md`.

MonkeyCode supplies task/workspace interaction structure only. Beautiful UI supplies AI-native component/microinteraction references only. VulnHunter owns functionality, terminology, security authority and the warm cream/off-white dotted + dusty-pink + compact-dark-sidebar visual system.

## Source Hunt

Source Hunt is Python-first and deliberately bounded.

It requires:

- approved repository root;
- exact revision/snapshot;
- file/byte limits;
- exact permitted paths;
- password re-authentication where required;
- source-processing approval;
- provider/data-retention attestations;
- deterministic file/hash/line verification.

The browser should preflight predictable size/file-limit failures and project the running hunt into the originating workspace.

See `docs/product/SOURCE_HUNT.md`.

## Mobile analysis

APK upload is resumable and integrity-validated. Uploading does not execute the APK.

Static analysis may run fixed bounded read-only tools when configured. Dynamic execution remains a separate, explicitly governed environment capability.

Partial tool failure must preserve existing evidence and remain truthful.

## AI routing

Models are optional advisory services.

Provider inventory and routing policy are defined by `docs/product/AI_ROUTING.md` and current code. Do not reintroduce stale global wording that claims Groq is the only provider everywhere when other approved advisory provider families exist.

Source Hunt may remain Groq-specific under its own contract.

Models cannot grant authorization, expand scope, execute scans, verify findings, set final severity, change human review state, merge fixes or publish results.

## Current-state truth

Implementation status is owned by:

- `docs/intelligence/CURRENT_STATE.md`;
- `docs/intelligence/ROADMAP.md`;
- `docs/intelligence/KNOWN_FAILURES.md`.

Those documents must distinguish product contract from runtime implementation and may not claim public-target or live-activity completion before the runtime and acceptance evidence exist.

## Verification expectations

Before claiming a substantial change complete, follow `AGENTS.md` and run the required repository gates plus workflow-specific browser/phone/worker tests.

Public-target work requires the full containment acceptance matrix in `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

Live-execution work requires persisted-event/reconnect/deduplication acceptance in `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

A green test that does not exercise the relevant trust boundary is not proof of that boundary.

## Production preparation

Production deployment still requires explicit environment acceptance for at least:

- TLS/proxy headers;
- PostgreSQL/data migration;
- backups/restore;
- worker isolation;
- evidence retention;
- provider secret management;
- monitoring/incident response;
- rollback;
- public-target transport safety when enabled;
- independent security review.

Deployment examples are examples, not proof of production readiness.
