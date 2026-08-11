# VulnHunter Product Definition

**Status:** CURRENT PRODUCT DEFINITION  
**Implementation status:** `docs/intelligence/CURRENT_STATE.md`

## Problem

Security-assessment tools often make one or more dangerous product mistakes:

- treat network reachability as permission;
- hide target scope inside scanner configuration;
- allow DNS/redirect drift outside the approved target;
- collect excessive sensitive data;
- present scanner matches as confirmed vulnerabilities;
- hide long-running execution behind a spinner or opaque background process;
- make mobile/security workflows feel like disconnected admin modules;
- let model output appear more authoritative than the underlying evidence;
- inflate ML performance through leakage, duplicates or non-representative benchmarks.

## Product

VulnHunter AI is an **authorised security-assessment and decision-support platform** that:

1. resolves exact target/repository/artifact identity before governed work;
2. supports explicitly authorised private and public website targets;
3. separates technical target validity from legal/operational permission;
4. binds execution to time-limited authorization, exact scope and immutable plans;
5. uses bounded, policy-controlled security tools;
6. persists meaningful live task/activity state while work runs;
7. creates structured, redacted evidence and candidate findings;
8. applies deterministic verification before stronger security claims;
9. preserves human authority for governed review/adjudication/release decisions;
10. supports Python-first Source Hunt under exact source-processing approval;
11. supports APK/mobile analysis under immutable artifact and worker boundaries;
12. builds provenance-bound, leakage-resistant ML/retrieval foundations;
13. exposes all of this through one conversation/task-first browser workspace.

## Public-target rule

Public Internet targets are supported **only when explicitly authorised**.

A public hostname is not permission. VulnHunter must distinguish:

```text
publicly reachable
≠ authorised to test
```

Valid public authorization may come from an owner-controlled deployment policy, client/third-party written approval, contract/ticket/SOW, or an exact bug-bounty/VDP scope reference.

The effective VulnHunter scope must be equal to or narrower than the authorization.

Public execution must also preserve the transport containment in `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

The current runtime status is maintained separately; the current private-only worker must not be presented as public-capable until the public transport path is implemented and accepted.

## Human / automation boundary

Automation may, when the corresponding governed capability exists:

- normalize/classify targets;
- validate exact authorization records;
- build immutable plans;
- execute bounded scanner jobs through approved workers;
- collect and normalize redacted evidence;
- map repository attack surfaces;
- propose/falsify source-code hypotheses;
- prioritize review;
- detect duplicates/conflicts;
- build features and governed datasets;
- run advisory models;
- produce remediation suggestions;
- persist task/activity/tool receipts.

Human or separately governed authority remains required for decisions such as:

- granting testing permission where policy requires a human approver;
- confirming exact plans when required;
- independent approval for higher-risk operations;
- final governed review/adjudication;
- merge/release/publication decisions;
- claims about real-world model performance.

An AI model cannot grant itself any of those authorities.

## Evidence rule

Scanner observations and model hypotheses are candidates/evidence, not automatic proof.

The product should preserve:

```text
authorization
→ plan
→ worker/tool receipt
→ evidence
→ candidate
→ deterministic verification / abstention
→ human review where required
→ report/release
```

Evidence remains assessment-scoped and redacted.

## Live execution rule

When the product says a task is queued or running, the user should be able to see truthful persisted operational state in the same workspace.

The primary UI should answer:

- what is happening now;
- what completed;
- what is next;
- which real worker/tool is active when known;
- what receipts/evidence/candidates exist;
- what failed/recovered;
- what was preserved.

The product must not rely on a generic “backend is running it; check another page” experience when richer backend state exists.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

## Product experience

VulnHunter is not a dashboard with a chatbot attached.

The canonical experience is:

```text
conversation / target / attachment
→ exact governed interpretation
→ authorization / plan / approval when required
→ persisted execution
→ live task rows + tool receipts
→ evidence / findings / remediation / report
→ contextual detail only when needed
```

The browser design is owned by `docs/design/VULNHUNTER_UI_CONTRACT.md`.

## Non-goals

VulnHunter is not intended to:

- scan arbitrary or unauthorised public systems;
- perform denial-of-service or destructive testing as a default capability;
- brute-force credentials without a separate explicit contract;
- bypass access controls merely to continue an assessment;
- convert model confidence into vulnerability proof;
- automatically publish unreviewed vulnerability claims;
- let browser state override backend authorization/worker policy;
- expose hidden chain-of-thought/private model reasoning;
- use synthetic benchmark scores as real-world marketing evidence;
- claim production readiness from repository configuration alone.

## Success definition

VulnHunter succeeds when security truth, authorization, worker execution, persisted evidence, live user experience, human governance and documentation all describe the **same exact assessment state**.
