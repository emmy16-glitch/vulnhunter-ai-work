# Known Failures and Limitations

**Status:** CURRENT UNRESOLVED LIMITATIONS  
**Rule:** resolved historical defects belong in commit/PR history or a clearly marked resolved-history document. This file should describe what can still mislead, block or weaken the current product.

---

## 1. Public-target product support is not yet implemented end-to-end

### Symptom

An operator can provide an authorised public hostname, but the current passive Nuclei worker remains private-target-only and cannot truthfully execute the public-host flow.

### Why it matters

The product contract now permits **authorised** public-target assessment, but documentation alone is not runtime support.

The current worker requires a private target and its safety checks must not be removed just to make a public hostname run.

### Required response

Implement `docs/product/PUBLIC_TARGET_ASSESSMENT.md`, including:

- exact public authorization;
- public/private target-class policy;
- connection-time DNS/address containment;
- protection against public-to-private/metadata rebinding;
- approved-address pinning or equivalent containment;
- original HTTP Host/TLS SNI/certificate identity preservation;
- redirect revalidation;
- public-capable worker policy;
- complete public-target acceptance.

### Forbidden workaround

Do not globally set `allow_public=True`, delete the private worker assertion, or let the scanner perform uncontrolled DNS resolution.

---

## 2. Long-running work does not yet have equally rich live activity across every workflow

### Symptom

Some flows can still produce a generic message that the backend is running work without showing enough of the actual persisted operational state in the originating conversation.

Website execution already records useful activity receipts, but Source Hunt and some other surfaces expose a shallower projection.

### Why it matters

The operator cannot confidently answer:

- what is running now;
- what completed;
- what comes next;
- which tool/worker is active;
- whether evidence/candidates are accumulating;
- whether the task is blocked/recovering/failed.

### Required response

Implement `docs/product/LIVE_EXECUTION_ACTIVITY.md` end-to-end:

```text
worker/service events
→ append-only persisted activity
→ selected-assessment projection
→ chat/task rows + tool receipts
→ reconnect/deduplication
→ browser acceptance against backend truth
```

### Forbidden workaround

Do not invent percentages, browser timers, fake tools or hidden chain-of-thought.

---

## 3. UI Contract V2 is authoritative but runtime migration is incomplete

### Symptom

Existing browser surfaces may still contain deprecated presentation such as:

- wide utility toolbar rows;
- old dashboard/KPI composition;
- giant dark Source Hunt/admin panels;
- clipped phone controls;
- tiny/low-contrast conversation text;
- competing navigation systems;
- incomplete in-workspace monitoring.

### Required response

Migrate affected surfaces to the locked UI contract and delete/refactor obsolete presentation rather than layering more CSS patches.

A documentation-only redesign is not runtime completion.

---

## 4. Source Hunt can fail predictable repository limits after the user submits setup

### Symptom

A repository may exceed the configured eligible-file or repository-byte limit, producing errors such as:

```text
repository exceeds the approved file-count limit
```

### Why it matters

The operator should see predictable deterministic limits before completing the full source-processing submission when possible.

### Required response

Add Source Hunt preflight showing:

- resolved root/revision;
- eligible Python file count and limit;
- eligible byte count and limit;
- excluded/generated directories;
- unsupported language note;
- permitted-path effect.

Do not silently increase safety limits merely to remove the error.

---

## 5. Source Hunt permitted-path UX can imply stronger narrowing than snapshot construction currently provides

### Symptom

The browser accepts `permitted_paths`, but snapshot construction can still occur from the supplied repository root before those paths become part of the remote-processing approval.

### Why it matters

A user may expect `vulnhunter/web` to avoid snapshotting unrelated eligible Python files while the runtime still inventories a larger root.

### Required response

Make the contract explicit and enforce it:

- preferably apply permitted-path selection during snapshot construction while preserving deterministic snapshot identity; or
- explicitly state that repository root is the snapshot boundary and permitted paths limit only remote processing.

Do not claim path narrowing solved file-count/byte-limit failure unless runtime proves it.

---

## 6. Current private Nuclei pilot is not a general scanner worker

The current pilot remains deliberately constrained:

- passive profile;
- reviewed templates;
- rate limit 1;
- concurrency 1;
- one target;
- private-target execution;
- no automatic updates;
- no public OAST;
- no cloud upload;
- no arbitrary command arguments.

These are safety properties, not bugs.

Public support should be implemented as an explicit target-class capability while preserving the bounded profile.

---

## 7. Physical Android/TalkBack/usability evidence remains manual

Automated responsive browser tests do not prove:

- real Android frame/performance behavior;
- TalkBack usability;
- bright-environment contrast;
- non-technical usability/polish;
- every OEM/browser keyboard/safe-area behavior.

Do not convert automated Chromium evidence into a physical-device claim.

---

## 8. Dynamic APK analysis remains environment-gated

Resumable upload and static analysis foundations exist, but dynamic execution depends on separately configured/disposable runtime infrastructure.

Uploading an APK is never proof that it executed.

MobSF/emulator/ADB/Frida availability must remain truthful and separately governed.

---

## 9. Real-world ML performance is not established

The repository contains substantial governed ML foundations, including release-bound training, group identity/partitioning, calibration/OOD/abstention foundations, evaluation and model registry lifecycle.

That does **not** establish a production-quality vulnerability classifier.

Required before strong performance claims include:

- diverse authorized application-family data;
- independent governed review;
- stable family-level development/calibration/external partitions;
- leakage/ablation evidence;
- calibration/OOD/coverage-risk evaluation;
- ranking/review-budget metrics;
- repeated grouped uncertainty;
- locked external evaluation;
- monitoring/shadow/rollback evidence.

Synthetic benchmark performance is not real-world performance.

---

## 10. Model/advisory providers remain non-authoritative and environment dependent

Provider reachability, quota, model availability, privacy/retention acceptance and exact capability profiles can fail independently of VulnHunter's deterministic workflow.

Provider failure must result in safe degradation/abstention rather than changing authorization, verification or review truth.

Do not use stale global wording that claims one provider is the only provider everywhere; use `docs/product/AI_ROUTING.md` and current provider registry truth.

---

## 11. Production deployment acceptance remains environment specific

A repository configuration or compose example is not production acceptance.

Production still requires explicit review for:

- TLS/proxy headers;
- DNS/networking;
- PostgreSQL/migrations;
- backup/restore;
- worker isolation;
- secret rotation;
- evidence retention;
- monitoring/incident response;
- rollback;
- public-target worker containment when enabled;
- independent security review.

---

## 12. Historical state/document contradictions can recur

### Failure mode

A completed implementation may remain listed as pending in the roadmap, while a known-failure file still says it is broken or a current-state file says it is complete under a narrower scope.

### Required response

When a capability changes state, reconcile together:

- `docs/intelligence/CURRENT_STATE.md`;
- `docs/intelligence/ROADMAP.md`;
- this file.

Use qualifiers such as:

```text
CONTRACT APPROVED
RUNTIME PARTIAL
AUTOMATED ACCEPTANCE COMPLETE
MANUAL EVIDENCE PENDING
IMPLEMENTED AND VERIFIED
```

rather than an ambiguous single word `complete`.

---

## 13. Failure-reporting rule

New unresolved product/runtime defects belong here only when they remain true on current `main`.

When resolved:

- remove them from this active list or move them to an explicitly historical record;
- preserve the motivating regression test;
- update current state/roadmap when status changes;
- do not keep stale wording that future agents could treat as current architecture.
