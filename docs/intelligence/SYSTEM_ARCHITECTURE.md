# VulnHunter System Architecture

**Status:** CURRENT SYSTEM-LEVEL REFERENCE  
**Cross-system blueprint:** `docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md`  
**Implementation status:** `docs/intelligence/CURRENT_STATE.md`

## 1. Core architecture

```text
User / API / browser request
          │
          ▼
Authentication + workspace ownership
          │
          ▼
Typed intent / exact object resolution
          │
          ▼
Authorization + scope + role + policy
          │
          ▼
Immutable plan / action identity
          │
          ▼
Required confirmation / approval / re-authentication
          │
          ▼
Persisted assessment/task graph
          │
          ├──────── Website scanner worker
          ├──────── Source Hunt worker
          ├──────── APK/static worker
          └──────── other governed workers/services
          │
          ▼
Append-only activity + tool receipts + evidence
          │
          ▼
Deterministic normalization / verification
          │
          ▼
Human review / adjudication where required
          │
          ▼
Remediation / retest / report / governed release
```

The browser and AI model never own security authority.

---

## 2. Website target pipeline

Target-class-neutral flow:

```text
Raw URL
→ normalize/parse
→ classify private/public address state
→ load/validate exact authorization
→ bind exact scheme/host/port/path/address policy
→ verify current worker target-class capability
→ construct immutable plan
→ exact human decision
→ signed worker job
→ connection-time contained execution
→ persisted activity/evidence
→ deterministic verification
```

### Current runtime

The current passive Nuclei worker is private-target-only.

### Target architecture

Authorised public targets are supported by the product contract and require the public-capable transport/worker boundary in `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

Do not confuse target-validation support with end-to-end worker capability.

---

## 3. Scope / target objects

Trusted network values are represented with validated types rather than raw URL strings.

An exact target identity includes:

- scheme;
- hostname;
- port;
- path boundary;
- target class;
- approved resolved-address set/policy.

Derived destinations/redirects are revalidated.

A public target may never rebind/redirect into private, loopback, link-local or metadata space.

---

## 4. Connection-bound HTTP transport

VulnHunter's bounded direct HTTP transport uses the following conceptual flow:

```text
ScopedUrl
→ connection-time resolution
→ canonical current address set
→ containment check against approved target policy
→ deterministic approved-address attempt
→ TCP peer verification
→ HTTP request using original hostname
→ TLS SNI/certificate validation using original hostname
→ connection/evidence audit state
```

Important properties:

- original hostname is preserved;
- address pinning does not silently replace hostname semantics;
- automatic redirects are disabled or each hop is revalidated;
- environment proxy inheritance is disabled unless a separate proxy design is reviewed;
- requests/body/timeouts/rate/cancellation are bounded;
- redaction occurs before persistence/display.

This transport pattern is particularly important for safe future public-host execution.

---

## 5. Scanner manager / worker architecture

```text
Django / manager
→ exact authorization
→ immutable plan
→ exact approval/confirmation
→ signed expiring job
→ worker
    ├─ validate signature/expiry
    ├─ validate authorization/plan/approval
    ├─ validate target class and worker capability
    ├─ validate template manifest/compatibility
    ├─ validate rate/concurrency/output/timeout
    ├─ execute fixed bounded adapter
    ├─ persist activity/receipts
    └─ persist bounded evidence/result
```

The manager owns policy/plan orchestration. The worker owns scanner process execution.

A worker cannot expand scope, approve its own job, accept raw user command arguments, persist raw secrets or confirm a finding.

The current private worker remains valid while a distinct public-capable path is designed.

---

## 6. Nuclei integration

Nuclei is an external evidence producer behind a governed adapter.

The integration uses:

- reviewed/pinned compatibility information;
- reviewed template manifest/digests;
- fixed command construction;
- passive profile constraints;
- exact target/plan/job identity;
- bounded process output;
- activity/evidence persistence;
- downstream deterministic verification.

See `docs/product/NUCLEI_INTEGRATION.md`.

---

## 7. Persisted task / activity architecture

Long-running operations use one persisted task identity and append-only activity stream.

Conceptually:

```text
assessment/task created
→ queued
→ worker claimed
→ stage/tool events
→ receipts/evidence/candidates
→ failure/recovery/cancellation/completion
```

The selected-assessment projection feeds:

- conversation task rows;
- Activity detail;
- inspector;
- history;
- evidence/findings;
- report readiness.

Reconnect reads persisted state and deduplicates event IDs/sequences. It does not restart work.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 8. Source Hunt architecture

```text
Repository intent
→ approved root
→ preflight eligible files/bytes/path boundary
→ exact revision + snapshot hash
→ exact source-processing approval
→ queued Source Hunt worker
→ deterministic Python inventory/attack-surface map
→ provider-assisted hypothesis
→ independent falsification
→ capability filtering
→ remediation/test proposal
→ deterministic/human-controlled fix workflow
```

The model never establishes source truth. File path/hash/line validation is deterministic.

Source Hunt activity is projected into the same assessment workspace.

---

## 9. APK/mobile architecture

```text
APK attachment
→ resumable upload
→ integrity verification
→ immutable artifact identity
→ static tool plan
→ tool receipts/activity
→ evidence/verification
→ optional separately governed dynamic runtime
```

Upload does not imply execution.

Static/dynamic worker capability remains explicit.

---

## 10. Evidence / observation architecture

```text
worker/tool output
→ bounded parser/normalizer
→ redacted evidence record
→ candidate observation/finding
→ deterministic verification / abstention
→ review/adjudication where required
```

Tool output is not automatically vulnerability proof.

Evidence remains linked to exact assessment/authorization/plan/tool identities.

---

## 11. Human review / governance architecture

Governed review preserves:

- authenticated identities;
- assignment and conflict rules;
- two-reviewer/independent adjudication where required;
- immutable decision attestations;
- campaign/release provenance;
- separation between scanner/model evidence and human authority.

Campaigns do not create target authorization; they consume/narrow already authorized evidence.

---

## 12. ML / intelligence architecture

```text
governed reviewed releases
→ immutable production training packages
→ application-family partitions
→ governed feature extraction
→ development evaluation / calibration / OOD / abstention
→ signed model registry/lifecycle
→ optional advisory inference
→ human-reviewed outcomes
```

Models remain advisory and cannot change authorization, verification or human labels.

Current Programme 3 status is in `CURRENT_STATE.md`.

---

## 13. Provider routing architecture

Provider routing is deterministic-first and data-class-aware.

Optional provider families currently include Groq and Hugging Face where configured.

Provider calls are bounded by:

- approved provider/model profile;
- task/data class;
- privacy/redaction;
- input/output/time/concurrency limits;
- structured output validation;
- safe abstention/degraded state.

Source Hunt can remain Groq-specific even though the global provider layer is provider-neutral.

---

## 14. Browser/product architecture

The browser is a server-backed projection of persisted state.

```text
compact task/chat navigation
→ conversation + task timeline + live activity
→ persistent composer
→ contextual detail only when opened
```

The browser may own temporary UI state only; it does not own assessment lifecycle.

See the locked UI/design contracts.

---

## 15. Engineering orchestration boundary

```text
bounded change specification
→ isolated/bounded builder work
→ deterministic verifier evidence
→ security-policy evidence
→ independent review
→ human promotion/approval where required
```

Repository-change orchestration cannot authorize a target, verify a vulnerability or alter finding/review authority.

---

## 16. Transactional research plane

```text
clean Git baseline
→ protected evaluator/resources
→ isolated candidate worktree
→ one hypothesis/candidate
→ trusted baseline/candidate evaluation
→ fixed safety/regression gates
→ accept/reject/inconclusive
→ human-controlled promotion
```

Candidate improvement never compensates for security/evaluator/data-integrity failure.

---

## 17. Unattended operations

Unattended routines use immutable expiring permission manifests plus runtime tool/path/network/connector/secret/destructive gates.

Prompts/model output/source documents do not create unattended permission.

Critical security/authorization/evaluator blockers halt the affected workflow.

---

## 18. Architectural principles

- Validate exact target identity before use.
- Validate explicit authorization before executable network activity.
- Distinguish private/public target class from permission.
- Distinguish authorization from worker capability.
- Revalidate derived/redirected destinations.
- Bind network connections to approved address policy while preserving Host/TLS identity.
- Keep scanner processes outside the Django web request/process boundary.
- Persist meaningful live task activity.
- Redact before persistence/provider/display boundaries.
- Keep scanner/model evidence separate from human conclusions.
- Preserve immutable review/evidence/model provenance.
- Keep related application/scan groups isolated in ML partitions.
- Prefer explicit blocked/unavailable/abstain states to silent fallback.
- Use current provider/worker capability profiles rather than historical assumptions.
- Keep browser state non-authoritative.

---

## 19. Runtime dependencies

Dependency lists change over time. Use `pyproject.toml`/lock files/current environment as the exact dependency source of truth.

Architecture currently relies on focused components such as HTTPX/httpcore, Pydantic, Typer, persistence libraries, HTML parsing, Django/web infrastructure, pytest/Ruff and tool adapters according to current code.

Do not copy a historical dependency list into implementation without checking current configuration.

---

## 20. Status rule

This file describes architecture. It does not prove runtime availability.

Use `docs/intelligence/CURRENT_STATE.md` for exact implemented/partial/unavailable classification and `docs/intelligence/ROADMAP.md` for remaining dependency order.
