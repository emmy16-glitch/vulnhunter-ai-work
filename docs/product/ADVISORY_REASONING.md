# Bounded Advisory Reasoning

**Status:** SPECIALIST / LEGACY GROQ-PIPELINE DOCUMENTATION  
**Provider authority:** `docs/product/AI_ROUTING.md`  
**Current implementation status:** `docs/intelligence/CURRENT_STATE.md`

This document describes the bounded multi-stage advisory reasoning pattern that exists in the repository. It is **not** the global provider inventory and must not be used to reintroduce a “Groq is the only provider everywhere” product assumption.

## 1. Authority boundary

Advisory reasoning is never authoritative for:

- target authorization;
- target class or scope;
- worker execution;
- evidence truth;
- vulnerability verification;
- final severity;
- human review/adjudication;
- merge/release/publication.

Models propose/explain. Deterministic VulnHunter services verify/enforce/persist authority.

## 2. Applicable targets

Advisory reasoning may operate on a completed/verified assessment envelope from an authorised **private or public** target when provider/data-class policy permits it.

Public-target support does not grant a provider raw target authority or bypass `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

The provider should receive bounded/redacted evidence rather than raw credentials, authorization evidence or unrestricted target data.

## 3. Legacy Groq multi-stage flow

Where the current Groq-backed advisory pipeline is configured, the conceptual flow is:

```text
authorised assessment
→ persisted scanner evidence
→ deterministic verification/proof capsule
→ sanitized advisory queue item
→ bounded analyst stage
→ bounded critic/falsification stage
→ bounded synthesis stage
→ stored untrusted advisory result
→ human review
```

Exact models, provider capabilities, fallbacks and runtime readiness must come from current configuration/provider profiles, not from hard-coded historical examples in this document.

Use `AI_ROUTING.md` and current runtime readiness as source of truth for provider/model availability.

## 4. Supplied context

Remote advisory processing should receive only the data class and fields allowed by current provider policy, such as:

- redacted finding metadata;
- deterministic verification verdict/strategy;
- reviewed scanner/tool identity;
- hashed or minimized target identity where required;
- safe structured observations;
- evidence references/digests;
- prior structured advisory-stage output.

Do not send remotely unless explicitly allowed:

- passwords;
- API keys/tokens;
- cookies/session values;
- private keys;
- raw authorization evidence containing secrets;
- unrestricted raw response bodies;
- unrestricted customer/source data;
- data disallowed by deployment/provider policy.

## 5. Evidence-reference rule

Every model-supplied evidence reference must correspond to evidence that VulnHunter supplied to the model/request context.

Invented/stale/foreign references are rejected or cause abstention according to the current contract.

Model prose is not evidence by itself.

## 6. Stage responsibilities

### Analyst / hypothesis stage

May identify possible explanations, assumptions, missing information and bounded security hypotheses.

### Critic / falsification stage

Challenges false positives, missing preconditions, contradictory evidence, framework protections and overconfidence.

### Synthesis stage

Produces a conservative advisory summary/remediation suggestion from validated supplied context.

The application stores structured user-facing conclusions and provenance, **not hidden chain-of-thought**.

## 7. Failure behavior

Provider/advisory failure must not corrupt assessment truth.

Examples:

- provider disabled/unconfigured → deterministic assessment remains usable;
- key missing → safe provider-unavailable state;
- timeout/rate limit → bounded retry or abstention according to current policy;
- malformed schema → reject response;
- invented evidence → reject response;
- provider/model unavailable → use only a configured approved fallback, otherwise abstain;
- activity-display failure → persisted assessment/evidence remains authoritative.

No advisory failure may silently change a scanner observation, verification result or human review state.

## 8. Live activity

If advisory reasoning is part of a running task, user-facing activity may expose safe operational stages such as:

```text
Preparing redacted advisory context…
Advisory analysis running…
Reviewing advisory result against persisted evidence…
Advisory result stored / abstained…
```

Do not expose provider chain-of-thought or private reasoning tokens.

The task/activity rules are defined by `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

## 9. Trust statement

Advisory results remain conceptually:

```text
advisory_only = true
trusted = false
```

or the equivalent current schema.

Human/deterministic authority remains unchanged.

## 10. Historical model/config examples

Older commits may contain concrete Groq model IDs and Codespaces defaults used for a specific deployment period. Treat those values as historical/runtime examples, not permanent product contract.

Current provider/model truth comes from:

- `docs/product/AI_ROUTING.md`;
- `docs/product/LLM_RUNTIME_READINESS.md`;
- current provider/model registry/configuration;
- current code/tests.
