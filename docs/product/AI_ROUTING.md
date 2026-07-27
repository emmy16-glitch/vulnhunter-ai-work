# Groq Routing and Privacy Gate

VulnHunter remains fully usable when Groq is disabled. Deterministic processing is authoritative for authorization, scope, approval, parsing, hashing, repository inventory, limits, evidence integrity, verification state and publication gates.

Central rule:

> Groq proposes; VulnHunter verifies and enforces.

Groq is the only AI/model provider in the production architecture. No Claude, Qwen, OpenAI API or local-model runtime is required or selected by the provider registry.

## Deterministic-first routing

Every request is first classified by privacy and task type.

- Deterministic processing is used whenever rules, schema validation, hashing or direct evidence are sufficient.
- Customer data, credentials, cookies, authorization records, private keys and detected secrets are denied remote routing.
- Sanitized non-sensitive evidence may use an explicitly approved bounded Groq advisory request.
- Source code requires a separate exact, time-limited Groq source-processing approval.
- Repeated open-ended remote loops are blocked.
- Provider failure, timeout, cancellation, malformed output, invented evidence or unavailable quota returns `ABSTAIN` or a safe failure state.

## Groq provider contract

Groq is optional and disabled by default. The provider contract enforces:

- the approved HTTPS API endpoint only;
- an owner-private API-key file;
- an explicit model allowlist;
- bounded input, output and timeout limits;
- no tools, shell, scanner, browser, MCP or connector definitions;
- structured `PROPOSAL`, `CANDIDATE_ANALYSIS` or `ABSTAIN` output only;
- no trusted, verified, approved or published output state;
- request/response hashes and bounded provenance without raw credentials.

Groq cannot authorize, expand scope, execute a tool, contact a target, verify a finding, determine final severity, apply a patch, merge code or publish a result.

## Normal advisory analysis

Groq is not consulted before target authorization, passive planning, approval or scanning. After scanner evidence exists, it may summarize or classify sanitized non-sensitive evidence through bounded analyst, critic and synthesizer stages.

Groq output is stored as advisory provenance under the unified finding. It never creates an independently authoritative finding and cannot change deterministic verification or human-review state.

## Exact source-code processing

Source Hunt is a distinct route. Before source excerpts are transmitted, VulnHunter creates an approval bound to:

- repository identifier;
- exact revision;
- complete eligible-file snapshot SHA-256;
- permitted repository-relative paths;
- repository visibility;
- Groq as the provider;
- approving identity;
- approval and expiry timestamps;
- approval-record SHA-256.

The browser requires password re-authentication. The CLI requires an authenticated governance administrator and an owner-only secret file. Any snapshot drift, path expansion, expired approval or provider mismatch fails closed.

Only bounded excerpts selected from deterministic attack surfaces are sent. Every returned path, source hash and line range is checked against the exact snapshot. Groq references that were not supplied are rejected.

Customer data and secret material remain prohibited even when source processing is approved.

## Source Hunt stages

The bounded Groq sequence is:

```text
reconnaissance
→ attacker-first hypothesis
→ separate falsification
→ capability assessment
→ remediation and RED test proposal
```

Hard limits cover files, bytes, attack surfaces, candidates, call-path depth, model calls, prompt bytes, output tokens and timeout. The model is not allowed to declare verification or completion.

## Graph context

A validated repository graph may supply a bounded subgraph. When external graph tooling is missing or stale, the context broker uses the native deterministic repository graph and bounded source excerpts. It never fabricates graph relationships or sends an unrestricted repository automatically.

## Activation dependencies

Groq remains disabled until all of these pass:

1. owner-private key-file validation;
2. approved model inventory check;
3. harmless structured-response test;
4. privacy and redaction acceptance tests;
5. exact source-processing approval tests;
6. evidence-reference integrity tests;
7. per-task and operational usage limits;
8. cancellation, timeout and failure tests;
9. human review of provider terms, retention and data controls.

Deterministic workflows continue when Groq is disabled or unavailable. Source Hunt details are documented in [`SOURCE_HUNT.md`](SOURCE_HUNT.md).
