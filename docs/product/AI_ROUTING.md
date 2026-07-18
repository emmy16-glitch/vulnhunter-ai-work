# Advisory Routing and Privacy Gate

VulnHunter remains fully usable without an advisory provider. Deterministic processing is authoritative for authorization, scope, approval, parsing, hashing, limits, evidence integrity, verification state and publication gates.

Central rule:

> Advisory analysis may propose; VulnHunter verifies and enforces.

## Deterministic-first routing

Every request is first classified by privacy and task type.

- Deterministic processing is used whenever rules, schema validation, hashing or direct evidence are sufficient.
- Customer-private or secret data is denied remote routing.
- Sanitized non-sensitive evidence may use one explicitly approved Groq advisory attempt.
- Repeated remote loops are blocked and routed to a human analyst.
- Provider failure, timeout, cancellation, malformed output or unavailable quota returns `ABSTAIN`.

## Groq advisory provider

Groq is optional and disabled by default. The provider contract enforces:

- the official HTTPS API endpoint only;
- an owner-private API-key file;
- an explicit model allowlist;
- bounded input, output and timeout limits;
- no tools, shell, scanner, browser, MCP or connector definitions;
- structured `PROPOSAL`, `CANDIDATE_ANALYSIS` or `ABSTAIN` output only;
- no trusted, verified, approved or published output state;
- request/response hashes and bounded provenance without raw credentials.

Private source code, private targets, authorization records, customer data, tokens, cookies, credentials, unpublished findings and raw evidence are denied remote routing.

## Assessment integration

Groq is not consulted before authorization, planning, approval or scanning. It may be used after evidence exists when deterministic processing cannot summarize or classify sanitized non-sensitive material confidently.

Groq output is stored as advisory provenance under the unified finding. It never creates a separate finding and cannot change deterministic verification or human-review state.

## Graph context

A validated repository graph may supply a bounded subgraph. When external graph tooling is missing or stale, the context broker uses the native deterministic repository graph and bounded source excerpts. It never fabricates graph relationships or send an unrestricted repository to a provider.

## Activation dependencies

Groq remains disabled until all of these pass:

1. owner-private key-file validation;
2. approved model inventory check;
3. harmless structured-response test;
4. privacy and redaction acceptance tests;
5. per-task and operational usage limits;
6. cancellation, timeout and failure tests;
7. human review of provider terms and data controls.

Deterministic workflows continue when Groq is disabled or unavailable.
