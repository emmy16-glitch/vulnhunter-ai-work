# Independent Web Verifier Foundation

## Purpose

The independent web verifier is a separate, read-only authority placed after the adaptive web
hunter coordinator. Hunters propose bounded hypotheses from sanitized browser structure. The
verifier does not trust those proposals merely because their hashes are internally consistent.
It independently re-validates the source evidence, checks the semantic hunter contract, and
reproduces the structural predicate before returning an integrity-linked verdict.

This foundation does **not** perform active vulnerability testing and cannot validate a
vulnerability from passive structure alone.

## Flow

```text
WebPerceptionResult
        +
HunterRunResult
        |
        v
recompute perception evidence integrity
        |
recompute application graph integrity
        |
recompute HunterRunResult integrity
        |
check exact target / plan / evidence / graph bindings
        |
validate every hypothesis graph reference and identity
        |
independently check strategy -> hunter -> vulnerability contract
        |
independently reproduce passive structural predicate
        |
        +-------------------------------+
        |                               |
predicate absent                 predicate reproduced
        |                               |
     REJECTED                       INCONCLUSIVE
        |                               |
        +---------------+---------------+
                        |
              integrity-linked batch
```

## Why the verifier is separate

The verifier deliberately does not import or call the private predicate helpers used by the
specialist hunters. It re-implements the supported structural checks at a separate boundary.
This prevents a defect in a hunter predicate from becoming self-confirming merely because the
same function is called twice.

The verifier also checks a stronger semantic contract than the hunter fingerprint alone. Each
verification strategy is bound to the expected hunter ID, vulnerability class, and exact
required-evidence list.

## Current verdict semantics

The lifecycle reserves three verdict names:

- `validated`
- `rejected`
- `inconclusive`

However, this passive foundation is intentionally unable to construct `validated`.
`IndependentVerificationResult` rejects a passive `validated` result at schema validation.

Current outcomes are:

### `rejected`

A hypothesis is rejected when either:

- its strategy/hunter/vulnerability/evidence contract does not match the known verifier
  contract; or
- the verifier cannot independently reproduce the structural predicate against the exact
  perception evidence and graph.

A rejected verdict means the specific hunter hypothesis failed this independent passive
verification step. It does not make a broader statement that the application is secure.

### `inconclusive`

A hypothesis remains inconclusive when the verifier reproduces the passive structural predicate
but passive structure cannot establish the security failure itself.

Examples:

- an object identifier exists in a browser-observed endpoint path, but no independently
  authorized two-identity access comparison has been performed;
- a state-changing form has no recognizable request-integrity field in the sanitized structure,
  but server-side, header-based, framework, or cookie controls have not been independently
  assessed;
- a file upload control exists, but no governed upload-policy/storage/serving evidence exists;
- an authentication form exists, but no independent session/rate-limit/recovery evidence exists;
- an API-like read-only endpoint exists, but role/tenant/object authorization evidence is absent.

## Authority boundary

The verifier has no execution plane. Every result hard-codes:

```text
network_access_performed       = false
mutating_request_performed     = false
credential_use_performed       = false
authorization_bypass_performed = false
shell_execution_performed      = false
external_evidence_accepted     = false
```

No scanner arguments, payloads, credentials, request bodies, headers, cookies, raw HTML,
JavaScript, storage values, command strings, or shell instructions are accepted by this API.

The verifier receives the same sanitized `WebPerceptionResult` and integrity-linked
`HunterRunResult` already produced by earlier stages. It does not create target authorization,
execution approval, finding severity, remediation authority, merge authority, or publication
authority.

## Evidence minimization

Verifier output deliberately carries hashes and graph identifiers rather than copying raw target
content. Evidence references bind:

- exact hunter result SHA-256;
- exact perception-plan SHA-256;
- exact perception-evidence SHA-256;
- exact application-graph SHA-256;
- exact hypothesis SHA-256;
- exact verification-intent SHA-256;
- exact target-reference SHA-256;
- hypothesis ID;
- verification-intent ID;
- target node ID;
- referenced graph node/edge IDs.

The verifier does not copy target-controlled form names into its result. Adversarial tests use
instruction-like field names and require them to remain absent from verifier output.

## Fail-closed source checks

Before any verdict is issued, the verifier requires:

1. valid browser-perception evidence integrity;
2. valid application-surface graph integrity;
3. valid hunter-run integrity;
4. exact target binding between perception and hunter run;
5. exact plan/evidence/graph hashes between perception and hunter run;
6. execution summaries whose emitted count matches the actual hypothesis count;
7. `suspected` source state only;
8. valid graph references, semantic fingerprint, hypothesis ID, and verification-intent ID for
   every hypothesis.

Tampered sources fail before a decision is produced.

## Supported independent structural predicates

The first verifier reproduces the five deterministic hunter classes introduced by the adaptive
hunter coordinator:

- object authorization candidate;
- request-integrity / CSRF-control candidate;
- file-upload validation candidate;
- authentication-control candidate;
- API access-control candidate.

The verifier is intentionally limited to those contracts. Adding another hunter requires an
explicit verifier contract and independent predicate implementation before that hunter can pass
this stage.

## What unlocks `validated` later

A later batch may add governed, independently produced evidence receipts. That work must not
simply relax the current schema or let hunter/model text assert success. It must define a real
evidence authority for each strategy, for example:

- exact active authorization binding;
- independently identified verifier/collector identity;
- immutable collection plan and receipt identity;
- read-only request semantics where applicable;
- exact target/origin/path containment;
- bounded request/time/output budgets;
- credential handling that never guesses credentials and uses only explicit test identities;
- comparison evidence that is redacted and hash-bound;
- replay/tamper/stale-evidence protection;
- a separate human-review gate where required.

Only such an evidence path may make `validated` constructible. The passive verifier foundation
must remain unable to promote itself.

## Deliberately deferred

This batch does not implement:

- network-capable verification;
- authenticated or two-identity object-access comparison;
- form submission;
- upload testing;
- credential submission or guessing;
- XSS, SQL injection, SSRF, command injection, or payload execution;
- headless/intrusive Nuclei verification;
- public OAST/Interactsh;
- persistent verifier storage;
- Assessment/task-graph projection;
- UI/conversation flows;
- LLM verdict authority;
- severity assignment;
- finding confirmation in the main observation store;
- automatic remediation.

## Acceptance contract

The focused verifier workflow runs on Python 3.11 and 3.12 and requires:

- Ruff lint;
- Ruff formatting;
- Python compilation;
- deterministic verifier unit/adversarial tests.

Repository-wide quality, browser, phone, conversational, scanner-compatibility, and existing
private-lab acceptance remain required before the batch can be considered complete.
