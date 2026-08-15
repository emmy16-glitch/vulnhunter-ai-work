# Governed External Web Verification Evidence

## Purpose

This layer accepts cryptographically signed, hash-only evidence receipts produced by a separate verification-evidence collector and binds them to one exact passive `IndependentVerificationResult`.

It does **not** run the collector, make a network request, submit a form, use credentials, execute a payload, bypass access control, or convert a hypothesis to `validated`.

```text
Passive IndependentVerificationResult
            +
Signed external evidence receipt
            +
Deployment-pinned collector public key + trust policy
            |
            v
revalidate passive result integrity
            |
verify exact hypothesis / intent / strategy / target bindings
            |
verify authorization-reference + collection-plan + runtime + evidence hashes are present
            |
verify collector policy and byte/network limits
            |
verify detached Ed25519 signature
            |
reject duplicate receipt IDs in this admission batch
            |
ExternalEvidenceAdmissionBatch
            |
      no finding authority
```

## Trust model

A receipt is not trusted because it contains a key. VulnHunter receives a `TrustedExternalEvidenceCollector` from deployment configuration containing:

- a fixed collector ID;
- a trust-policy SHA-256;
- an expected Ed25519 public-key ID;
- the actual trusted public key;
- an explicit list of allowed verification strategies;
- whether that collector may attest bounded read-only network collection;
- a maximum evidence-byte limit.

The receipt's detached signature must verify with that already-trusted public key. Production private signing keys are not generated, stored, or loaded by VulnHunter.

## Receipt contents

Receipts carry only bounded metadata and cryptographic references:

- passive verification ID and result SHA-256;
- hunter result, hypothesis and intent identities;
- verification strategy and target-reference SHA-256;
- authorization-reference and authorization-snapshot SHA-256 values;
- immutable collection-plan SHA-256;
- collector-runtime SHA-256;
- evidence SHA-256 and bounded byte count;
- evidence class and collector outcome;
- collection timestamps;
- whether network collection occurred and, if so, only `GET` / `HEAD` method declarations;
- explicit false assertions for mutation, credential use, authorization bypass, shell execution and payload execution;
- explicit redaction/no-raw-content/no-secret assertions.

Raw response bodies, headers, cookies, credentials, HTML, JavaScript, storage values, payloads, shell commands, and user/target prose do not exist in the receipt schema. Extra fields are rejected.

## Evidence outcome is not a vulnerability verdict

The collector may attest one of:

- `supports_hypothesis`;
- `refutes_hypothesis`;
- `inconclusive`.

Those values describe the collector's evidence. They are deliberately **not** mapped to `validated` / `rejected` finding authority in this batch.

Every admitted receipt and admission batch hard-code:

```text
finding_validation_permitted = false
verification_adjudication_permitted = false
```

The passive verifier remains unchanged and still cannot construct `validated`.

## Network boundary

This package performs no network access. It can verify a receipt that says a separate collector performed bounded read-only network collection only when the deployment-pinned trust policy explicitly allows it.

The receipt schema permits only `GET` and `HEAD`. Mutation, credentials, authorization bypass, shell execution and payload execution are impossible to encode as successful values because their fields are `Literal[False]`.

This does not create a network-capable verifier. The actual collector remains a separate future authority with its own target authorization, exact origin/path containment, DNS pinning, budgets and worker acceptance.

## Authorization limitation

The receipt cryptographically binds `authorization_reference_sha256` and `authorization_snapshot_sha256`, but this batch does not query the authorization store or prove that the referenced authorization was active at collection time. That check belongs to the future governed collector/execution integration and must be verified before evidence can influence a final vulnerability verdict.

A signed receipt therefore proves that a trusted collector attested to those exact authorization references; it does not itself create permission.

## Replay and persistence limitation

Duplicate receipt IDs are rejected within one admission batch, and receipt IDs/hashes are deterministic and tamper-evident.

However, this batch intentionally does **not** add durable persistence. It therefore records:

```text
durable_replay_protection_established = false
```

Cross-process/cross-restart replay prevention requires the later authoritative persistence/task-graph integration. This layer must not claim durable replay protection before that store exists.

## Signature boundary

Receipts use detached Ed25519 signatures over canonical JSON bytes. The signature key ID is derived from the public key's DER SubjectPublicKeyInfo SHA-256, matching the existing worker-release trust convention.

The admission boundary rejects:

- unknown collectors;
- wrong public keys;
- key-ID substitution;
- malformed signatures;
- invalid signatures;
- strategies not permitted by collector policy;
- receipts bound to another passive result/hypothesis/intent/target;
- evidence that predates the passive verification result;
- evidence larger than the collector's configured limit;
- network evidence when the collector is not trusted for read-only network collection;
- duplicate receipt IDs;
- forged receipt IDs even when an attacker recomputes the outer receipt hash.

## Deliberately deferred

This batch does not implement:

- a network evidence collector;
- active authorization-store lookup for receipt admission;
- persistent receipt ledger / durable replay prevention;
- two-identity access comparison;
- credential handling;
- form submission or file upload;
- injection/payload execution;
- strategy-specific sufficient-evidence policy;
- conversion from external evidence to a `validated` vulnerability;
- human adjudication;
- severity assignment;
- main Assessment/task graph/database integration;
- UI/conversation projection;
- automatic remediation.

Those capabilities must be separate batches because each crosses a different authorization or evidence-authority boundary.
