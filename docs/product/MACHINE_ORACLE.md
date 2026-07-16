# Machine Oracle

The Machine Oracle is an independent verifier layer. It cannot authorize targets, expand scope, approve actions, consume approvals, grant privilege, execute arbitrary commands, activate connectors, or publish findings.

Implemented foundations:

- immutable `ProofCapsule` records with deterministic hashes;
- deterministic verifier selection that prefers replay and evidence consistency;
- Oracle verdict records separate from final finding status;
- disabled-by-default `pentest-ai` connector contract;
- injected external-response authenticator interface for future protected-key or signature verification;
- durable response replay ledger with atomic digest claims;
- verifier identity, supported-version, response-integrity, capsule-hash, authentication, and replay checks;
- durable capsule storage and transactional SQLite session envelopes;
- canonical queued-only session creation with immutable identity and configuration bindings;
- full typed history replay on every load and update, including sequence, hash-chain,
  event-digest, transition, monotonicity, append-only evidence, and snapshot checks;
- atomic expected-status and expected-snapshot compare-and-swap updates that reject stale writers.

Malformed proof capsules are rejected during capsule validation. `CONFLICTING_EVIDENCE` is reserved for valid conflicting evidence or authenticated external verifier conflict responses; it is not used to relabel structurally invalid capsules.

Deferred operational dependencies:

- live `pentest-ai` service;
- production connector keys, signatures, or protected authentication material;
- external verifier execution;
- model-assisted verification;
- production promotion of Oracle output.

Oracle output remains candidate material until governed human review accepts it.
