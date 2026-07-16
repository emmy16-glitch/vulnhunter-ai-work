# Proof Capsule Specification

A proof capsule is a schema-versioned immutable bundle of safe references used for independent verification. Capsules include campaign, authorization, scope, target, action-manifest hash, evidence hashes, structured observations, finding claim, verification limits, permitted strategies, redaction policy, customer boundary, and provenance.

Capsules do not include raw credentials, tokens, cookies, private keys, unrestricted shell output, private model context, hidden reasoning, unbounded payloads, or authorization-expanding instructions.

Any field change changes the capsule hash.

Structured observations must reference evidence hashes already present in the capsule. A missing or mismatched evidence reference is malformed capsule structure and is rejected during validation; it is not treated as an Oracle conflict verdict.
