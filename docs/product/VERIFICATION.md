# Deterministic Verification

Verification is an internal stage of an assessment, not a separate product or scanner.

## Finding lifecycle

```text
scanner observation
→ candidate finding
→ proof capsule
→ deterministic verification
→ human review
→ governed release
```

The verification layer cannot authorize a target, expand scope, approve an action, grant privilege, execute arbitrary commands or publish a finding.

## Proof capsules

Every safe verification attempt binds:

- campaign, run, authorization, scope and target identity;
- exact action-plan digest and approval reference;
- scanner, adapter and tool versions;
- evidence hashes and structured observations;
- the claimed condition and expected verification rule;
- permitted strategies, limits and expiry;
- provenance and redaction policy.

A capsule is content-addressed and replayable without trusting an advisory explanation.

## Deterministic outcomes

Verification may return:

- `VERIFIED` when the bounded rule is satisfied by consistent evidence;
- `NOT_REPRODUCED` when a valid safe check does not reproduce the condition;
- `CONFLICTING_EVIDENCE` when valid evidence disagrees;
- `ABSTAIN` when evidence, authorization, scope, safety or runtime prerequisites are insufficient.

Failure to run is never treated as proof that a target is safe.

## Unified findings

The assessment and Findings pages show one consolidated record. Scanner identity, template ID, verification recipe, hashes and optional advisory involvement remain in evidence provenance and the audit trail.

Verification does not determine final business impact, customer risk, severity or publication. Those remain human-review and release decisions.
