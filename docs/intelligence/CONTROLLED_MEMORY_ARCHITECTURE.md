# Controlled Learning Architecture

```text
verified finding
→ bounded analyst / critic / synthesizer
→ untrusted memory candidates
→ named human review
→ deterministic evaluation
→ explicit promotion
→ promoted memory retrieval for later reasoning
```

The intelligence worker may generate semantic and procedural candidates after a completed advisory
analysis. Candidate generation does not alter a model, prompt, policy, severity, authorization,
publication state, or tool permission.

The next analysis receives at most eight promoted memory items. The prompt marks them as reviewed
context that cannot override policy. All scanner evidence and authorization checks remain
independent and authoritative.

High-impact actions use a separate capability proposal contract. The model may describe the exact
objective, target, scope reference, and evidence reference. A role-appropriate human must approve
the proposal, after which the existing governed tool layer must still enforce execution limits.
