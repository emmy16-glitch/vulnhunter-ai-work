# Controlled Capability Boundaries

VulnHunter can let the AI **propose** high-impact work, but the proposal itself never grants
permission or executes a tool.

| Proposed action | Required human role | Additional gate |
|---|---|---|
| Network request | Authorization owner | Exact active authorization and deterministic verification |
| Grant or change authorization | Authorization owner | The model cannot approve its own request |
| Change severity | Security analyst | Evidence review and recorded decision |
| Publish a result | Publisher | Publication review and provenance checks |
| Exploit action | Test-environment owner | Exact scope, isolated lab, deterministic verification |

No entry is automatically executable. Destructive actions remain prohibited. The broker returns
requirements after an approved decision; an existing scoped tool adapter must still enforce the
actual target, method, limits, evidence, stop conditions, and audit record.
