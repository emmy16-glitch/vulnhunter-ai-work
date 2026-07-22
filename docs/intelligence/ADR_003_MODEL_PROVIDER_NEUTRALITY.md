# ADR-003 — Model-provider neutrality and retirement of Qwen-specific plans

**Status:** Accepted  
**Date:** 2026-07-22  
**Owner:** Emmanuel Okunlola

## Decision

VulnHunter is model-provider neutral. Qwen is not a required runtime, frontend
designer, scanner, authority, or product dependency. Any older Qwen-specific
roadmap text is historical research and is superseded by this decision.

The platform may use an explicitly approved advisory provider in the future, but
all providers remain optional and non-authoritative. The product must continue to
work through deterministic tools and human review when no model is configured.

No model may authorize a target, expand scope, approve an action, execute an
unrestricted tool, verify its own finding, determine final severity, publish a
finding, access secrets, or override a human decision.

## Consequences

- UI copy and routes must use neutral terms such as “Intelligence components” or
  “Advisory analysis,” never a model brand as the product identity.
- No Qwen package, service, API, prompt, or model file is installed by default.
- Historical documents may mention evaluated models, but they do not grant an
  implementation requirement.
- Provider removal must not break authorization, scanning, evidence, verification,
  review, reporting, or audit workflows.
