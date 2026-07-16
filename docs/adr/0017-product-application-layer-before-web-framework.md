# ADR-0017: Product Application Layer Before Web Framework

## Status

Accepted, then resolved by the approved Django implementation in Combined
Milestone 24C-24F.

## Decision

Implement Milestone 24 as a framework-independent product application/read-model
layer backed by the existing VulnHunter stores, services, runtime state, and
validated product blueprint. Expose this layer through a controlled local CLI
surface first.

At the time of the original decision, do not introduce an ad hoc browser
server, template runtime, session layer, or CSRF mechanism in-repo while no
approved web framework exists. The minimum safe next step for a browser product
shell was an explicit dependency decision for a framework that can support:

- authenticated sessions;
- CSRF protection for consequential actions;
- route-level authorization;
- safe server rendering or templating;
- accessibility- and security-reviewable HTML generation.

That dependency decision has now been made:

- Django is the approved secure server-rendered framework.
- The product application layer remains the read-model boundary beneath the web
  adapter layer.
- Browser authentication uses Django sessions.
- CSRF protection, security headers, and route-level authorization are enforced
  in the Django surface.

## Consequences

- `vulnhunter.product` remains the presentation-facing boundary above domain and
  store services.
- Product summaries use real authorization, governance, readiness, role/skill,
  and bounded-agent data without duplicating backend policy.
- Browser-specific operational pages are now implemented through Django rather
  than an ad hoc server.
- Unsupported capabilities remain explicitly unavailable instead of being mocked
  or loosely approximated.
