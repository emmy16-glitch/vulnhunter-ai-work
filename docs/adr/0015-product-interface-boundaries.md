# ADR-0015: Product Interface Boundaries

## Status

Accepted as a blueprint; no product runtime is implemented by this decision.

## Decision

Define a machine-readable, validated product-interface blueprint before building
the API and frontend. The interface follows the governed workflow and consumes
domain services, but it never becomes a second source of authorization, scope,
review, adjudication, release, or model-governance logic.

Figma is the editable design source for visual and interaction decisions. The
repository specification remains the reviewable source for routes, resources,
permissions, error states, responsive rules, and Figma handoff requirements.

## Consequences

Product implementation can proceed in vertical slices with stable contracts. The
blueprint adds no endpoint, scan, identity, credential, connector, training job, or
deployment capability. Any future difference between UI behavior and backend policy
is resolved in favor of the backend policy and recorded as a defect.
