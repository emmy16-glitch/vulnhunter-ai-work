# VulnHunter Product Interface Blueprint

## Purpose

This blueprint defines the future browser interface without implementing an API,
frontend runtime, connector, model-training action, deployment, or policy bypass.
The backend remains authoritative for authorization, scope, DNS pinning, review,
adjudication, release eligibility, and audit integrity.

## Product character

The interface is a calm, professional security-operations product rather than a
decorative cyberpunk dashboard. Dense evidence is organized progressively: key
status and blockers first, technical provenance on demand, and immutable hashes in
dedicated evidence views.

## Primary areas

1. Security operations dashboard.
2. Authorizations and bounded scan setup.
3. Scan progress, findings, and redacted evidence.
4. Governed campaigns and application families.
5. Independent review and adjudication workspaces.
6. Release assessment and immutable manifests.
7. Dataset readiness and model-evaluation evidence.
8. Audit timelines, integrity verification, and reports.

## Non-negotiable boundary

A hidden, disabled, or visually unavailable control is not a security control.
Every permission, separation-of-duty rule, release blocker, and scan boundary must
also be enforced by backend services.
