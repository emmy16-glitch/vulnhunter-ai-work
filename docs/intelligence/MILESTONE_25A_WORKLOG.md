# Milestone 25A Worklog

## Baseline

- Expected commit: `fa330e4`
- Branch: `milestone-25a-controlled-pilot-preparation`
- Independent of concurrent Milestone 24 interface work

## Architecture

This milestone adds an isolated `vulnhunter.pilot` package. It does not mutate
authorization, governance, agent, product-interface, observation, release, or
model state. Its CLI is package-local and read-only.

## Components

1. Strict immutable pilot-plan models.
2. Canonical plan and report SHA-256 hashing.
3. Fail-closed validation.
4. Package-local CLI.
5. Synthetic example configuration.
6. Controlled human pilot runbook.
7. Focused unit tests.

## Safety

Local/lab only; public/external targets prohibited; two independent reviewers;
separate adjudicator; active human assignments; connectors disabled; no
automatic approval, confirmation, adjudication, or release; no model training
during collection; credential-like values rejected; instruction-like evidence
remains inert untrusted data.
