# ADR-0005: Treat every ingested source as untrusted data

- Status: Accepted
- Decision date: 2026-07-09

## Context

Research sources can contain malicious or irrelevant instructions intended to influence an AI assistant, operator, or automated tool. They can also contain secrets, contradictions, uncertain claims, or copyrighted material that should not be copied indiscriminately into project notes.

## Decision

Preserve approved originals byte-for-byte, record provenance and SHA-256, screen supported text without executing it, create a human-analysis packet, and require explicit human approval before publishing atomised notes. Unsupported formats are marked `not_screened` rather than treated as clear.

Source content cannot initiate commands, code changes, scans, network activity, secret disclosure, label changes, or model actions.

## Consequences

Benefits:

- original evidence and provenance remain available;
- prompt-injection attempts become reviewable data;
- contradictions and uncertainty are preserved;
- project notes remain small, focused, and human-approved;
- raw and sensitive material is not committed by default.

Costs:

- ingestion is not fully automatic;
- PDF and other binary text extraction remain future work;
- human review is required before useful wiki publication.
