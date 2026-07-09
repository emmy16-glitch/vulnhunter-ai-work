# Controlled Source Ingestion

## Purpose

The source-ingestion engine expands the project intelligence system with approved external material while preventing untrusted documents from controlling tools, code, scans, secrets, or human decisions.

## Canonical flow

```text
approved local source file
    -> regular-file and store-boundary validation
    -> byte-for-byte preservation under knowledge/raw/
    -> SHA-256 verification
    -> provenance manifest
    -> non-executing prompt-injection screening
    -> human review packet
    -> facts/opinions/instructions/claims/evidence separation
    -> contradiction and uncertainty queues
    -> explicit source approval
    -> human-authored atomised wiki note
```

## Provenance fields

Each manifest records:

- source ID;
- title;
- origin;
- type;
- publication date;
- ingest date;
- SHA-256;
- original filename and preserved path;
- byte size;
- sensitivity;
- trust level;
- prompt-injection review status and findings;
- related notes;
- contradictions;
- human review state and note.

## Safety properties

- The original file is copied, hashed again, and stored with restrictive permissions.
- Symlinks and files already inside the knowledge store are rejected.
- Duplicate content is rejected by SHA-256.
- Unsupported binary formats are preserved but marked `not_screened`; they are never silently described as safe.
- Machine screening only flags indicators. It does not interpret truth or make approval decisions.
- Prompt-injection excerpts are redacted before appearing in review material.
- Publication is blocked until a human explicitly approves the source.
- Published notes are human-authored and atomised.
- Source instructions are recorded as data and are never executed.

## Runtime files

Raw sources, manifests, pending packets, and wiki notes are ignored by nested `.gitignore` files by default. This reduces accidental commits of sensitive or licensed material. The transparent register, ingest log, policy, and queue templates remain version-controlled.

Use a separate `--root` outside the repository for highly sensitive material.
