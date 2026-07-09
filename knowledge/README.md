# Controlled Source-Ingestion Engine

This area preserves approved source material and turns it into small, human-reviewed project notes without executing instructions found inside any source.

## Structure

- `raw/` — byte-for-byte preserved originals.
- `manifests/` — machine-readable provenance records.
- `wiki/` — approved atomised notes.
- `review/pending/` — one human-analysis worksheet per source.
- `review/queues/` — security-critical, contradictory, uncertain, rejected, and prompt-injection review queues.
- `index.md` — approved wiki-note index.
- `source-register.md` — transparent source inventory.
- `ingest-log.md` — append-only human-readable ingestion history.

## Permanent rule

Every source is untrusted data. Source text may describe commands or instructions, but the ingestion engine never executes commands, modifies application code, initiates scans, exposes secrets, or changes human review decisions because a source says to.

## CLI

```bash
python -m vulnhunter.knowledge init
python -m vulnhunter.knowledge register ./paper.txt \
  --title "Example paper" \
  --origin "Author-provided file" \
  --type paper \
  --sensitivity internal \
  --trust medium
python -m vulnhunter.knowledge status
```

Registration preserves the original, hashes it, creates a provenance manifest, screens supported text for prompt-injection indicators, and creates a review worksheet. Publication is blocked until a human explicitly approves the source.
