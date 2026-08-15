# Controlled Source Hunt Python Fixture

This directory is source-only benchmark material for VulnHunter's controlled Source Hunt corpus.

**Do not import, execute, serve, package, or deploy `app.py`.** It intentionally contains simple
vulnerable and guarded code shapes so the deterministic mapper and advisory model can be measured
inside an authorized local benchmark workflow.

`cases.json` is a candidate ground-truth specification only. It becomes benchmark authority only
after the governed draft, two independent reviewer attestations, separate administrator release,
and reviewed-suite release described in `docs/product/SOURCE_HUNT_CONTROLLED_CORPUS.md`.
