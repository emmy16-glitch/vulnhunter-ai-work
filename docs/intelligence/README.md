# VulnHunter Project Intelligence Pack

This directory is the permanent, model-agnostic second brain for VulnHunter AI. It is deliberately stored as atomised Markdown in Git rather than one giant report.

## Reading order

1. [Current state](CURRENT_STATE.md)
2. [Product definition](PRODUCT_DEFINITION.md)
3. [System architecture](SYSTEM_ARCHITECTURE.md)
4. [Security boundaries](SECURITY_BOUNDARIES.md)
5. [Explicit target authorization](TARGET_AUTHORIZATION.md)
6. [Data and human review](DATA_AND_REVIEW.md)
7. [Independent review and adjudication](INDEPENDENT_REVIEW.md)
8. [ML governance](ML_GOVERNANCE.md)
9. [Testing strategy](TESTING_STRATEGY.md)
10. [Known failures and limitations](KNOWN_FAILURES.md)
11. [Experiment log](EXPERIMENT_LOG.md)
12. [Roadmap](ROADMAP.md)
13. [Bounded orchestration loop](ORCHESTRATION_LOOP.md)
14. [Transactional autoresearch engine](AUTORESEARCH_ENGINE.md)
15. [Technical debt](TECHNICAL_DEBT.md)
16. [Architecture decisions](../adr/README.md)

## Maintenance rule

A milestone that changes architecture, security boundaries, data contracts, model behaviour, quality gates, or known limitations must update the corresponding note in the same commit.

Run the repository audit after meaningful changes:

```bash
python scripts/project_audit.py
```

Generated audit files are written to:

```text
artifacts/project-audit/
```

Generated audit outputs are operational artifacts and should not become the source of truth. The maintained Markdown notes remain authoritative.
