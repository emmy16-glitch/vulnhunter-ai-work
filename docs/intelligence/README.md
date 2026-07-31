# VulnHunter Project Intelligence Pack

This directory is the permanent, model-agnostic second brain for VulnHunter AI. It is deliberately stored as atomised Markdown in Git rather than one giant report.

## Reading order

1. [Master architecture and end-to-end delivery plan](VULNHUNTER_MASTER_ARCHITECTURE.md)
2. [Current state](CURRENT_STATE.md)
3. [Product definition](PRODUCT_DEFINITION.md)
4. [System architecture](SYSTEM_ARCHITECTURE.md)
5. [Security boundaries](SECURITY_BOUNDARIES.md)
6. [Explicit target authorization](TARGET_AUTHORIZATION.md)
7. [Data and human review](DATA_AND_REVIEW.md)
8. [Independent review and adjudication](INDEPENDENT_REVIEW.md)
9. [Governed collection and authenticated review](GOVERNED_COLLECTION_AND_REVIEW.md)
10. [ML governance](ML_GOVERNANCE.md)
11. [Testing strategy](TESTING_STRATEGY.md)
12. [Known failures and limitations](KNOWN_FAILURES.md)
13. [Experiment log](EXPERIMENT_LOG.md)
14. [Roadmap](ROADMAP.md)
15. [Bounded orchestration loop](ORCHESTRATION_LOOP.md)
16. [Transactional autoresearch engine](AUTORESEARCH_ENGINE.md)
17. [Unattended operations control plane](UNATTENDED_OPERATIONS.md)
18. [Connection-bound DNS enforcement](CONNECTION_PINNING.md)
19. [Technical debt](TECHNICAL_DEBT.md)
20. [Milestone 31 scanner harness](MILESTONE_31_CONTROLLED_NUCLEI_EXECUTION_HARNESS.md)
21. [Detailed future requirement register](VULNHUNTER_FUTURE_MASTER_PLAN.md)
22. [Architecture decisions](../adr/README.md)

The master architecture is the canonical readable product blueprint, current status classification, and dependency-ordered path to the finished product. The future master plan and atomic coverage documents preserve detailed requirement history and supporting evidence.

## Maintenance rule

A milestone that changes architecture, security boundaries, data contracts, model behaviour, quality gates, current status, or remaining delivery order must update the corresponding note and `VULNHUNTER_MASTER_ARCHITECTURE.md` in the same commit.

Run the repository audit after meaningful changes:

```bash
python scripts/project_audit.py
```

Generated audit files are written to:

```text
artifacts/project-audit/
```

Generated audit outputs are operational artifacts and should not become the source of truth. The maintained Markdown notes remain authoritative.