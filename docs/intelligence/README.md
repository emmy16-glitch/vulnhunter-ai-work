# VulnHunter Project Intelligence Pack

This directory is the permanent, model-agnostic second brain for VulnHunter AI. It is deliberately stored as atomised Markdown in Git rather than one giant report.

## Reading order

1. [Master architecture and end-to-end delivery plan](VULNHUNTER_MASTER_ARCHITECTURE.md)
2. [Chat-first workspace contract](../product/CHAT_FIRST_WORKSPACE.md)
3. [Current state](CURRENT_STATE.md)
4. [Product definition](PRODUCT_DEFINITION.md)
5. [System architecture](SYSTEM_ARCHITECTURE.md)
6. [Security boundaries](SECURITY_BOUNDARIES.md)
7. [Explicit target authorization](TARGET_AUTHORIZATION.md)
8. [Data and human review](DATA_AND_REVIEW.md)
9. [Independent review and adjudication](INDEPENDENT_REVIEW.md)
10. [Governed collection and authenticated review](GOVERNED_COLLECTION_AND_REVIEW.md)
11. [ML governance](ML_GOVERNANCE.md)
12. [Testing strategy](TESTING_STRATEGY.md)
13. [Known failures and limitations](KNOWN_FAILURES.md)
14. [Experiment log](EXPERIMENT_LOG.md)
15. [Roadmap](ROADMAP.md)
16. [Bounded orchestration loop](ORCHESTRATION_LOOP.md)
17. [Transactional autoresearch engine](AUTORESEARCH_ENGINE.md)
18. [Unattended operations control plane](UNATTENDED_OPERATIONS.md)
19. [Connection-bound DNS enforcement](CONNECTION_PINNING.md)
20. [Technical debt](TECHNICAL_DEBT.md)
21. [Milestone 31 scanner harness](MILESTONE_31_CONTROLLED_NUCLEI_EXECUTION_HARNESS.md)
22. [Detailed future requirement register](VULNHUNTER_FUTURE_MASTER_PLAN.md)
23. [Architecture decisions](../adr/README.md)

The master architecture is the canonical readable product blueprint, current status classification, and dependency-ordered path to the finished product. The chat-first workspace contract is binding for product delivery: every supported operation must begin from, report to, and remain resumable through the authenticated conversation workspace. The future master plan and atomic coverage documents preserve detailed requirement history and supporting evidence.

## Maintenance rule

A milestone that changes architecture, security boundaries, data contracts, model behaviour, quality gates, current status, remaining delivery order, or the conversation workflow must update the corresponding note, `VULNHUNTER_MASTER_ARCHITECTURE.md`, and `docs/product/CHAT_FIRST_WORKSPACE.md` in the same commit.

Run the repository audit after meaningful changes:

```bash
python scripts/project_audit.py
```

Generated audit files are written to:

```text
artifacts/project-audit/
```

Generated audit outputs are operational artifacts and should not become the source of truth. The maintained Markdown notes remain authoritative.
