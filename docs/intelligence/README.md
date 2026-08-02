# VulnHunter Project Intelligence Pack

This directory is the permanent, model-agnostic second brain for VulnHunter AI. It is deliberately stored as atomised Markdown in Git rather than one giant report.

## Reading order

1. [Master architecture and end-to-end delivery plan](VULNHUNTER_MASTER_ARCHITECTURE.md)
2. [Chat-first workspace contract](../product/CHAT_FIRST_WORKSPACE.md)
3. [AI-first assessment workspace architecture](../product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md)
4. [Current state](CURRENT_STATE.md)
5. [Product definition](PRODUCT_DEFINITION.md)
6. [System architecture](SYSTEM_ARCHITECTURE.md)
7. [Security boundaries](SECURITY_BOUNDARIES.md)
8. [Explicit target authorization](TARGET_AUTHORIZATION.md)
9. [Data and human review](DATA_AND_REVIEW.md)
10. [Independent review and adjudication](INDEPENDENT_REVIEW.md)
11. [Governed collection and authenticated review](GOVERNED_COLLECTION_AND_REVIEW.md)
12. [ML governance](ML_GOVERNANCE.md)
13. [Testing strategy](TESTING_STRATEGY.md)
14. [Known failures and limitations](KNOWN_FAILURES.md)
15. [Experiment log](EXPERIMENT_LOG.md)
16. [Roadmap](ROADMAP.md)
17. [Bounded orchestration loop](ORCHESTRATION_LOOP.md)
18. [Transactional autoresearch engine](AUTORESEARCH_ENGINE.md)
19. [Unattended operations control plane](UNATTENDED_OPERATIONS.md)
20. [Connection-bound DNS enforcement](CONNECTION_PINNING.md)
21. [Technical debt](TECHNICAL_DEBT.md)
22. [Milestone 31 scanner harness](MILESTONE_31_CONTROLLED_NUCLEI_EXECUTION_HARNESS.md)
23. [Detailed future requirement register](VULNHUNTER_FUTURE_MASTER_PLAN.md)
24. [Architecture decisions](../adr/README.md)

The master architecture is the canonical readable product blueprint, current status classification, and dependency-ordered path to the finished product. The chat-first workspace contract is binding for product delivery: every supported operation must begin from, report to, and remain resumable through the authenticated conversation workspace.

The AI-first assessment workspace architecture is the binding product-experience and implementation contract for arranging that workspace. It defines the single-assessment source of truth, live agent execution timeline, mobile and desktop shell, navigation consolidation, contextual inspector, APK flow, failure language, report alignment, test matrix, and dependency-ordered pull-request programme. It is not an optional visual-design note.

The future master plan and atomic coverage documents preserve detailed requirement history and supporting evidence.

## Maintenance rule

A milestone that changes architecture, security boundaries, data contracts, model behaviour, quality gates, current status, remaining delivery order, conversation workflow, assessment-state projection, task activity, responsive behaviour, navigation, inspector behaviour, findings/evidence/report presentation, or product terminology must update the corresponding note, `VULNHUNTER_MASTER_ARCHITECTURE.md`, `docs/product/CHAT_FIRST_WORKSPACE.md`, and `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md` in the same implementation sequence.

Run the repository audit after meaningful changes:

```bash
python scripts/project_audit.py
```

Generated audit files are written to:

```text
artifacts/project-audit/
```

Generated audit outputs are operational artifacts and should not become the source of truth. The maintained Markdown notes remain authoritative.
