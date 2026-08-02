# VulnHunter Project Intelligence Pack

This directory is the permanent, model-agnostic second brain for VulnHunter AI. It is deliberately stored as atomised Markdown in Git rather than one giant report.

## Reading order

1. [Master architecture and end-to-end delivery plan](VULNHUNTER_MASTER_ARCHITECTURE.md)
2. [Chat-first workspace contract](../product/CHAT_FIRST_WORKSPACE.md)
3. [AI-first assessment workspace architecture](../product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md)
4. [AI-first assessment workspace implementation standard](../product/AI_FIRST_ASSESSMENT_WORKSPACE_IMPLEMENTATION_STANDARD.md)
5. [UI quality assurance](../product/UI_QUALITY_ASSURANCE.md)
6. [Current state](CURRENT_STATE.md)
7. [Product definition](PRODUCT_DEFINITION.md)
8. [System architecture](SYSTEM_ARCHITECTURE.md)
9. [Security boundaries](SECURITY_BOUNDARIES.md)
10. [Explicit target authorization](TARGET_AUTHORIZATION.md)
11. [Data and human review](DATA_AND_REVIEW.md)
12. [Independent review and adjudication](INDEPENDENT_REVIEW.md)
13. [Governed collection and authenticated review](GOVERNED_COLLECTION_AND_REVIEW.md)
14. [ML governance](ML_GOVERNANCE.md)
15. [Testing strategy](TESTING_STRATEGY.md)
16. [Known failures and limitations](KNOWN_FAILURES.md)
17. [Experiment log](EXPERIMENT_LOG.md)
18. [Roadmap](ROADMAP.md)
19. [Bounded orchestration loop](ORCHESTRATION_LOOP.md)
20. [Transactional autoresearch engine](AUTORESEARCH_ENGINE.md)
21. [Unattended operations control plane](UNATTENDED_OPERATIONS.md)
22. [Connection-bound DNS enforcement](CONNECTION_PINNING.md)
23. [Technical debt](TECHNICAL_DEBT.md)
24. [Milestone 31 scanner harness](MILESTONE_31_CONTROLLED_NUCLEI_EXECUTION_HARNESS.md)
25. [Detailed future requirement register](VULNHUNTER_FUTURE_MASTER_PLAN.md)
26. [Architecture decisions](../adr/README.md)

The master architecture is the canonical readable product blueprint, current status classification, and dependency-ordered path to the finished product. The chat-first workspace contract is binding for product delivery: every supported operation must begin from, report to, and remain resumable through the authenticated conversation workspace.

The AI-first assessment workspace architecture owns the required product behaviour and arrangement of that workspace. It defines the single-assessment source of truth, live agent execution timeline, mobile and desktop shell, navigation consolidation, contextual inspector, APK flow, failure language, report alignment, test matrix and dependency-ordered pull-request programme. It is not an optional visual-design note.

The AI-first implementation standard is the non-duplicating code-level companion. It owns the implementation root-cause map, canonical assessment projection, create-or-bind boundary, error and retry contracts, role-based entry, frontend state ownership, design-token and CSS/JavaScript consolidation, responsive and accessibility thresholds, acceptance evidence and agent anti-regression rules. Agents must read it before changing the workspace, APK path, activity, inspector, navigation, findings, evidence, graph, reports or frontend architecture.

The UI quality assurance document owns the browser, responsive, accessibility and product-truth gates. Passing a screenshot or static template check does not establish completion when persisted state, lifecycle or allowed actions disagree.

The future master plan and atomic coverage documents preserve detailed requirement history and supporting evidence.

## Maintenance rule

A milestone that changes architecture, security boundaries, data contracts, model behaviour, quality gates, current status, remaining delivery order, conversation workflow, assessment-state projection, task activity, responsive behaviour, navigation, inspector behaviour, findings/evidence/report presentation, product terminology, frontend state ownership, design tokens, CSS/JavaScript ownership, accessibility thresholds or browser acceptance must update the corresponding note in the same implementation sequence.

At minimum, reconcile:

- `VULNHUNTER_MASTER_ARCHITECTURE.md` when architecture or delivery order changes;
- `docs/product/CHAT_FIRST_WORKSPACE.md` when conversation ownership changes;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md` when required product behaviour changes;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_IMPLEMENTATION_STANDARD.md` when implementation mechanics, migration boundaries or acceptance evidence changes;
- `docs/product/UI_QUALITY_ASSURANCE.md` when browser, responsive or accessibility gates change;
- `CURRENT_STATE.md` with implemented status only;
- `KNOWN_FAILURES.md` when a limitation is added, narrowed or resolved.

Do not create another document that claims to own the same assessment lifecycle, workspace projection or UI quality gate. Update the existing owner instead.

Run the repository audit after meaningful changes:

```bash
python scripts/project_audit.py
```

Generated audit files are written to:

```text
artifacts/project-audit/
```

Generated audit outputs are operational artifacts and should not become the source of truth. The maintained Markdown notes remain authoritative.