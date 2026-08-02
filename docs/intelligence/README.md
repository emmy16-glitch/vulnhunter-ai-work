# VulnHunter Project Intelligence Pack

This directory is the permanent, model-agnostic second brain for VulnHunter AI. It is deliberately stored as atomised Markdown in Git rather than one giant report.

## Reading order

1. [Master architecture and end-to-end delivery plan](VULNHUNTER_MASTER_ARCHITECTURE.md)
2. [Chat-first workspace contract](../product/CHAT_FIRST_WORKSPACE.md)
3. [AI-first assessment workspace architecture](../product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md)
4. [AI-first assessment workspace implementation standard](../product/AI_FIRST_ASSESSMENT_WORKSPACE_IMPLEMENTATION_STANDARD.md)
5. [Premium interaction, motion and conversation experience standard](../product/PREMIUM_INTERACTION_MOTION_AND_CONVERSATION_EXPERIENCE.md)
6. [UI quality assurance](../product/UI_QUALITY_ASSURANCE.md)
7. [Current state](CURRENT_STATE.md)
8. [Product definition](PRODUCT_DEFINITION.md)
9. [System architecture](SYSTEM_ARCHITECTURE.md)
10. [Security boundaries](SECURITY_BOUNDARIES.md)
11. [Explicit target authorization](TARGET_AUTHORIZATION.md)
12. [Data and human review](DATA_AND_REVIEW.md)
13. [Independent review and adjudication](INDEPENDENT_REVIEW.md)
14. [Governed collection and authenticated review](GOVERNED_COLLECTION_AND_REVIEW.md)
15. [ML and Hugging Face production architecture](ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)
16. [ML governance](ML_GOVERNANCE.md)
17. [Dataset integrity and ML release quality](../DATA_QUALITY.md)
18. [Machine-learning pipeline](../ML_PIPELINE.md)
19. [Model selection, calibration and locked evaluation](../MODEL_SELECTION.md)
20. [AI provider routing and privacy](../product/AI_ROUTING.md)
21. [LLM and Hugging Face runtime readiness](../product/LLM_RUNTIME_READINESS.md)
22. [Testing strategy](TESTING_STRATEGY.md)
23. [Known failures and limitations](KNOWN_FAILURES.md)
24. [Experiment log](EXPERIMENT_LOG.md)
25. [Roadmap](ROADMAP.md)
26. [Bounded orchestration loop](ORCHESTRATION_LOOP.md)
27. [Transactional autoresearch engine](AUTORESEARCH_ENGINE.md)
28. [Unattended operations control plane](UNATTENDED_OPERATIONS.md)
29. [Connection-bound DNS enforcement](CONNECTION_PINNING.md)
30. [Technical debt](TECHNICAL_DEBT.md)
31. [Milestone 31 scanner harness](MILESTONE_31_CONTROLLED_NUCLEI_EXECUTION_HARNESS.md)
32. [Detailed future requirement register](VULNHUNTER_FUTURE_MASTER_PLAN.md)
33. [Architecture decisions](../adr/README.md)

## Document authority

The master architecture is the canonical readable product blueprint, current status classification and dependency-ordered path to the finished product.

The chat-first workspace contract is binding for product delivery: every supported operation begins from, reports to and remains resumable through the authenticated conversation workspace.

The AI-first assessment workspace architecture owns required workspace behaviour and information architecture. It defines the single-assessment source of truth, live execution timeline, desktop and mobile shell, navigation, contextual inspector, APK path, failure language, assessment-scoped results and core definition of done.

The AI-first implementation standard is the non-duplicating code-level companion. It owns the root-cause map, canonical projection, create-or-bind boundary, lifecycle and retry contracts, frontend state ownership, design-token and CSS/JavaScript consolidation, accessibility thresholds and implementation evidence.

The premium interaction, motion and conversation experience standard owns the post-architecture interaction-quality programme. It defines motion semantics, complete component states, desktop pointer and mobile touch behaviour, authentication transitions, conversation sending/streaming/autoscroll, upload and task choreography, overlays, perceived performance, reduced motion and interaction-specific acceptance.

UI quality assurance owns browser-connected product truth, responsive behaviour, accessibility and visual evidence gates. A screenshot cannot prove completion when persisted state or allowed actions disagree.

The ML and Hugging Face production architecture owns the complete cross-layer path that joins governed releases, training packages, application-family partitions, feature extractors, calibration, abstention, OOD, evaluation, model registry, shadow deployment, monitoring, Hugging Face model profiles, embeddings, retrieval and evidence-grounded advisory output. It is a future implementation programme and does not mean these capabilities are already implemented.

The narrower ML documents retain distinct ownership:

- `ML_GOVERNANCE.md` owns authority, eligibility, promotion, activation, rollback, retirement and revocation;
- `docs/DATA_QUALITY.md` owns review integrity, application metadata, immutable release quality, corrections and training packages;
- `docs/ML_PIPELINE.md` owns implemented baseline mechanics and versioned feature/model interfaces;
- `docs/MODEL_SELECTION.md` owns development partitions, calibration/OOD selection, locked external evaluation and diagnostic metrics;
- `docs/product/AI_ROUTING.md` owns deterministic-first privacy and provider routing;
- `docs/product/LLM_RUNTIME_READINESS.md` owns exact deployed provider/model capability verification.

The current-state document is the only place that may claim a capability is implemented, partial, unavailable or blocked. Architecture documents describe required behaviour. Documentation alone never changes current-state classification.

The future master plan and atomic coverage documents preserve detailed requirement history and supporting evidence.

## Mandatory implementation sequence

Future agents must preserve this order:

1. finish any real active bounded implementation pull request;
2. complete the AI-first assessment workspace programme;
3. complete the premium interaction, motion and conversation programme;
4. execute the ML and Hugging Face production programme through its dependency-ordered slices;
5. continue the next unfinished production-readiness item from the authoritative roadmap.

Do not add transformer, embedding or model-generated product experiences before the assessment source of truth, lifecycle, evidence identity and responsive workspace are correct.

Do not replace the transparent local baseline merely because a larger Hugging Face model exists.

## Non-duplication rule

Do not create another document that claims to own:

- assessment lifecycle or workspace projection;
- interaction/motion programme;
- UI/browser quality gate;
- ML governance or promotion;
- governed dataset release quality;
- training/model-selection mechanics;
- provider routing;
- runtime model readiness;
- the cross-layer ML/Hugging Face production programme.

Update the existing owner instead. When a cross-cutting change affects several owners, update all affected documents in the same implementation sequence.

## Maintenance rule

A milestone that changes architecture, security boundaries, data contracts, model behaviour, quality gates, current status, remaining delivery order, conversation workflow, assessment projection, task activity, responsive behaviour, navigation, inspector behaviour, findings/evidence/report presentation, terminology, frontend state ownership, design tokens, component states, motion, loading, streaming/autoscroll, mobile direct manipulation, accessibility, dataset release lineage, application-family grouping, feature extraction, calibration, OOD, abstention, model registry, shadow deployment, drift monitoring, Hugging Face model identity, embeddings, retrieval, citations, provider routing or runtime readiness must update the corresponding owner in the same sequence.

At minimum, reconcile:

- `VULNHUNTER_MASTER_ARCHITECTURE.md` when top-level architecture or delivery order changes;
- `docs/product/CHAT_FIRST_WORKSPACE.md` when conversation ownership changes;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_ARCHITECTURE.md` when required workspace behaviour changes;
- `docs/product/AI_FIRST_ASSESSMENT_WORKSPACE_IMPLEMENTATION_STANDARD.md` when implementation mechanics or core acceptance evidence changes;
- `docs/product/PREMIUM_INTERACTION_MOTION_AND_CONVERSATION_EXPERIENCE.md` when interaction or motion requirements change;
- `docs/product/UI_QUALITY_ASSURANCE.md` when browser, responsive or accessibility gates change;
- `ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md` when cross-layer ML/Hugging Face architecture, sequencing or invariants change;
- `ML_GOVERNANCE.md` when eligibility, authority, registry states, promotion, activation, rollback or revocation changes;
- `docs/DATA_QUALITY.md` when review, application metadata, release/package, correction or external-dataset policy changes;
- `docs/ML_PIPELINE.md` when feature, model, artifact, prediction or monitoring contracts change;
- `docs/MODEL_SELECTION.md` when partition, calibration, OOD, metric or external-evaluation policy changes;
- `docs/product/AI_ROUTING.md` when task/data/provider routing or privacy rules change;
- `docs/product/LLM_RUNTIME_READINESS.md` when provider/model capability, revision, token, streaming, citation or supply-chain readiness changes;
- `CURRENT_STATE.md` with implemented status only;
- `KNOWN_FAILURES.md` when a limitation is added, narrowed or resolved;
- `ROADMAP.md` when dependency order changes.

## Repository audit

Run the repository audit after meaningful changes:

```bash
python scripts/project_audit.py
```

Generated audit files are written to:

```text
artifacts/project-audit/
```

Generated audit outputs are operational artifacts and do not become the source of truth. Maintained Markdown notes remain authoritative.