# Known Failures and Limitations

## 1. Initial baseline model under-detected confirmed findings

The first controlled benchmark baseline produced high precision but very low recall. The pipeline worked, but the model predicted the confirmed class too rarely to be practically useful.

Response:

- preserve the weak artifact as an honest baseline;
- add privacy-safe features;
- compare estimators and thresholds using training scans only;
- inspect locked-holdout errors without tuning against them.

## 2. Synthetic benchmark performance is not real-world performance

The controlled benchmark uses known scenarios and deliberately structured signals. Strong scores validate experiment plumbing and reproducibility, not generalisation to real applications.

## 3. Historical DNS time-of-check/time-of-use gap — resolved

Earlier releases revalidated DNS before a request but allowed the HTTP stack to resolve the hostname again while opening the socket. The transport now resolves at connection time, connects directly to an approved IP, verifies the peer, preserves the original hostname for HTTP/TLS, and disables keep-alive reuse between independently pinned requests.

## 4. Passive observations do not prove exploitability

Missing headers, debug indicators, directory-style pages, and technology disclosures require context. VulnHunter intentionally keeps deterministic verification and human review authoritative.

## 5. Real application diversity remains limited

The control plane can govern diverse campaigns, but the project has not yet produced a sufficiently broad real dataset spanning frameworks, deployment stacks, authentication states, proxies, custom errors, and application families.

## 6. Historical and benchmark single-review labels remain

New governed real observations require two authenticated assigned reviewers and, when needed, an independent adjudicator. Historical and controlled benchmark labels remain single-review records for reproducibility and cannot qualify for a governed campaign release without matching attestations.

## 7. Local artifact lifecycle is not fully operationalised

Databases, campaign releases, scanner evidence, model artifacts, and experiment evidence are local operational files. Formal backup, retention, migration, external signing, restore, and release procedures remain future work.

## 8. Web UI is implemented but not every backend capability has a browser write contract

The authenticated Django console covers dashboard, authorizations, assessments, approvals, findings, review, adjudication, campaigns, releases, datasets, intelligence status, reports, audit, tools, roles, skills, settings, mobile static analysis, and controlled active validation.

The interface deliberately remains read-only where the backend does not expose a safe write contract. In particular:

- release assessment does not provide a publication button;
- dataset quality does not start export or training;
- intelligence pages do not start inference, training, graph refresh, or model promotion;
- opening a scanner page does not activate the worker;
- dynamic Android execution remains environment-gated.

This is intentional fail-closed behaviour, not a decorative missing control.

## 9. Finding detail is bounded by the current product read model

The finding workspace can display only fields and artifacts exposed by the authenticated product service. Evidence retained internally but absent from the read model remains unavailable to the browser until a reviewed, redacted contract is added.

## 10. Orchestration and research isolation are not kernel sandboxes

Fixed shell-free verifiers, worktrees, protected hashes, role separation, and deterministic rejection make evaluator gaming visible, but repository code still runs under the local account. Stronger isolation requires a dedicated low-privilege user, container, VM, or operating-system sandbox.

## 11. Outer-loop guidance is intentionally non-executable

The meta-search layer proposes strategy changes rather than injecting Python. This limits autonomy but prevents the outer loop from mutating its evaluator or security boundaries.

## 12. Runtime permissions do not replace operating-system controls

The unattended control plane enforces tools, paths, commands, network, connectors, secrets, and destructive permissions in application code. It cannot protect the host from code that already executes with equivalent operating-system privilege.

## 13. Local authentication is not external identity proof

Reviewer secrets use scrypt and actions are identity-bound, but the local registry does not provide SSO, MFA, hardware-backed keys, independent proof that separate accounts belong to separate people, or protection from a compromised administrator account.

## 14. Campaign integrity is hash-based, not digitally signed

Campaign records, assignments, attestations, releases, and events detect local database tampering through deterministic hashes and a hash chain. They are not yet signed by an independently protected external key, so portable authenticity and non-repudiation are not established.

## 15. Historical scan-completion correlation gap — resolved

Earlier governed scan linking matched scan completion primarily by scan ID and event order after a matching start event. The authorization completion event now binds the authorization ID, normalized scan database, scan ID, normalized target URL, and persisted scan snapshot hash. Campaign linking fails closed when that tuple is missing, malformed, mismatched, or ordered before the matching start event.

## 16. Real-world model evidence is still absent

The governed collection workflow is implemented, but meaningful performance claims require actual collection across diverse authorized applications, independent review, application-group-isolated development and holdout sets, and an untouched external evaluation.

## 17. Optional advisory analysis is non-authoritative and environment-dependent

The platform remains usable without an advisory provider. Provider reachability, quota, approved-model availability, privacy acceptance, and operator activation remain external dependencies. Failure or malformed output must result in abstention and cannot change authorization, verification, review, adjudication, or release state.

## 18. Production deployment acceptance remains outstanding

The repository contains secure defaults, private secret-file support, health and readiness checks, and deployment examples. A real production environment still requires independent acceptance for TLS, proxy headers, database backups, worker isolation, evidence retention, logging, key rotation, monitoring, rollback, and incident response.

## 19. Assessment state can contradict across browser surfaces

A direct phone and desktop-site product review on 2026-08-02 exposed a case in which an APK could be uploaded, validated, shown in the graph and queued for static analysis while the assessment inspector still reported `No active assessment`, assessment history reported zero runs, findings reported zero, and a later chat message reported that the worker failed.

This is not merely a visual defect. The user cannot identify which surface is authoritative or whether the assessment was created and preserved.

Required response:

- establish one stable assessment identity immediately after artifact validation;
- bind chat, activity, inspector, history, findings, evidence, graph and reports to the same assessment projection;
- add invariant tests that prevent artifact-owned content from appearing under `No active assessment`;
- preserve partial evidence and terminal state across reconnects;
- implement the dependency-ordered AI-first workspace programme.

## 20. The conversation can repeat already satisfied prerequisites

The assistant can ask the user to upload an APK or explain the future upload workflow while the selected APK is already uploading or complete.

This occurs when model or fallback prose is generated without first resolving authoritative workspace and assessment state.

Required response:

- compose operational responses from the persisted workspace projection;
- verify that a required input is genuinely absent before requesting it;
- separate model explanation from backend state and allowed actions;
- add tests for in-progress, completed, replacement and resumed uploads.

## 21. Worker failures are too generic to support recovery

The current user-facing failure may state only that a governed worker did not complete. It does not consistently identify failed stage, tool, attempt, reason category, preserved evidence, retry boundary, or operator action.

Required response:

- introduce typed product error categories;
- expose a redacted failure reference;
- show completed and preserved work;
- offer retry only when the backend supports safe idempotent retry;
- retain prior failure receipts after a new attempt.

## 22. Long-running work lacks one coherent live task experience

Upload banners, cards, toasts, chat replies, inspector state and global pages can all describe the same operation differently. The user does not receive one credible timeline of completed, active, waiting, blocked and terminal stages.

Required response:

- project persisted activity into one updating task card;
- use understandable stages by default;
- expose technical node and worker details under an expandable activity view;
- show progress percentages only when measured from bytes or declared weighted stages;
- deduplicate activity events and visual indicators.

## 23. Mobile layout can compress the desktop inspector beside chat

Some phone screenshots show a deliberate mobile layout, while others show desktop conversation and inspector compressed into a narrow viewport. This produces tiny text, clipped actions, unreadable tables, horizontal overflow, and competition between composer, bottom navigation and keyboard.

Required response:

- use one responsive shell;
- make the inspector a full-screen sheet, route or appropriate bottom sheet on phone;
- transform tables into cards;
- prevent horizontal overflow;
- verify keyboard, Android Back, safe area, long text and desktop-site simulation;
- preserve chat position when opening and closing specialist views.

## 24. Navigation contains competing duplicates

Findings and Graph are available in more than one primary navigation system, while Analysis, Evidence, Reports and History appear both contextually and globally. The user cannot tell whether these views share state.

Required response:

- assign one primary location to each concept;
- use Chat, Activity, Findings and More as the mobile primary set;
- make desktop inspector tabs assessment-scoped;
- keep global Findings and Reports as cross-assessment indexes only;
- show Graph only when meaningful graph data exists.

## 25. The composer exposes too much infrastructure

The primary message area exposes attachment, reasoning level, provider selection, provider status, prompt history, explanatory text, character count and bottom navigation simultaneously. The keyboard can reduce usable conversation space further.

Required response:

- retain attachment, text, mode and send as primary controls;
- move provider and advanced configuration behind progressive disclosure;
- show character count near the limit only;
- show worker state in the task card and provider readiness in settings;
- add keyboard-open responsive acceptance.

## 26. Governance terminology dominates normal task meaning

Correct internal phrases such as canonical worker state, persisted receipts, exact snapshot, gated worker and release gate appear before ordinary user language. This makes the product feel like an audit console rather than an AI assistant, even when the underlying control works correctly.

Required response:

- use ordinary task language in the primary layer;
- retain exact policy, digest, receipt and worker terminology under details;
- never hide a decision the user must make;
- standardise terminology across chat, activity, findings, evidence and report.

## 27. Empty and report pages are disconnected from the selected task

Zero-data pages use large repeated metric cards, while Reports may show a seeded pilot record unrelated to the selected user assessment. A user can therefore see an apparently valid report while the active APK operation has no clear report state.

Required response:

- use compact contextual empty states;
- filter contextual findings, evidence and reports to the selected assessment;
- display exact unmet requirements for each report format;
- label and separate seeded/demo records from user work;
- return all specialist views to the owning conversation and assessment.

## 28. Production training is not yet bound to immutable governed dataset releases

The repository has governed campaign releases and separately has a reviewed-observation ML pipeline, but production-mode training does not yet require a verified immutable release as its direct source.

A mutable database query can change after training because labels, records, membership or metadata change. Dataset SHA-256 protects the extracted content but does not by itself prove that the content came from an approved release or remains permitted for production use.

Required response:

- define a content-addressed ML training package derived from one or more compatible governed releases;
- require release ID, manifest digest, campaign/authorisation provenance and review/adjudication attestations;
- retain research-mode local exports with an explicit research-only classification;
- fail closed on withdrawn, revoked, corrected or incompatible releases;
- add release lineage to model artifacts and registry entries;
- implement correction-to-model impact discovery.

## 29. Scan-group isolation does not prove application-family generalisation

The current splitter correctly prevents one scan from crossing training and holdout. Separate scans of the same application can still cross those partitions.

The model may learn application routes, wording, deployment fingerprints, repeated detector output or benchmark structure instead of transferable evidence patterns.

Required response:

- add stable application-family, instance and environment identifiers;
- group related benchmark variants and repository revisions;
- create development training, development calibration and locked external family partitions;
- keep complete families out of development when assigned to external holdout;
- report honestly when data cannot support external family evaluation;
- preserve partition assignment across compatible releases.

## 30. The current binary prediction contract forces every input into one class

The implemented classifier returns either `confirmed` or `false_positive` after applying a threshold.

Security decision support needs an explicit `abstain` outcome for unfamiliar, incomplete, uncertain or degraded inputs. Treating uncertainty as false-positive-like can hide findings.

Required response:

- introduce an advisory task contract separate from review labels;
- add `prioritise_review`, `normal_review` and `abstain` decisions;
- preserve raw score, calibrated score, OOD score, feature coverage and reason codes;
- route abstentions to human review;
- prevent abstention from becoming a stored false-positive label.

## 31. Raw Naive Bayes posterior is not calibrated real-world confidence

The current posterior is useful for ranking and thresholding, but it is not evidence that a displayed value such as 0.90 corresponds to a 90% real-world success rate.

Naive Bayes may be sharply overconfident because feature-independence assumptions do not hold.

Required response:

- call current values raw scores/posteriors;
- create versioned calibrator artifacts bound to exact models;
- select calibration using development groups only;
- report Brier score, log loss, expected/max calibration error and reliability data;
- evaluate calibration by family, category and severity;
- never present calibrated language without measured calibration evidence.

## 32. Out-of-distribution handling is not implemented

The current pipeline can encounter unseen categories, detector revisions, evidence schemas, application families or token patterns without one explicit production OOD policy.

Unknown values can simply produce absent/zero feature indicators and a forced binary prediction.

Required response:

- emit unknown-category/detector/schema and feature-coverage indicators;
- define deterministic baseline OOD signals before complex learned detectors;
- test intentionally excluded families, categories, templates and malformed inputs;
- bind OOD policy to model/extractor/release identity;
- convert unsupported-domain conditions to abstention rather than negative classification.

## 33. Current evaluation is incomplete for reviewer prioritisation

Accuracy, precision, recall, F1 and confusion counts are implemented, but the product's practical value includes ordering review work.

A classifier can have acceptable F1 while ranking urgent confirmed findings poorly, or vice versa.

Required response:

- add PR-AUC, precision at K, recall at K and fixed review-budget recall;
- report number needed to review;
- report severe false negatives;
- measure coverage and error after abstention;
- include grouped uncertainty and multiple seeds;
- preserve classification and ranking claims as separate conclusions.

## 34. Feature and detector leakage has not been fully ruled out

Current features include category, severity, generated title/description tokens and selected detector evidence. These can encode the detector's own conclusion or application identity.

Strong internal performance can therefore reflect memorisation rather than evidence generalisation.

Required response:

- structural-evidence-only baseline;
- no-category, no-severity and no-generated-text ablations;
- leave-one-detector-out and leave-one-template-family-out evaluation;
- leave-one-application-family-out evaluation;
- report candidate degradation and reject misleading feature families;
- keep feature selection entirely within development data.

## 35. A production model registry and activation lifecycle do not yet exist

The repository records strong model artifact provenance, but it does not yet provide a complete registry lifecycle with candidate, validated, approved, shadow, active, degraded, retired and revoked states.

Placing or selecting a model file is not sufficient production activation control.

Required response:

- immutable registry entries with model, extractor, calibrator, OOD, release, partition, code and dependency digests;
- separate evaluation, promotion and deployment authority;
- atomic activation;
- tested complete-package rollback;
- revocation and degradation;
- active model reconstruction after restart;
- historical prediction provenance that survives rollback.

## 36. Shadow deployment and delayed outcome comparison are not implemented

A new model cannot yet run safely beside the active baseline while remaining invisible to reviewers and later joining to governed human outcomes.

Required response:

- separate active and shadow prediction records;
- no shadow effect on user-visible order or state;
- delayed joins to consensus/adjudicated labels;
- active-shadow disagreement and abstention reports;
- bounded canary phase with easy disable and rollback;
- no automatic traffic expansion.

## 37. Model monitoring, drift and incident response are incomplete

Offline holdout diagnostics exist, but production model-quality monitoring is not implemented.

Required response:

- separate service, model, extractor, input and assessment health;
- monitor latency, failure, score, OOD, abstention and coverage distributions;
- monitor family/category/detector mix and delayed reviewer outcomes;
- preserve privacy-safe aggregates;
- define incidents for artifact corruption, release revocation, privacy leak, calibration failure, critical false-negative clusters and cross-tenant retrieval;
- support disable, degrade, rollback and revoke;
- never automatically retrain or activate from drift.

## 38. Hugging Face model allowlists are not yet exact revision capability profiles

The remote Hugging Face provider safely restricts model names and endpoint, but a model repository/name alone can change over time and does not describe supported parameters or tokenizer identity.

Required response:

- exact repository/model and revision where available;
- tokenizer repository/revision;
- license/model-card/terms/retention review;
- structured-output, streaming, context and parameter capability matrix;
- model/tokenizer file digests for local use;
- configured, approved, capable, reachable and end-to-end-verified states;
- safe retirement/revocation;
- document limitations when a remote backend cannot expose immutable revision identity.

## 39. Provider health currently risks conflating configuration and reachability

A configured provider can be syntactically valid while the endpoint is unavailable. One current health description states that live reachability is verified on inference, so configuration must not be represented as current reachability.

Required response:

- separate enabled, credential-valid, model-approved, capability-verified and reachable;
- retain last success/failure and freshness;
- show stale/degraded states;
- keep deterministic operation available;
- avoid one ambiguous `AI ready` badge.

## 40. Token accounting is still conservative rather than exact per model

Byte limits are strong security controls, but conservative byte-to-token approximation may reject valid prompts or misjudge exact context capacity.

Required response:

- retain byte limits;
- use revision-pinned tokenizer where possible;
- otherwise validate provider token accounting;
- document approximation when exact accounting is unavailable;
- bind method to model capability profile;
- test Unicode, exact limits and structured truncation.

## 41. Bounded streaming advisory responses are not implemented

The current Hugging Face provider uses non-streaming structured responses. This is safe but does not provide token-by-token chat delivery.

Streaming must not be enabled globally without model-specific capability and safety controls.

Required response:

- cumulative byte/token limits;
- cancellation and read timeout;
- incremental UTF-8 handling;
- interruption recovery;
- final structured validation and digest;
- no action from partial output;
- invalid partial stream becomes degraded/abstain;
- product UI does not retain failed partial output as authoritative success.

## 42. Assessment-scoped embeddings and retrieval are not implemented

There is no production vector index connecting assessment evidence, findings, remediation and conversation while enforcing tenant, role and assessment boundaries.

Required response:

- local-first embedding policy for private evidence/source;
- exact embedding model/revision and dimension;
- vector metadata for tenant/workspace/assessment/source/digest/visibility;
- permission filters before results are returned;
- stale/deleted/revision-change handling;
- retrieval quality evaluation;
- cross-tenant, prompt injection and malicious-content tests;
- deterministic lexical baseline comparison.

## 43. Evidence-grounded model citations are not yet implemented

The advisory model can answer from bounded redacted context, but assessment-specific factual claims do not yet use a complete citation contract that validates every cited object against the supplied context and selected assessment.

Required response:

- context records with object ID, digest, visibility and safe excerpt;
- citation labels included in prompts;
- verify cited IDs were supplied and remain authorised;
- reject invented or foreign-assessment citations;
- treat retrieved evidence and source comments as untrusted data;
- prevent citations from granting finding or lifecycle authority.

## 44. Local Hugging Face model supply-chain controls are not implemented

No local transformer/embedding model is currently part of the approved runtime. Future use introduces model weights, tokenizer files, dependencies and possible custom code.

Required response:

- exact repository/revision and file manifests;
- reviewed license and model card;
- `safetensors` preference;
- no arbitrary pickle loading;
- `trust_remote_code=False` by default;
- separate review/sandbox for any exception;
- dependency lock and SBOM;
- controlled cache and offline operation;
- digest verification, registry and revocation.

## 45. External vulnerability datasets have task, quality and leakage limitations

Public Hugging Face datasets such as unofficial BigVul mirrors, CodeXGLUE defect detection and synthetic security preference pairs can help test pipelines or representations, but do not represent VulnHunter's governed product domain automatically.

Required response:

- record official/unofficial source and license;
- classify synthetic versus human-labelled;
- inspect repository/function/commit duplicates;
- prevent repository and temporal leakage;
- preserve language/task distribution;
- keep public benchmark results separate from governed real external evaluation;
- never use popularity/download count as quality evidence.

## 46. Source Hunt code-model evaluation is not established

The existing Source Hunt architecture protects exact repository revision, snapshot and approval, but no Hugging Face code encoder has yet proven value against lexical and native graph baselines.

Required response:

- exact snapshot-bound code retrieval experiments;
- lexical and graph baselines;
- exact model/tokenizer revisions;
- code/symbol/vulnerable-function retrieval metrics;
- cross-repository and language evaluation;
- path/hash/line validation;
- no automatic vulnerability verification, patch, merge or deployment.

## 47. Documentation now defines the ML/Hugging Face programme but code remains unchanged

The detailed programme in `ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md` and its owner documents is architecture and planning evidence only.

It does not mean release-bound training, calibration, OOD, model registry, shadow deployment, monitoring, local embeddings or evidence citations have been implemented.

Required response:

- preserve truthful current-state classifications;
- implement dependency-ordered bounded pull requests only after earlier mandatory product programmes;
- add tests and machine-readable evidence with every slice;
- update this document as each limitation is narrowed or resolved;
- never close a limitation merely because its desired design was documented.