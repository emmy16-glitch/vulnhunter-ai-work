# VulnHunter AI — Master Architecture and End-to-End Delivery Plan

**Canonical current-to-finished product blueprint**  
**Owner:** Emmanuel Okunlola  
**Repository:** `emmy16-glitch/vulnhunter-ai-work`  
**Baseline reviewed:** `main` at `cc8b33735b74d05b286ebdd2f780176d592e202d`  
**Created:** 2026-07-31  
**Status:** Active master architecture and remaining-work sequence

---

## 0. Purpose and authority of this document

This file answers four questions in one place:

1. What is the finished VulnHunter product supposed to be?
2. What has already been implemented and must not be rebuilt?
3. What exists only partially, is not connected, requires activation, or has not been implemented?
4. What exact steps remain, in dependency order, until the finished product is accepted?

This document is the **canonical readable product blueprint and execution order**. It does not erase the detailed requirements in `VULNHUNTER_FUTURE_MASTER_PLAN.md`, the atomic coverage rows in `TOTAL_PROGRAMME_CANONICAL_COVERAGE_MATRIX.md`, or the security rules in `AGENTS.md`. Those remain supporting authority.

When documents disagree, use this order:

1. `AGENTS.md` for binding security and engineering rules;
2. this file for finished-product architecture, current classification, and execution order;
3. current implementation and tests as evidence of what actually exists;
4. focused product and intelligence documents for subsystem contracts;
5. historical trackers and handoffs for provenance only.

A future coding agent must begin by reading this file, `CURRENT_STATE.md`, `KNOWN_FAILURES.md`, and the relevant subsystem documentation before changing code.

### Status language

| Status | Meaning |
|---|---|
| `DONE` | Implemented in the repository with documented verification evidence. It is removed from the remaining-work queue unless a regression is found. |
| `PARTIAL` | A real foundation exists, but an important workflow, integration, language, environment, or acceptance gate remains. |
| `ACTIVATION_REQUIRED` | Code and contracts exist, but an operator-controlled environment, credential, tool, worker, privacy decision, or readiness check is still required. |
| `NOT_CONNECTED` | Components exist separately but the finished end-to-end product path is not connected and accepted. |
| `NOT_IMPLEMENTED` | No sufficient production implementation exists yet. |
| `LATE_STAGE` | Work is intentionally blocked until data, safety, evaluation, or operational prerequisites are satisfied. |
| `EXCLUDED` | The capability is outside the approved product boundary and must not be silently introduced. |

A feature is not `DONE` merely because a class, page, adapter, prompt, or test double exists. Completion requires the real intended path, failure behaviour, tests, documentation, and any declared acceptance evidence.

---

# 1. Finished product definition

VulnHunter AI will be a **local-first, evidence-driven, human-governed security assessment and verification platform** for explicitly authorised work.

The finished product will provide one coherent workspace for:

- authorised website assessment;
- source-repository security analysis;
- Android APK static, native, and controlled dynamic analysis;
- bounded binary and artifact inspection;
- evidence-backed candidate findings;
- deterministic and machine-oracle verification;
- independent review, adjudication, remediation, retesting, and release;
- controlled security knowledge retrieval;
- model-assisted planning and analysis without model authority;
- governed dataset creation, evaluation, learning, and model improvement;
- private deployment from desktop or phone-controlled infrastructure.

The product must remain useful in three modes:

```text
DETERMINISTIC-ONLY
No model is available. Authorisation, scanning, evidence, review and reporting still work.

LOCAL-INTELLIGENCE
A reviewed local model assists with planning, retrieval and analysis.

CONTROLLED-REMOTE-FALLBACK
An explicitly approved remote provider receives only permitted, bounded and sanitised material.
```

The finished product is **not** an autonomous public-Internet scanner, unrestricted exploitation framework, credential attack platform, automatic vulnerability publisher, or replacement for qualified human review.

---

# 2. Non-negotiable authority model

The permanent authority chain is:

```text
Human authorises exact work
        ↓
VulnHunter validates identity, scope and policy
        ↓
Model may propose a bounded plan
        ↓
VulnHunter creates an immutable action manifest
        ↓
Human approval is consumed where required
        ↓
Restricted worker or deterministic tool collects evidence
        ↓
VulnHunter validates, hashes, redacts and persists evidence
        ↓
Model may analyse or challenge the evidence
        ↓
Deterministic verifier or machine oracle tests the claim
        ↓
Independent human review and adjudication determine meaning
        ↓
Authorised release service may publish an approved result
```

The model must never own:

- target authorisation;
- scope expansion;
- scanner activation;
- shell or unrestricted connector access;
- exploit permission;
- evidence integrity;
- finding confirmation;
- final severity or business impact;
- reviewer or adjudicator decisions;
- source-code merge;
- dataset release;
- model promotion;
- deployment;
- publication.

Permanent rule:

> Models propose. VulnHunter verifies and enforces. Humans retain final authority.

---

# 3. Finished master architecture

```text
┌──────────────────────────────── EXPERIENCE PLANE ────────────────────────────────┐
│ Responsive web workspace • CLI • phone-controlled private lab • future API     │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │
┌──────────────────────────── IDENTITY AND GOVERNANCE PLANE ──────────────────────┐
│ Django identity • governed identities • roles • step-up auth • approvals       │
│ target authorisations • campaigns • review assignments • adjudication          │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │
┌──────────────────────────────── CONTROL PLANE ───────────────────────────────────┐
│ Workspace service • policy engine • immutable plans • task graph • budgets      │
│ pause/cancel • deadlines • worker leases • threat containment • audit ledger    │
└───────────────────────┬───────────────────────────────┬─────────────────────────┘
                        │                               │
┌───────────────────────▼──────── EXECUTION PLANE ──────▼─────────────────────────┐
│ Signed worker spool • local/remote Nuclei worker • source worker • APK worker   │
│ static/native tools • disposable dynamic lab • approved machine-oracle workers │
│ no arbitrary shell • fixed typed adapters • resource and egress boundaries     │
└───────────────────────┬───────────────────────────────┬─────────────────────────┘
                        │                               │
┌───────────────────────▼──────── INTELLIGENCE PLANE ───▼─────────────────────────┐
│ Deterministic mapper • rules • current Naive Bayes classifier • context broker │
│ repository graph • governed RAG • provider gateway • local VulnHunter model    │
│ optional controlled Groq fallback • critic/falsifier • abstention              │
└───────────────────────┬───────────────────────────────┬─────────────────────────┘
                        │                               │
┌───────────────────────▼──── EVIDENCE AND ASSURANCE PLANE ───────────────────────┐
│ Evidence store • provenance • candidate findings • proof capsules              │
│ deterministic verification • active validation • independent review            │
│ adjudication • remediation • retest • signed report/release                    │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │
┌──────────────────────────── DATA AND LEARNING PLANE ─────────────────────────────┐
│ Reviewed campaigns • deduplication • group-isolated splits • locked holdouts    │
│ evaluation registry • feedback candidates • promotion • fine-tuning • rollback │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │
┌──────────────────────────── OPERATIONS AND TRUST PLANE ──────────────────────────┐
│ PostgreSQL • object/evidence storage • signing keys • backup/restore             │
│ monitoring • incident response • deployment manifests • release provenance      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

Cross-cutting controls apply to every plane:

- explicit authorisation;
- least privilege;
- redaction before persistence or remote routing;
- immutable hashes and audit events;
- exact source, target, tool and version binding;
- bounded time, memory, storage, token and tool-call budgets;
- truthful disabled, unavailable, blocked and abstained states;
- independent verification and human review;
- rollback and recovery.

---

# 4. Canonical product workflows

## 4.1 Website assessment

```text
Authenticated operator
→ exact existing authorisation or permitted private-lab authorisation creation
→ immutable passive plan
→ digest-bound confirmation or independent approval
→ signed worker job
→ private-lab Nuclei or bounded HTTP collection
→ normalised redacted evidence
→ candidate findings
→ deterministic verification
→ optional approved active validation
→ two-person review or adjudication
→ remediation and retest
→ governed report and release
```

The finished website path may support additional reviewed scanners, but all must reuse the same authorisation, plan, worker, evidence and review control plane.

## 4.2 Source-repository assessment

```text
Operator-approved repository root
→ exact revision and content snapshot
→ secret detection and eligible-path inventory
→ exact source-processing approval where remote intelligence is used
→ deterministic entry-point, call-path, guard and sink mapping
→ bounded context retrieval
→ model reconnaissance and attack-path hypothesis
→ separate falsification and capability filter
→ candidate finding with real file/hash/line evidence
→ RED security test and minimal remediation proposal
→ developer-led isolated patch
→ read-only deterministic fix verification
→ independent review and controlled merge
```

The finished path must support multiple declared languages without pretending unsupported languages are covered.

## 4.3 Android APK assessment

```text
Resumable upload
→ archive, size, quota and SHA-256 validation
→ immutable artifact record
→ static manifest/package/signature inspection
→ decompilation and static code/resource analysis
→ native-library analysis when present
→ evidence correlation and candidate findings
→ optional disposable MobSF/emulator/ADB/Frida laboratory
→ deterministic or oracle verification
→ human review, remediation advice and retest
→ governed report
```

An uploaded APK is never executed merely because it was uploaded.

## 4.4 Finding lifecycle

```text
OBSERVATION
→ CANDIDATE
→ MACHINE_VERIFIED or ABSTAINED
→ HUMAN_CONFIRMED / HUMAN_REJECTED / DISPUTED
→ ADJUDICATED when required
→ REMEDIATION_PROPOSED
→ RETESTED
→ RELEASE_APPROVED
→ PUBLISHED or ARCHIVED
```

Model output alone cannot advance a finding to a trusted state.

## 4.5 Knowledge and model workflow

```text
Approved source
→ immutable original and provenance
→ sanitisation and trust review
→ chunking or graph extraction
→ embedding/index generation
→ retrieval evaluation
→ bounded context supplied to a model
→ cited advisory output
→ human feedback candidate
→ review and deterministic evaluation
→ controlled promotion to memory or training data
```

---

# 5. Implemented foundation — do not rebuild

The following foundations already exist and are removed from the remaining implementation queue unless verification finds a regression.

## 5.1 Security, authorisation and network boundaries — `DONE`

- strict private-laboratory target validation;
- explicit, time-limited and revocable authorisation records;
- immutable target and scoped-URL trust-boundary models;
- redirect containment and path/port/scheme enforcement;
- connection-time DNS revalidation, approved-address TCP pinning and peer checks;
- request budgets, cancellation, rate limits, timeouts and body limits;
- central sensitive-data redaction;
- append-only authorisation and audit evidence.

## 5.2 Unified authenticated product workspace — `DONE`

- one responsive website/APK conversational assessment workspace;
- authenticated Django sessions, CSRF protection and role-aware navigation;
- durable concurrent workspaces and conversation state;
- exact approval, activity, evidence, finding and run visibility;
- desktop, tablet and phone layouts;
- stale-CSRF recovery and resumable upload controls;
- truthful persisted states rather than fabricated progress.

## 5.3 Controlled private-lab scanner path — `DONE` for the declared pilot

- immutable passive Nuclei plans;
- signed manager-to-worker spool with expiry and replay protection;
- separate local or restricted remote worker process;
- fixed passive template, private target, rate `1`, concurrency `1` pilot;
- bounded output, cancellation, cleanup, restart recovery and evidence hashing;
- genuine private-lab acceptance coverage.

This does not mean unrestricted or public scanning is implemented.

## 5.4 Evidence, findings and human review — `DONE` foundation

- redacted observations and evidence provenance;
- candidate finding records;
- deterministic verification and proof-capsule foundations;
- two independent primary reviews;
- independent adjudication for disagreement;
- identity-bound attestations and governed release gates;
- evidence-backed remediation and read-only fix-verification foundations.

## 5.5 Source Hunt Python production slice — `DONE` foundation

- exact repository revision and snapshot binding;
- path-bound, expiring Groq source-processing approval;
- separate file-backed worker queue;
- deterministic Python inventory, entry-point, guard, call-path and sink mapping;
- bounded Groq reconnaissance, hypothesis, falsification, capability filtering and remediation proposal;
- source hash and line-reference integrity enforcement;
- no automatic patching or merge authority.

## 5.6 APK ingestion and static-worker foundation — `DONE` foundation

- resumable APK upload;
- archive, quota, disk, final digest and artifact validation;
- immutable artifact inventory;
- networkless, read-only static worker contract;
- fixed adapters for signature, package, manifest, decompilation, static and native inspection;
- independent tool receipts and safe partial-tool failure handling.

## 5.7 Agent, task and approval control foundations — `DONE`

- typed task and action manifests;
- deadlines, explicit terminal states and immutable transitions;
- operator pause/resume and cooperative cancellation checkpoints;
- exact Approval Centre consumption;
- task-graph revision/CAS and bounded worker leases;
- immutable activity and audit streams;
- agentic-threat sequence detection and containment foundations;
- bounded engineering orchestration and independent verifier roles.

## 5.8 Intelligence and data foundations — `DONE` as plumbing

- deterministic-first provider routing;
- Groq-only current production provider contract, disabled by default;
- native repository graph and typed context broker foundations;
- controlled knowledge-store and learning-candidate promotion controls;
- reviewed dataset export, deduplication and scan-group-isolated splits;
- deterministic Naive Bayes training, tuning, metrics and provenance;
- locked-holdout and synthetic-benchmark safeguards.

These foundations do not establish real-world model accuracy.

## 5.9 Controlled active validation — `DONE` for synthetic scenarios

- exact plan approval with requester/approver separation;
- generated-data-only scenarios;
- networkless disposable workspace;
- bounded retries, evidence hashes, cancellation and cleanup verification;
- persisted truthful activity;
- workspace-bound child task graph tied to the parent assessment, exact finding, authorisation, reviewed scenario and immutable plan digest;
- browser-independent projection of approval, queue, worker, evidence evaluation, cancellation and failed-closed states back into the originating chat workspace.

This is not general exploitation or production-target validation.

---

# 6. Current gaps and unconnected areas

| Area | Current classification | What remains before finished acceptance |
|---|---|---|
| Master architecture and delivery order | `DONE` by this document | Keep it updated in every architecture-changing milestone. |
| Documentation/current-state reconciliation | `PARTIAL` | Older trackers and roadmap summaries must be reconciled with the later workspace, Source Hunt, APK and Groq commits. |
| Educational LLM from scratch | `NOT_IMPLEMENTED` | Build an isolated learning lab for tokenizer, embeddings, attention, transformer training and generation. |
| Production local model | `NOT_IMPLEMENTED` | Add a disabled local provider contract, benchmark it, and retain deterministic operation. |
| VulnHunter-owned security model | `LATE_STAGE` | Build reviewed data, evaluation and fine-tuning before considering domain pretraining or a foundation model. |
| Governed vector RAG | `PARTIAL` | Finalise source registry, chunking, embedding/version contracts, vector storage, retrieval evaluation and citation integrity. |
| Current Groq activation | `ACTIVATION_REQUIRED` | Owner-private key, model allowlist, privacy/retention acceptance, quota and harmless-response tests. |
| General agent-to-tool integration | `PARTIAL` | Website, APK, Source Hunt and Active Validation now use workspace-bound authoritative task graphs; remediation, retest, downstream evidence completion, verification, review and reporting still require migration. |
| Website private-lab pilot | `DONE` for narrow pilot | Add release-quality repeat acceptance and selected additional passive adapters only if justified. |
| OpenVAS or additional website scanners | `NOT_IMPLEMENTED` | Select exact versions/feeds/isolation, implement the shared protocol adapter and acceptance suite. |
| APK medium/large full static acceptance | `PARTIAL` | Run complete configured toolchain against representative authorised artifacts and record resource behaviour. |
| Dynamic Android laboratory | `NOT_CONNECTED` | Provision disposable emulator/device identity, private MobSF, ADB/Frida policy, egress control, cleanup and acceptance. |
| Native binary/reverse-engineering depth | `PARTIAL` | Complete reviewed Ghidra/radare/binutils adapters, evidence parsers and representative acceptance. |
| Source Hunt language coverage | `PARTIAL` | Add one language at a time with deterministic parsing, framework-aware entry points, sinks and false-positive evaluation. |
| Repository coverage/impact analysis | `PARTIAL` | Incremental changed-region coverage, impact paths, staleness and optional Graphify comparison remain. |
| Machine-oracle operational connectors | `PARTIAL` / `ACTIVATION_REQUIRED` | Add real read-only or safely reversible oracle connectors, authenticated replay protection and acceptance evidence. |
| Finding detail/read models | `PARTIAL` | Expose additional redacted evidence through reviewed browser contracts without leaking raw data. |
| Reporting and PDF | `PARTIAL` / `ACTIVATION_REQUIRED` | Final report schemas, PDF renderer activation, signed export manifests and release workflow. |
| Publication service | `NOT_IMPLEMENTED` | Add a dedicated human-authorised release contract; never expose a decorative publish button. |
| Real diverse dataset | `NOT_IMPLEMENTED` operationally | Collect governed data across multiple authorised application families and independently review every retained record. |
| Real-world model evaluation | `NOT_IMPLEMENTED` | Freeze external holdout, calibration, category/family analysis and repeated-run error analysis. |
| Controlled learning at scale | `PARTIAL` / `LATE_STAGE` | Retention, privacy, feedback evaluation, dataset release and rollback evidence before production learning. |
| Identity assurance | `PARTIAL` | SSO/MFA or equivalent, hardware-backed or independently protected keys, recovery and compromised-admin procedures. |
| Portable authenticity | `PARTIAL` | External digital signatures, key rotation, revocation and verification for releases, workers, evidence and models. |
| PostgreSQL and schema operations | `PARTIAL` / `ACTIVATION_REQUIRED` | Production migration rehearsal, concurrency tests, backup/restore and rollback proof. |
| Storage lifecycle | `PARTIAL` | Formal retention, deletion, legal/privacy policy, object/evidence storage and disaster recovery. |
| Monitoring and incident response | `PARTIAL` | Metrics, alerts, audit export, worker health, provider usage, storage pressure, security events and response runbooks. |
| Production hosting | `ACTIVATION_REQUIRED` | TLS, DNS, proxy, secrets, database, persistent storage, workers, monitoring and independent deployment acceptance. |
| Independent security assessment | `NOT_IMPLEMENTED` | Review the final deployment, workers, provider boundaries, auth, data lifecycle and supply chain. |
| Public Internet autonomous scanning | `EXCLUDED` | Remains outside the approved product boundary. |
| Destructive exploitation and credential attacks | `EXCLUDED` | Remains prohibited. |
| Automatic source patching and merge | `EXCLUDED` from model authority | Fixes remain bounded, developer-led, independently verified and human-merged. |

---

# 7. LLM and intelligence architecture

The LLM work must proceed in distinct layers. They must not be confused.

## 7.1 Layer A — Educational LLM laboratory

Purpose: understand exactly how an LLM works.

This laboratory will implement, with small code and tiny data:

```text
text corpus
→ tokenizer training
→ token IDs
→ embedding table
→ positional representation
→ self-attention
→ feed-forward network
→ transformer block
→ next-token logits and softmax
→ autoregressive generation
→ training loss and backpropagation
```

Rules:

- it lives outside production packages;
- it receives no VulnHunter tools, targets, secrets, evidence or authority;
- it is not described as a vulnerability model;
- its tests are deterministic and small enough for the development environment;
- each stage includes a plain-language learning note.

## 7.2 Layer B — Current production advisory model

Today, Groq is the only production model provider contract. It is optional, disabled by default and non-authoritative.

The current contract must remain intact until a reviewed migration explicitly changes it.

## 7.3 Layer C — Future local open-weight provider

The finished architecture should support a local model as the primary advisory provider while keeping deterministic-only operation.

Required contract:

- disabled by default;
- loopback/private endpoint only;
- exact model and digest allowlist;
- bounded context, output, timeout and concurrency;
- structured proposal/analysis/abstain output;
- no direct shell, scanner, network, browser or MCP access;
- privacy and prompt-injection filters;
- reproducible evaluation before promotion.

## 7.4 Layer D — VulnHunter Security Model

The practical first VulnHunter-owned model should be a fine-tuned or adapter-tuned open-weight model, not a foundation model trained from random weights.

Evolution path:

```text
VulnHunter-SecLM v0: educational tiny model, learning only
VulnHunter-SecLM v1: existing open-weight model + prompts + governed RAG
VulnHunter-SecLM v2: supervised fine-tuning or LoRA on reviewed VulnHunter traces
VulnHunter-SecLM v3: optional continued domain pretraining with licensed data
VulnHunter-SecLM v4: from-scratch foundation-model feasibility only if justified
```

A from-scratch production foundation model is not required to finish VulnHunter v1. It is allowed only after a written data, compute, licensing, evaluation and safety feasibility decision.

---

# 8. Remaining work — exact dependency-ordered sequence

Completed foundations from Section 5 are not repeated here. Work starts from the current repository.

## Phase A — Master baseline and LLM understanding

### Step 1 — Publish this canonical master architecture — `DONE`

Deliverables:

- finished-product definition;
- architecture planes and workflows;
- completed-versus-gap classification;
- one remaining-work sequence;
- explicit LLM evolution path.

Acceptance:

- file is linked from the intelligence-pack reading order;
- future architecture changes update this file.

### Step 2 — Build the isolated tokenizer laboratory

Create an educational package such as `experiments/llm_from_scratch/`.

Deliver:

- corpus loader;
- character tokenizer first;
- small BPE tokenizer second;
- vocabulary save/load;
- encode/decode tests;
- token-count and context-window demonstration;
- plain-language documentation.

Acceptance:

- round-trip text tests pass;
- unknown and edge characters behave explicitly;
- no production import depends on the experiment.

### Step 3 — Build the embedding and vector laboratory

Deliver:

- trainable token embedding table;
- positional embeddings;
- cosine-similarity demonstration;
- tiny semantic-neighbour example;
- tests proving shapes and deterministic seeds.

Acceptance:

- vectors can be inspected and compared;
- the learning note explains token IDs versus embeddings versus document embeddings.

### Step 4 — Build the neural-network and backpropagation laboratory

Deliver:

- tiny scalar neuron;
- multilayer XOR network;
- loss calculation;
- gradient/backpropagation demonstration;
- saved weight artifact;
- tests showing loss decreases.

Acceptance:

- the single-layer limitation and multilayer solution are demonstrated honestly.

### Step 5 — Build self-attention from first principles

Deliver:

- query, key and value projections;
- causal mask;
- scaled dot-product attention;
- one-head and multi-head versions;
- attention-weight inspection;
- shape and masking tests.

Acceptance:

- no future token can influence an earlier generated position;
- the learning note explains attention without claiming human consciousness.

### Step 6 — Build a tiny transformer language model

Deliver:

- token and positional embeddings;
- layer normalisation;
- residual connections;
- attention and feed-forward blocks;
- output logits and softmax;
- cross-entropy training;
- checkpoint save/load.

Acceptance:

- a tiny corpus can overfit predictably;
- training is reproducible;
- artifact metadata records configuration and dataset hash.

### Step 7 — Build the autoregressive generation laboratory

Deliver:

- next-token loop;
- temperature and top-p controls;
- context-window truncation demonstration;
- streaming output;
- repetition and hallucination examples.

Acceptance:

- deterministic generation works at temperature zero or equivalent greedy mode;
- limits stop runaway generation.

### Step 8 — Build a safe tool-calling simulator

Deliver:

- typed fake tools only;
- structured tool request schema;
- application-side validation and execution;
- tool-result return to the model loop;
- deny and abstain paths;
- no real scanner, shell, network or repository writes.

Acceptance:

- documentation clearly separates LLM output from application execution.

### Step 9 — Record the complete LLM learning report

Deliver:

- one beginner-readable guide connecting tokenizer, embeddings, transformer, training, inference, RAG and agents;
- diagrams tied to the actual laboratory code;
- limitations and what the tiny model cannot do.

Acceptance:

- the educational track remains isolated and does not alter production authority.

## Phase B — Production intelligence and governed knowledge

### Step 10 — Reconcile current architecture documents with latest main

Update `CURRENT_STATE.md`, `ROADMAP.md`, `SYSTEM_ARCHITECTURE.md`, `KNOWN_FAILURES.md`, and relevant product docs so they consistently include the unified workspace, Source Hunt, resumable APK flow, controlled learning, current Groq boundary and recent acceptance evidence.

Acceptance:

- no old document claims that a now-implemented feature is missing;
- no current document upgrades an activation-gated feature to operational;
- repository audit passes.

### Step 11 — Define the provider-gateway v2 contract

Preserve current Groq behaviour while defining a model-neutral internal interface for deterministic-only, local and controlled remote modes.

Acceptance:

- existing Groq tests remain green;
- provider selection cannot grant authority;
- unavailable providers return truthful degraded or abstained states.

### Step 12 — Add a disabled local-model adapter

Implement a loopback-only, digest-pinned local provider adapter behind explicit configuration.

Acceptance:

- disabled default;
- no automatic model download;
- no production activation from the browser;
- health, timeout, cancellation, schema and privacy tests pass.

### Step 13 — Build the security-model evaluation harness

Create a private, versioned benchmark covering:

- evidence grounding;
- source-reference accuracy;
- false claims and abstention;
- prompt injection;
- scope and authorisation compliance;
- tool selection;
- structured output;
- latency, memory and cost;
- repeatability.

Acceptance:

- local and remote models run against the same cases;
- scores cannot override hard security failures;
- hidden holdout remains inaccessible to model-selection code.

### Step 14 — Complete the governed knowledge-source registry

Deliver:

- immutable originals;
- source owner, licence, trust, date and expiry;
- secret and prompt-injection review;
- contradiction records;
- reviewed/approved states;
- deletion and retention rules.

Acceptance:

- unreviewed sources cannot enter production retrieval;
- imported instructions never become authority.

### Step 15 — Implement governed chunking, embeddings and vector storage

Deliver:

- document-type-aware chunkers;
- embedding model/version/dimension binding;
- vector store abstraction;
- metadata filters;
- content hashes;
- incremental refresh and deletion;
- no secret-bearing chunks.

Acceptance:

- index drift and incompatible dimensions fail closed;
- original source remains authoritative.

### Step 16 — Connect RAG through the existing context broker

Combine exact search, graph traversal and embedding retrieval.

Acceptance:

- every returned chunk carries source, hash and location;
- context budgets are enforced;
- stale, contradictory or low-confidence material is labelled;
- model output can cite only supplied sources.

### Step 17 — Evaluate retrieval quality before model dependence

Build question sets for architecture, policy, evidence and source-code retrieval.

Acceptance:

- measure recall, precision, unsupported citations and context size;
- weak retrieval blocks production promotion.

## Phase C — Complete assessment engines and connections

### Step 18 — Unify all assessment tasks on one authoritative task graph

**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt and Active Validation now create workspace-bound authoritative task graphs and project approval, queue, execution, cancellation, failed-closed and user-facing chat stages from durable stores. Remediation, retest, downstream evidence completion, verification, review and reporting still require migration to the shared graph.

Ensure website, APK, Source Hunt, active validation, remediation and retest share consistent plan, state, approval, worker, cancellation, activity and receipt contracts.

Acceptance:

- no second hidden workflow or browser-only state machine;
- every long-running action survives browser disconnects;
- terminal states are immutable.

### Step 19 — Lock release-quality website private-lab acceptance

Repeat the complete authorised website path across representative private applications, redirects, failures, cancellations, restarts and empty-result scans.

Acceptance:

- evidence, candidate, verification, review and report linkage is proven end to end;
- no public target is needed.

### Step 20 — Decide and implement the next website scanner adapter

Select only one justified adapter, such as OpenVAS, after exact engine/feed/isolation review.

Acceptance:

- same shared scanner protocol;
- no arbitrary arguments;
- signed job, cancellation, evidence and recovery tests;
- activation remains separate.

### Step 21 — Complete medium and large APK static acceptance

Run representative authorised APKs through every configured static tool.

Acceptance:

- storage preflight, timeout, partial-tool failure, output size, cleanup and restart behaviour are recorded;
- no claim of full coverage beyond the tested toolchain.

### Step 22 — Complete native-library and binary-analysis integration

Deliver reviewed parsers and evidence contracts for native-library inspection, including bounded Ghidra/radare/binutils use where approved.

Acceptance:

- fixed arguments and read-only copies;
- no analyst claim without file, offset/symbol and tool provenance;
- representative native artifacts pass acceptance.

### Step 23 — Build the disposable dynamic Android laboratory

Deliver:

- isolated emulator/device identity;
- private MobSF option;
- ADB and Frida broker contracts;
- network egress policy;
- exact action approval;
- snapshot reset, timeout, cleanup and evidence capture;
- no host execution.

Acceptance:

- one complete authorised disposable run;
- cancellation and cleanup failure tests;
- sensitive traffic evidence remains protected.

### Step 24 — Expand Source Hunt one language at a time

Recommended order follows actual target demand, not popularity.

For each language:

- deterministic parser/inventory;
- framework entry points;
- attacker inputs;
- guards and sinks;
- call-path limitations;
- false-positive and abstention tests;
- exact source-reference verification.

Acceptance:

- unsupported constructs are explicit;
- no blanket multi-language coverage claim.

### Step 25 — Complete incremental repository coverage and impact analysis

Deliver changed-file/symbol invalidation, dependency and call-impact paths, staleness detection, coverage evidence and optional Graphify comparison.

Acceptance:

- a changed revision invalidates stale graph/context data;
- critical relationships are verified against source.

## Phase D — Verification, remediation and release

### Step 26 — Operationalise real machine-oracle connectors

Start with read-only or generated-data verification recipes.

Acceptance:

- exact authorisation and finding binding;
- oracle identity/version;
- replay protection;
- bounded attempts;
- `ABSTAIN` for unavailable or inconsistent verification;
- model cannot verify its own claim.

### Step 27 — Connect remediation to controlled engineering orchestration

Deliver a consistent flow from finding to RED test, bounded patch, GREEN tests, broader verification and human promotion.

Acceptance:

- model cannot write outside declared paths;
- fix verifier is read-only and independent;
- human controls merge.

### Step 28 — Complete retest workflows

Website, source and APK retests must run only checks relevant to the remediation claim and preserve original evidence lineage.

Acceptance:

- before/after evidence is comparable;
- regression and cannot-verify states are explicit.

### Step 29 — Complete report and export contracts

Deliver:

- stable JSON and human-readable report schemas;
- evidence citations and limitations;
- reviewer/adjudicator state;
- remediation and retest state;
- export manifest and integrity hashes;
- PDF renderer behind separate readiness.

Acceptance:

- report generation cannot publish;
- raw secrets and prohibited evidence are absent.

### Step 30 — Implement the dedicated publication service

Deliver exact release approval, final manifest, authorised destination and revocation/correction procedure.

Acceptance:

- no model or ordinary assessment operator can publish;
- publication is auditable and separately authorised.

## Phase E — Real data and VulnHunter-owned model

### Step 31 — Run governed real-data campaigns

Collect across multiple intentionally diverse, owned or explicitly authorised applications and repositories.

Acceptance:

- exact authorisations and application-family metadata;
- two independent reviews per retained observation;
- adjudication of every dispute;
- immutable release manifest.

### Step 32 — Freeze development and external holdouts

Split by application/repository family, not individual finding.

Acceptance:

- no family leakage;
- external holdout is locked before model decisions;
- access is audited.

### Step 33 — Establish honest baseline performance

Evaluate rules, current Naive Bayes, prompted models and RAG-assisted models.

Acceptance:

- calibration, precision, recall, false-negative, false-positive, category and family results;
- synthetic and real results remain separate;
- weak performance is preserved honestly.

### Step 34 — Build the reviewed agent-trace dataset

Store only sanitised, authorised and reviewed examples of tasks, context, tool choices, evidence, abstentions, reviewer corrections and final outcomes.

Acceptance:

- provenance and consent/retention policy;
- no secrets or unauthorised targets;
- disagreement is preserved rather than silently flattened.

### Step 35 — Fine-tune VulnHunter-SecLM v2

Use supervised fine-tuning or LoRA on a selected open-weight model.

Acceptance:

- frozen base model and dataset versions;
- reproducible training;
- hard safety and scope tests;
- rollback to the prior model;
- no direct authority or tools.

### Step 36 — Run shadow-mode comparison

The fine-tuned model operates without influencing authoritative outcomes.

Acceptance:

- compare against deterministic baselines, current provider and humans;
- track hallucinations, unsafe proposals, abstention and reviewer disagreement;
- promotion requires explicit human approval.

### Step 37 — Promote a bounded local advisory model

Only after the evaluation gate passes, make the local model the default advisory provider for approved tasks.

Acceptance:

- deterministic-only fallback remains;
- Groq remains optional and controlled;
- model failure cannot block authoritative workflows.

### Step 38 — Decide whether continued pretraining is justified

Review data volume, licence, compute, privacy and measured gaps.

Acceptance:

- written go/no-go decision;
- no automatic escalation from fine-tuning to pretraining.

### Step 39 — Decide whether a from-scratch foundation model is justified

This is a feasibility gate, not an assumed destination.

Required evidence:

- sufficiently large licensed corpus;
- compute and storage budget;
- tokenizer and architecture plan;
- safety and evaluation resources;
- expected benefit over existing open-weight models;
- long-term maintenance ownership.

A `NO-GO` decision is acceptable and does not prevent VulnHunter from being finished.

## Phase F — Production trust and operations

### Step 40 — Complete production identity assurance

Deliver deployment-appropriate MFA/SSO or equivalent assurance, recovery, identity lifecycle and privileged-role review.

Acceptance:

- compromised-admin response;
- reviewer independence controls;
- no browser-controlled role grants.

### Step 41 — Implement protected signing and key lifecycle

Sign worker images/jobs, compatibility manifests, evidence releases, review attestations, model artifacts and reports with independently protected keys.

Acceptance:

- rotation, revocation, verification and recovery tests;
- keys never enter prompts or repository files.

### Step 42 — Complete PostgreSQL, storage and migration readiness

Deliver schema migration rehearsal, concurrent-worker tests, object/evidence storage policy, backup, restore, retention and deletion.

Acceptance:

- proven restore into an isolated environment;
- rollback runbook tested;
- corruption and disk-pressure behaviour fail closed.

### Step 43 — Complete monitoring and incident response

Deliver:

- health/readiness;
- worker queue and lease metrics;
- provider usage and failures;
- storage pressure;
- security and threat-containment alerts;
- immutable audit export;
- incident, pause, key-revocation and recovery runbooks.

Acceptance:

- one tabletop incident exercise and one restore exercise.

### Step 44 — Complete production deployment acceptance

Provision the chosen private hosting environment with TLS, DNS, reverse proxy, secrets, PostgreSQL, persistent evidence storage and separately activated workers/providers.

Acceptance:

- deployment checklist passes;
- no wildcard hosts or unsafe proxy trust;
- public exposure remains separately reviewed.

### Step 45 — Run an independent security assessment

Review authentication, authorisation, workers, provider privacy, source processing, upload handling, storage, supply chain, model injection, prompt injection, SSRF, replay, cancellation and deployment.

Acceptance:

- critical/high issues resolved or explicitly block release;
- retest evidence recorded.

### Step 46 — Run final multi-workflow acceptance

Required end-to-end scenarios:

- website private-lab assessment;
- Source Hunt on an authorised repository;
- small and representative large APK static assessment;
- approved disposable Android dynamic assessment when included in the release;
- finding verification, review, remediation, retest and report;
- provider unavailable and deterministic-only mode;
- backup/restore and worker restart;
- phone-responsive workflow.

Acceptance:

- every displayed state is backed by persisted evidence;
- no hidden manual workaround is represented as product completion.

### Step 47 — Release VulnHunter v1

Release only after the architecture, security, operational and acceptance gates above pass for the declared feature set.

The release manifest must state:

- enabled and disabled capabilities;
- exact model/provider state;
- scanner/tool versions;
- supported languages and artifact types;
- known limitations;
- deployment assumptions;
- test and acceptance evidence;
- rollback procedure.

### Step 48 — Operate the continuous improvement cycle

```text
authorised use
→ evidence and human feedback
→ governed candidate learning
→ evaluation
→ shadow deployment
→ human promotion
→ monitoring
→ rollback when needed
```

No model, rule, tool, skill or worker enters production without the same versioned test, review and release gates.

---

# 9. Definition of finished

VulnHunter is considered finished for a declared release only when:

1. the declared website, source and APK workflows run end to end in the intended environment;
2. authorisation, scope, approval and worker boundaries cannot be bypassed by the model or browser;
3. every candidate finding is bound to genuine evidence and provenance;
4. verification can succeed, abstain or fail truthfully;
5. independent review and adjudication remain authoritative;
6. remediation and retest preserve evidence lineage;
7. the product works when the model provider is unavailable;
8. retrieval outputs are source-bound and evaluated;
9. real-world model claims use diverse governed data and locked holdouts;
10. production storage, backup, restore, signing, monitoring and incident response are accepted;
11. an independent security review has passed;
12. the release manifest states exactly what is and is not enabled.

“Finished” does not mean every possible security tool, programming language, model, exploit technique or deployment environment is supported. It means the declared product scope is complete, honest, secure, tested and operable.

---

# 10. Explicit permanent exclusions

Unless Emmanuel approves a new product boundary through a documented architecture and security review, VulnHunter must not add:

- arbitrary public-Internet scanning;
- destructive exploitation;
- credential stuffing or brute force;
- persistence, lateral movement or defence evasion;
- arbitrary shell tools exposed to the model;
- model-controlled authorisation or scope expansion;
- automatic finding confirmation, severity, publication or merge;
- silent upload of private source, APKs, evidence or credentials;
- silent model downloads, training or self-modification;
- public unauthenticated MCP/tool services;
- fabricated progress, evidence or performance claims.

---

# 11. Maintenance rule

Every milestone that changes architecture, status or execution order must update this file in the same pull request.

When marking a row or step `DONE`, include:

- implementation paths;
- focused and repository-level tests;
- operational acceptance where required;
- known limitations;
- exact activation state.

Never move a feature from `PARTIAL`, `ACTIVATION_REQUIRED` or `LATE_STAGE` to `DONE` merely because a code skeleton exists.
