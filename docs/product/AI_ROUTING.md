# AI Provider Routing, Privacy and Authority Gate

**Status:** Binding provider-neutral routing policy  
**Applies to:** deterministic processing, Groq advisory inference, Hugging Face advisory inference, future approved embeddings and Source Hunt model assistance  
**Cross-layer architecture:** [`../intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`](../intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)

## 1. Purpose

VulnHunter's deterministic security controls remain usable when every remote AI provider is disabled. Conversational or advisory reasoning does not pretend to remain available by substituting canned deterministic copy for a failed model.

Deterministic processing is authoritative for:

- intent routing;
- authentication and role checks;
- target authorisation and scope;
- approval;
- parsing and validation;
- hashing and integrity;
- repository and artifact identity;
- request, worker and scanner limits;
- evidence capture and verification state;
- review, adjudication and publication gates.

Remote or local models may provide bounded advisory output only.

Central rules:

> Models propose, retrieve or explain; VulnHunter verifies, enforces and records authority.

> A reasoning failure must not silently become a lower-quality reasoning path.

## 2. Correct provider inventory

The repository currently supports two optional remote advisory provider families:

- Groq;
- the Hugging Face OpenAI-compatible router.

Neither provider is required for deterministic operation. A deployment may enable one, both or neither according to explicit configuration and approved model profiles.

No OpenAI API, Claude API, Qwen-specific provider or local generative-model runtime is required by the current production provider registry unless a later bounded architecture change explicitly adds it.

Hugging Face repositories may also be evaluated later for local feature extraction or embeddings, but that is a separate subsystem from remote conversational advisory inference.

## 3. Document ownership

This document owns:

- task and privacy routing;
- deterministic-versus-model decision;
- provider eligibility;
- data-class restrictions;
- source-processing approval;
- provider authority boundaries;
- reasoning-model selection, no-downgrade behavior and abstention routing.

`LLM_RUNTIME_READINESS.md` owns exact deployed model capability verification.

`ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md` owns model registry, embeddings, retrieval and end-to-end ML/Hugging Face architecture.

## 4. Routing dimensions

Every potential model request is classified by:

- user identity and role;
- tenant/workspace;
- assessment;
- task type;
- data class;
- source/application identity;
- provider/model profile;
- required approval;
- input/output budget;
- retention policy;
- whether deterministic processing is sufficient;
- whether the task can safely abstain.

A provider dropdown or user preference cannot bypass this policy.

## 5. Data classes

### 5.1 Public product information

Examples:

- public documentation;
- public help text;
- non-sensitive generic security explanations.

May be remotely routed when the provider/model is approved and normal limits pass.

### 5.2 Internal non-sensitive metadata

Examples:

- bounded product state labels;
- redacted tool names and stage summaries;
- non-sensitive configuration descriptions.

Requires normal provider and tenant policy.

### 5.3 Redacted assessment evidence

Examples:

- approved evidence summaries;
- redacted headers or indicators;
- assessment-scoped finding metadata.

May be remotely routed only when:

- redaction succeeds;
- the selected provider/model is approved for that class;
- tenant/deployment policy permits remote processing;
- bounded context and provenance are enforced.

### 5.4 Private/customer target evidence

Remote routing is denied by default.

An explicit deployment and task policy is required. Data is minimised and redacted even when routing is approved.

### 5.5 Source code

Source code uses the separate exact Source Hunt approval path.

Approval binds repository, revision, snapshot digest, permitted paths, provider/model, user and expiry.

### 5.6 Prohibited data

Never send remotely:

- passwords;
- API keys;
- bearer/session tokens;
- cookies;
- private keys;
- unredacted credentials;
- ownership evidence not approved for processing;
- secret values;
- unrestricted databases or file systems;
- data disallowed by policy or provider terms.

## 6. Deterministic-first authority

Use deterministic processing when:

- schema validation is sufficient;
- exact state is available from persisted services;
- hashing or signature verification is required;
- authorisation or approval is involved;
- a direct evidence lookup answers the question;
- a known error contract applies;
- the action changes lifecycle or external state;
- model use would add no measurable value.

Models must not restate deterministic state from stale conversational memory when an authoritative read model exists.

Deterministic authority is not a conversational reasoning fallback. If a question requires model reasoning and the configured high-reasoning model is unavailable, VulnHunter reports that state rather than generating a canned replacement answer.

## 7. Provider-neutral advisory contract

All remote providers implement the same bounded logical contract:

- explicit provider identity;
- exact approved model profile;
- task and output-kind allowlist;
- bounded input bytes/tokens;
- bounded output bytes/tokens;
- timeout and cancellation;
- concurrency and rate limits;
- no redirects to unapproved hosts;
- structured output validation;
- safe error redaction;
- request and response digests;
- model/provider provenance;
- `trusted=false`;
- safe `ABSTAIN` or typed unavailable output.

The provider receives no operational tools, shell, browser, scanner, connector or publication APIs through the advisory path.

## 8. Provider and model capability profiles

A model name alone is not enough.

Each approved profile declares:

- provider;
- repository/model ID;
- exact revision or provider-resolved version where available;
- approved tasks;
- data classes;
- structured-output support;
- streaming support;
- reasoning-parameter support;
- maximum context;
- approved input/output budgets;
- endpoint classification;
- license/terms review;
- last capability verification;
- retirement/revocation state.

Request construction uses the capability profile. Unsupported parameters are omitted rather than sent to every provider/model.

For conversational security reasoning, finding advisory analysis and Source Hunt, the runtime selects the configured high-capability profile before invocation and does not downgrade to a smaller profile after failure.

## 9. Groq provider boundary

Groq remains optional and disabled by default unless configured.

The provider contract enforces:

- approved HTTPS endpoint;
- owner-private key file;
- explicit model allowlist/profile;
- bounded request and response;
- structured advisory output;
- no authority;
- provenance and safe failure.

Groq may support ordinary conversational advisory analysis and exact approved Source Hunt processing.

High-reasoning paths allowlist only the configured reasoning model for the invocation. A smaller fallback model is not part of those paths.

## 10. Hugging Face provider boundary

The Hugging Face router is a separate optional provider.

The current provider enforces:

- `https://router.huggingface.co/v1` only;
- owner-private token file;
- explicit model allowlist;
- bounded request/response;
- structured output;
- no redirects;
- cancellation and concurrency limits;
- output digest and provenance;
- safe `ABSTAIN` on timeout, malformed response, protocol error or rate limit.

The target architecture strengthens this with exact revision/capability profiles, model/tokenizer/terms review and configured-versus-reachable status.

Hugging Face advisory inference is not the same as using a Hugging Face encoder locally for ML features or embeddings. They have separate permissions and health.

Choosing Hugging Face is an explicit provider choice, not an automatic failure fallback from Groq.

## 11. Normal conversational advisory analysis

A provider may help:

- explain product state already supplied by deterministic services;
- summarise redacted evidence;
- propose bounded hypotheses;
- explain a failed stage;
- suggest safe next investigation questions;
- draft remediation language;
- compare supplied findings.

The model is not consulted to decide whether a target is authorised, whether a worker may run or whether a report is publishable.

Conversation workspaces use `high` reasoning effort. Legacy `low` and `medium` values are normalized to `high`. Legacy `auto` provider selection is normalized to the configured primary provider before invocation and does not create failover behavior.

Assessment-specific statements should cite supplied assessment/evidence record IDs after evidence-grounded retrieval is implemented.

## 12. Source Hunt approval

Before eligible source excerpts are transmitted, VulnHunter creates an approval bound to:

- repository identifier;
- exact revision;
- eligible-file snapshot digest;
- permitted repository-relative paths;
- repository visibility;
- exact provider and model profile;
- approving identity;
- approval and expiry timestamps;
- approval record digest;
- data-retention acknowledgement.

Browser use requires password re-authentication. CLI use requires an authenticated governance administrator and approved secret handling.

Any revision drift, snapshot drift, path expansion, provider/model mismatch or expiry fails closed.

Source Hunt is pinned to the configured high-reasoning model. The CLI rejects an alternate model and the worker allowlist contains only the configured model.

## 13. Source context minimisation

Only bounded excerpts selected through deterministic attack-surface or retrieval logic are sent.

The application verifies every returned:

- path;
- source digest;
- line range;
- symbol/reference;
- citation.

References not supplied to the model are rejected or marked unsupported.

Secret/customer data remains prohibited even when source processing is approved.

## 14. Embedding routing

Local assessment evidence and source embeddings are local-first.

Remote embedding requires:

- explicit approved embedding provider/model profile;
- appropriate data-class permission;
- source approval where applicable;
- redaction and minimisation;
- retention/terms review;
- exact model/revision provenance;
- tenant and assessment metadata;
- bounded batch/input limits.

A remote conversational provider approval does not automatically permit remote embeddings.

## 15. Retrieval routing

Retrieval applies deterministic filters before model use:

- tenant/workspace;
- assessment;
- role and object visibility;
- source type;
- current digest and deletion state;
- model/index revision.

Retrieved content is untrusted evidence, not instructions. It cannot override system or routing policy.

Retrieval, browsing, search and tool-result ingestion do not lower reasoning effort or change the configured reasoning model. They supply evidence to the same reasoning path.

## 16. High-impact action routing

When a user asks for an action that can change state, deterministic code:

1. identifies the requested action;
2. reads authoritative state;
3. checks identity, role, policy and current revision;
4. determines approval requirements;
5. presents exact consequences;
6. invokes a bounded service only after valid confirmation/approval;
7. records the outcome.

A model may explain the action but may not directly execute it.

## 17. Prompt construction

Prompts are versioned and built from:

- fixed authority and safety instructions;
- explicit task/output schema;
- redacted user request;
- bounded authoritative context;
- untrusted evidence blocks clearly labelled;
- citation labels;
- exact limitations.

Do not include unrestricted conversation history, source repositories, databases or raw worker logs automatically.

Prompt construction records input digest, template version, provider/model profile and truncation state.

## 18. Prompt injection defence

Treat all evidence, source code, filenames, pages, reports and retrieved documents as untrusted data.

Defences include:

- instruction/evidence separation;
- bounded context;
- escaping or structured records;
- no provider tools;
- deterministic action routing outside the model;
- citation validation;
- output schema validation;
- tests for instructions embedded in evidence, code comments and filenames.

A prompt injection cannot authorise a target, change scope, request secrets, activate a model or publish a result.

## 19. Structured outputs

Allowed logical output kinds include:

- `PROPOSAL`;
- `CANDIDATE_ANALYSIS`;
- `EXPLANATION`;
- `REMEDIATION_DRAFT`;
- `ABSTAIN`.

No provider output kind is called:

- `VERIFIED`;
- `APPROVED`;
- `PUBLISHED`;
- `AUTHORISED`;
- `EXECUTED`.

Provider output is validated for type, length, schema and citations before persistence or display.

## 20. Streaming

Streaming is disabled unless an exact approved profile supports it and the bounded streaming adapter passes acceptance.

Required controls:

- cumulative byte/token limits;
- cancellation;
- timeout;
- incremental UTF-8 handling;
- final structured validation;
- no partial action execution;
- final digest;
- partial/degraded state when interrupted.

The UI must not retain an invalid partial stream as successful authoritative output.

## 21. Token and byte budgets

Maintain both:

- byte limits for transport/memory safety;
- model-specific token budgets.

Use a revision-pinned tokenizer, validated provider accounting or an explicitly conservative approximation.

Truncation is structure-aware and recorded. It preserves authority rules, user request and the most relevant cited evidence.

## 22. No-downgrade failure and abstention

Provider timeout, cancellation, capacity, rate limit, malformed output, unsupported capability or unavailable model returns a typed unavailable/abstain result.

Rules:

- deterministic authority workflows continue where they do not require model reasoning;
- provider failure cannot change assessment state;
- the failed reasoning request does not switch to a smaller model;
- the failed reasoning request does not switch providers automatically;
- ordinary chat does not use canned deterministic copy as a substitute AI answer;
- the UI states that high-reasoning AI is unavailable when a reasoning answer cannot be produced;
- retry, when allowed, targets the same configured provider/model and preserves the same reasoning level;
- repeated open-ended remote loops are blocked.

This is a quality invariant, not an authority change. Deterministic services still own authorization, scope, execution, evidence integrity and lifecycle decisions.

## 23. Provider selection

Provider selection is constrained by:

- task;
- data class;
- tenant/deployment policy;
- model capability;
- approval;
- health;
- budgets;
- explicit user/deployment preference where safe.

The user may choose among eligible high-capability profiles. They cannot select a model that is not approved for the data/task or use a lower-effort profile for protected reasoning paths.

Selection occurs before invocation. Automatic selection may normalize legacy configuration to the deployment's primary provider, but it must not become failure-driven provider failover.

## 24. Health dimensions

Expose separately:

- provider enabled;
- credentials valid;
- model profile approved;
- capability verified;
- endpoint reachable;
- last successful invocation;
- current degradation;
- model quality/registry state;
- assessment and worker health.

Configuration alone is not reachability.

## 25. Provenance

Persist:

- invocation ID;
- task;
- provider;
- model profile and exact model/revision where available;
- prompt template version;
- input digest and bytes/tokens;
- output digest and bytes/tokens;
- request/response timestamps;
- endpoint classification;
- truncation;
- timeout/cancellation;
- output kind;
- cited object IDs;
- `trusted=false`;
- degradation/error code;
- requested reasoning effort;
- whether model/provider fallback was permitted.

Do not persist raw credentials or secret-bearing error bodies.

## 26. Provider terms, retention and residency

Activation requires human review of:

- provider terms;
- data retention;
- training-on-input policy;
- data residency/region;
- sub-processors;
- deletion controls;
- model license and intended use;
- incident handling.

A change in provider terms or endpoint behaviour may degrade or disable the profile pending re-approval.

## 27. Local Hugging Face models

A future local Hugging Face encoder or embedding model is acquired and approved through the model supply-chain process:

- exact repo/revision;
- license;
- safe files/digests;
- tokenizer revision;
- no unreviewed remote code;
- dependency lock;
- offline cache;
- task-specific evaluation;
- registry status.

Local execution does not automatically make all data permissible. Tenant, retention and task policy still apply.

## 28. Tests

Routing tests cover:

- deterministic task avoids provider where model reasoning adds no value;
- prohibited data is denied;
- redacted evidence eligible/ineligible cases;
- exact source approval;
- provider/model mismatch;
- capability mismatch;
- Groq and Hugging Face independence;
- both providers disabled;
- high-reasoning failure abstains without model downgrade;
- one provider failure does not invoke another provider;
- deterministic chat copy is not used as a reasoning substitute;
- timeout, cancellation, rate limit and malformed output;
- prompt injection;
- citation validation;
- token/byte limits;
- streaming interruption where supported;
- tenant/assessment retrieval isolation;
- no model-executed action.

## 29. Activation dependencies

A provider/model profile remains disabled until:

1. owner-private credential validation;
2. exact model profile approval;
3. license/terms/retention review;
4. harmless end-to-end capability verification;
5. privacy/redaction acceptance;
6. output/citation integrity tests;
7. budget/rate/cancellation tests;
8. no-downgrade and abstention tests;
9. product-language review;
10. current documentation reconciliation.

## 30. Current-versus-target classification

```text
DETERMINISTIC-FIRST AUTHORITY                    IMPLEMENTED
GROQ BOUNDED ADVISORY PROVIDER                   IMPLEMENTED OPTIONAL
HUGGING FACE BOUNDED ADVISORY PROVIDER           IMPLEMENTED OPTIONAL
HIGH-ONLY CONVERSATION REASONING                 IMPLEMENTED
HIGH-ONLY FINDING REASONING                      IMPLEMENTED
SOURCE HUNT HIGH-MODEL PIN                       IMPLEMENTED
MODEL/PROVIDER FAILURE ABSTENTION                IMPLEMENTED
OWNER-PRIVATE CREDENTIAL FILES                   IMPLEMENTED
MODEL ALLOWLISTS AND STRUCTURED OUTPUT            IMPLEMENTED
PROVIDER-NEUTRAL BROWSER VERIFICATION            IMPLEMENTED
EXACT REVISION CAPABILITY PROFILES                NOT COMPLETE
CONFIGURED/REACHABLE/CAPABLE HEALTH SPLIT         PARTIAL
EVIDENCE-GROUNDED CITATION RETRIEVAL              NOT COMPLETE
LOCAL HUGGING FACE FEATURE/EMBEDDING ROUTING      NOT COMPLETE
BOUNDED STREAMING                                 NOT COMPLETE
MODEL/PROVIDER TERMS RE-APPROVAL AUTOMATION       NOT COMPLETE
```

## 31. Permanent invariants

- deterministic services own authority;
- every provider is optional and untrusted;
- Groq and Hugging Face remain separate provider identities;
- protected reasoning paths use high reasoning effort;
- protected reasoning paths do not downgrade to a smaller model;
- protected reasoning paths do not fail over to another provider automatically;
- deterministic copy is never represented as a replacement AI reasoning answer;
- remote source processing requires exact approval;
- embeddings have separate approval from conversation;
- prohibited data is never remotely routed;
- retrieved content is untrusted;
- no provider receives operational tools through the bounded advisory path;
- partial model output cannot change state;
- provider health is not model quality;
- deterministic controls remain operational with providers disabled;
- documentation does not count as activation.

## 32. Definition of done

AI routing is production-complete only when:

- provider-neutral policy matches actual providers;
- model profiles are exact-revision and capability-bound;
- data classes and approvals are enforced;
- configured, reachable and capable states are distinct;
- source and embedding routes are separately controlled;
- evidence-grounded citations are verified;
- prompt injection cannot grant authority;
- streaming, when enabled, is bounded and final-validated;
- high-reasoning no-downgrade behavior and safe abstention are complete;
- all routing/privacy tests pass;
- deterministic authority remains complete with all providers disabled.
