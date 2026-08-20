# AI Provider Routing, Privacy and Authority Gate

**Status:** Binding provider-neutral routing policy  
**Applies to:** deterministic processing, ordinary conversational advisory inference, provider-bound finding intelligence, exact-approved Source Hunt processing, future approved embeddings and retrieval assistance  
**Cross-layer architecture:** [`../intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`](../intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)

## 1. Purpose

VulnHunter's deterministic security controls remain usable when every remote or local generative model provider is disabled. Conversational or advisory reasoning does not pretend to remain available by substituting canned deterministic copy for a failed model.

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

> Provider availability may improve conversational continuity, but it never transfers security authority or provider-bound data-processing approval.

Two model-routing classes must remain distinct:

1. **Ordinary conversational advisory reasoning** may use the approved high-capability availability chain `Groq -> Gemini -> loopback Ollama` when deployment/data policy permits it.
2. **Provider-bound protected tasks** such as exact-approved Source Hunt source processing and the finding-intelligence analyst/critic/synthesizer session remain pinned to their configured/approved provider and model and do not inherit cross-provider failover.

Neither class may silently downgrade to an arbitrary smaller or unapproved model.

## 2. Correct provider inventory

The current repository has multiple provider roles rather than one interchangeable provider registry:

- **Groq** — the primary ordinary conversational reasoning route and an optional provider for exact-approved protected reasoning paths.
- **Gemini** — an optional ordinary conversational fallback when enabled and permitted for the data class.
- **Ollama on loopback** — an optional local ordinary conversational fallback; the adapter accepts loopback hosts only.
- **Hugging Face OpenAI-compatible router** — a separate optional provider family used only where explicitly configured/approved. It is not part of the automatic ordinary-chat fallback chain.

No OpenAI API or Claude API is required by the current production routing contract. Ollama is a local runtime, not permission to run arbitrary models or to transmit data outside the host.

Hugging Face repositories may also be evaluated later for local feature extraction or embeddings, but that is a separate subsystem from conversational advisory inference.

## 3. Document ownership

This document owns:

- task and privacy routing;
- deterministic-versus-model decision;
- provider eligibility;
- data-class restrictions;
- source-processing approval;
- provider authority boundaries;
- conversational availability failover;
- protected provider/model pinning;
- no-smaller-model-downgrade behavior and abstention routing.

`LLM_RUNTIME_READINESS.md` owns exact deployed model capability verification.

`ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md` owns model registry, embeddings, retrieval and end-to-end ML/Hugging Face architecture.

`../AI_PROVIDER_FAILOVER.md` owns the operational ordinary-chat Groq/Gemini/Ollama failover sequence and timeout/circuit behavior.

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
- whether the task can safely abstain;
- whether cross-provider conversational fallback is permitted for that exact task/data class.

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

Cross-provider conversational fallback is allowed only across providers that are independently eligible for the same redacted data class.

### 5.4 Private/customer target evidence

Remote routing is denied by default.

An explicit deployment and task policy is required. Data is minimised and redacted even when routing is approved. Failure of one provider does not create permission to send this data to another provider.

### 5.5 Source code

Source code uses the separate exact Source Hunt approval path.

Approval binds repository, revision, snapshot digest, permitted paths, repository visibility, provider/model, user and expiry. Ordinary conversational provider fallback does not apply to approved source processing.

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

Deterministic authority is not a conversational reasoning fallback. If a question requires model reasoning and no eligible conversational provider can complete it, VulnHunter reports the unavailable state rather than generating a canned replacement answer.

## 7. Provider-neutral advisory contract

All advisory providers implement or are adapted to the same bounded logical contract appropriate to their role:

- explicit internal provider identity;
- exact approved model profile or configured local model;
- task and output-kind allowlist;
- bounded input bytes/tokens;
- bounded output bytes/tokens;
- timeout and cancellation controls;
- concurrency and rate limits where applicable;
- no redirects to unapproved hosts;
- structured output validation or safe normalization into the bounded advisory envelope;
- safe error redaction;
- model/provider provenance in server-side records where the subsystem persists it;
- `trusted=false` for model conclusions;
- safe `ABSTAIN` or typed unavailable behavior.

The provider receives no operational tools, shell, scanner, connector, publication authority, or raw Obscura MCP client through the advisory path.

Provider identity may be hidden from ordinary chat UI copy so provider switching does not become user-visible noise. Hiding provider churn in the UI does not remove server-side routing boundaries or internal diagnostics.

## 8. Provider and model capability profiles

A model name alone is not enough for provider-bound protected processing.

Each approved profile should declare:

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

For finding intelligence and exact-approved Source Hunt, the runtime remains pinned to the configured/approved high-capability profile and does not switch providers after failure.

For ordinary conversational reasoning, availability routing may select the next independently eligible high-capability provider in the documented chain. That is a provider availability change, not permission to downgrade to a smaller/unapproved model or change the data class.

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

Groq may support ordinary conversational advisory analysis and exact-approved Source Hunt processing under separate policy paths.

High-reasoning provider-bound paths allowlist only the configured reasoning model for the invocation. A smaller fallback model is not part of those paths.

For ordinary conversation, Groq is the preferred provider and its availability failure may advance to the next independently eligible conversational provider.

## 10. Gemini, Ollama and Hugging Face boundaries

### Gemini

Gemini is an optional ordinary conversational fallback. The adapter requires the reviewed HTTPS API host, a configured secret, bounded input/output behavior, no redirects, structured JSON-oriented output, and separate short connection versus bounded read timeouts. It is not automatically approved for source code or private/customer evidence merely because it is configured.

### Ollama

Ollama is an optional local ordinary conversational fallback. The adapter accepts only `127.0.0.1`, `localhost`, or `::1`. It does not expose an unauthenticated remote Ollama service and it receives no security authority. Local execution does not automatically make every data class permissible.

### Hugging Face

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

Hugging Face advisory inference is not the same as using a Hugging Face encoder locally for ML features or embeddings. They have separate permissions and health.

Choosing Hugging Face is an explicit provider choice for an eligible subsystem, not an automatic failure fallback from the ordinary-chat Groq/Gemini/Ollama chain.

## 11. Normal conversational advisory analysis

An eligible conversational model may help:

- explain product state already supplied by deterministic services;
- summarise redacted evidence;
- propose bounded hypotheses;
- explain a failed stage;
- suggest safe next investigation questions;
- draft remediation language;
- compare supplied findings.

The model is not consulted to decide whether a target is authorised, whether a worker may run, whether a candidate is a verified vulnerability, or whether a report is publishable.

Conversation workspaces use `high` reasoning effort. Legacy `low` and `medium` values are normalized to `high`.

When deployment/data policy permits the same conversation context for each provider, ordinary chat uses the availability chain:

```text
Groq -> Gemini -> loopback Ollama
```

The router uses process-local circuit health to avoid repeatedly waiting on a failing provider, probes a cooled-down provider again after the cooldown window, and restores the preferred route automatically after a successful probe. Provider switching does not create a new conversation, reset task activity, or become finding evidence.

A provider failure never authorizes a lower-quality/unapproved model. If no eligible provider succeeds, ordinary chat returns a short unavailable/retry response.

Assessment-specific statements should cite supplied assessment/evidence record IDs where evidence-grounded retrieval is implemented.

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

Source Hunt is pinned to the provider/model allowed by that exact source-processing approval. The ordinary conversational failover router is not invoked for source-code processing. If the approved provider/model is unavailable, Source Hunt remains blocked/unavailable rather than sending code to another provider.

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

Retrieval, browsing, search and tool-result ingestion do not lower reasoning effort or change authorization. They supply bounded evidence to an eligible reasoning path.

## 16. High-impact action routing

When a user asks for an action that can change state, deterministic code:

1. identifies the requested action;
2. reads authoritative state;
3. checks identity, role, policy and current revision;
4. determines approval requirements;
5. presents exact consequences;
6. invokes a bounded service only after valid confirmation/approval;
7. records the outcome.

A model may explain or propose the action but may not directly execute it. AI-controlled browser operation follows the same rule: the model may propose a typed `BrowserAction`; VulnHunter policy authorizes and dispatches it to the worker/runtime.

## 17. Prompt construction

Prompts are versioned and built from:

- fixed authority and safety instructions;
- explicit task/output schema;
- redacted user request;
- bounded authoritative context;
- untrusted evidence blocks clearly labelled;
- citation labels where supported;
- exact limitations.

Do not include unrestricted conversation history, source repositories, databases or raw worker logs automatically.

Prompt construction records or derives bounded provenance appropriate to the subsystem. Provider switching must not change the authoritative conversation/task identity.

## 18. Prompt injection defence

Treat all evidence, source code, filenames, pages, reports, browser observations and retrieved documents as untrusted data.

Defences include:

- instruction/evidence separation;
- bounded context;
- escaping or structured records;
- no provider operational tools;
- deterministic action routing outside the model;
- citation/provenance validation where implemented;
- output schema validation;
- tests for instructions embedded in evidence, code comments and filenames.

A prompt injection cannot authorise a target, change scope, request secrets, activate a model, control Obscura directly, or publish a result.

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

Provider output is validated or safely normalized for type, length and contract before persistence or display. Model output never promotes a finding without deterministic evidence.

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

The browser conversation must not simulate token/word streaming with client timers. Persisted complete messages or a real bounded server stream are the only acceptable presentation paths.

## 21. Token and byte budgets

Maintain both:

- byte limits for transport/memory safety;
- model-specific token budgets.

Use a revision-pinned tokenizer, validated provider accounting or an explicitly conservative approximation where required.

Truncation is structure-aware and recorded. It preserves authority rules, user request and the most relevant cited evidence.

## 22. Failure, failover, no-downgrade and abstention

Failure behavior depends on the routing class.

### Ordinary conversational advisory

For eligible conversation data, provider timeout, capacity, rate limit, malformed output or temporary transport failure may advance to the next independently eligible provider in the approved conversational chain. Circuit cooldown prevents repeated full waits and later probes allow preferred-provider recovery.

Rules:

- deterministic authority workflows continue independently;
- provider failure cannot change assessment state;
- provider failover cannot lower the data-policy bar;
- provider failover cannot select an arbitrary smaller/unapproved model;
- ordinary chat does not use canned deterministic copy as a substitute AI answer;
- if all eligible providers fail, the UI reports a short unavailable/retry state;
- the same conversation/task identity is preserved.

### Provider-bound protected tasks

Finding intelligence, exact-approved Source Hunt processing and any task whose approval binds provider/model do not use cross-provider failure fallback. Timeout/cancellation/capacity/rate-limit/malformed output returns a typed unavailable/abstain result or bounded same-provider retry where explicitly allowed.

This separation is a quality and privacy invariant, not an authority change. Deterministic services still own authorization, scope, execution, evidence integrity, finding promotion and lifecycle decisions.

## 23. Provider selection

Provider selection is constrained by:

- task;
- data class;
- tenant/deployment policy;
- model capability;
- approval;
- health;
- budgets;
- explicit deployment/user preference where safe;
- routing class (ordinary conversation versus provider-bound protected task).

The user cannot select a model that is not approved for the data/task or use a lower-effort profile for protected reasoning paths.

For ordinary conversation, the deployment defines the provider priority chain and the router may move to the next independently eligible provider after failure/cooldown. For provider-bound tasks, selection occurs before invocation and failure does not change provider/model identity.

## 24. Health dimensions

Expose or retain separately as appropriate:

- provider enabled;
- credentials configured/valid where verification exists;
- model profile approved;
- capability verified;
- endpoint reachable;
- last successful invocation where recorded;
- current degradation/circuit state;
- model quality/registry state;
- assessment and worker health.

Configuration alone is not reachability. Conversational circuit health is process-local advisory state, not authoritative persistence.

## 25. Provenance

Protected advisory subsystems should persist or make available:

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
- whether provider/model fallback was permitted for the routing class.

Ordinary chat may deliberately hide provider-switch details from the user-facing message metadata while retaining safe server-side diagnostics. Do not persist raw credentials or secret-bearing error bodies.

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

A change in provider terms or endpoint behaviour may degrade or disable the profile pending re-approval. A provider must be independently acceptable for the data class before it can join a conversational fallback chain.

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
- protected Groq/Hugging Face independence;
- ordinary Groq -> Gemini -> Ollama conversational availability behavior;
- all conversational providers unavailable;
- circuit cooldown and preferred-provider recovery;
- split connection/read timeout behavior;
- high-reasoning failure does not downgrade to a smaller/unapproved model;
- provider-bound Source Hunt/finding intelligence does not cross-provider fail over;
- deterministic chat copy is not used as a reasoning substitute;
- timeout, cancellation, rate limit and malformed output;
- prompt injection;
- citation/provenance validation where implemented;
- token/byte limits;
- streaming interruption where supported;
- tenant/assessment retrieval isolation;
- no model-executed action.

## 29. Activation dependencies

A provider/model profile remains disabled for protected data/tasks until the applicable controls pass:

1. owner-private credential validation where required;
2. exact model profile approval where required;
3. license/terms/retention review;
4. harmless end-to-end capability verification;
5. privacy/redaction acceptance;
6. output/citation integrity tests where relevant;
7. budget/rate/cancellation tests;
8. no-smaller-model-downgrade and abstention/failover-class tests;
9. product-language review;
10. current documentation reconciliation.

## 30. Current-versus-target classification

```text
DETERMINISTIC-FIRST AUTHORITY                    IMPLEMENTED
GROQ BOUNDED ADVISORY PROVIDER                   IMPLEMENTED OPTIONAL
GEMINI ORDINARY-CHAT FALLBACK                    IMPLEMENTED OPTIONAL
LOOPBACK OLLAMA ORDINARY-CHAT FALLBACK           IMPLEMENTED OPTIONAL
CONVERSATIONAL CIRCUIT COOLDOWN/RECOVERY          IMPLEMENTED PROCESS-LOCAL
HUGGING FACE BOUNDED ADVISORY PROVIDER            IMPLEMENTED OPTIONAL / EXPLICIT
HIGH-ONLY CONVERSATION REASONING                 IMPLEMENTED
HIGH-ONLY FINDING REASONING                      IMPLEMENTED
SOURCE HUNT PROVIDER/MODEL APPROVAL PIN          IMPLEMENTED
PROVIDER-BOUND FAILURE ABSTENTION                IMPLEMENTED
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
- ordinary conversational fallback is limited to independently eligible providers/data classes;
- provider-bound Source Hunt and finding-intelligence tasks remain pinned to their approved/configured provider/model;
- protected reasoning paths do not downgrade to a smaller or unapproved model;
- deterministic copy is never represented as a replacement AI reasoning answer;
- remote source processing requires exact approval;
- embeddings have separate approval from conversation;
- prohibited data is never remotely routed;
- retrieved/browser content is untrusted;
- no provider receives operational tools through the bounded advisory path;
- AI browser control uses typed policy-checked actions rather than direct MCP access;
- partial model output cannot change state;
- provider health is not model quality;
- deterministic controls remain operational with providers disabled;
- documentation does not count as activation.

## 32. Definition of done

AI routing is production-complete only when:

- provider-neutral policy matches actual providers and their distinct routing roles;
- model profiles are exact-revision and capability-bound where protected tasks require them;
- data classes and approvals are enforced across every provider;
- configured, reachable and capable states are distinct;
- conversational failover and provider-bound abstention remain separate and tested;
- source and embedding routes are separately controlled;
- evidence-grounded citations are verified where required;
- prompt injection cannot grant authority;
- streaming, when enabled, is bounded and final-validated;
- high-reasoning no-smaller-model-downgrade behavior is complete;
- all routing/privacy tests pass;
- deterministic authority remains complete with all providers disabled.
