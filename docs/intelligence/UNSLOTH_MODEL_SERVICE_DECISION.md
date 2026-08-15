# Unsloth Model-Service Architecture Decision

**Decision date:** 2026-08-15  
**Status:** architecture recorded; no Unsloth runtime dependency activated

## Decision

VulnHunter may use Unsloth in the future as a **separate local AI/model-service
plane**. Unsloth must not be embedded into the Django/web process and must not be
used as the scanner isolation boundary.

The permanent separation is:

```text
                         VulnHunter
                             |
              +--------------+--------------+
              |                             |
        intelligence                     execution
              |                             |
       AI provider gateway             policy + approval
              |                             |
     +--------+--------+                    |
     |                 |                    v
cloud/frontier    Unsloth local        OpenSandbox
providers         model service             |
                                            v
                                      scanner workers
```

- **Unsloth = model/inference/training infrastructure.**
- **OpenSandbox = isolated tool-execution infrastructure.**
- **VulnHunter = authority, scope, policy, evidence, review, and orchestration.**

No model provider is allowed to collapse those boundaries.

## Why Unsloth is relevant

The upstream `unslothai/unsloth` project is Apache-2.0 licensed and supports local
model inference and training, including an OpenAI-compatible API, model fine-tuning,
LoRA/QLoRA, reinforcement-learning workflows, and local-agent integrations.

Those capabilities make it a plausible future backend for private/local reasoning
without requiring VulnHunter to place PyTorch, CUDA, model weights, training
libraries, and the Unsloth Studio dependency graph inside the web/control process.

The authoritative upstream source for implementation decisions is:

```text
https://github.com/unslothai/unsloth
```

Version, model, hardware, and API compatibility must be re-verified immediately
before any implementation batch because upstream changes quickly.

## Required process boundary

Do not build this:

```text
Django / VulnHunter web process
  + Unsloth
  + PyTorch/CUDA
  + model weights
  + training stack
  + scanners
```

Build this instead:

```text
VulnHunter control plane
        |
        | authenticated internal inference request
        v
VulnHunter local-model service
        |
        +-- Unsloth runtime
        +-- approved model manifest
        +-- bounded context/input
        +-- bounded output
        +-- no scanner credentials
        +-- no target authorization authority
```

The model service should be independently deployable, restartable, resource-limited,
and replaceable. VulnHunter should consume it through a provider interface rather
than importing Unsloth directly into application modules.

## Authority rule

A local model is advisory only.

```text
model proposes action
        |
        v
VulnHunter validates typed proposal
        |
        +-- authorization
        +-- target scope
        +-- role/skill policy
        +-- approval state
        +-- rate/resource limits
        +-- immutable command plan
        |
        v
OpenSandbox executes approved plan
        |
        v
evidence + deterministic verification
        |
        v
human review
```

A model response, prompt, chat message, RAG document, training example, or previous
successful run must never count as execution permission.

## Provider architecture

The future provider layer should make local inference optional and replaceable:

```text
VulnHunter AI Gateway
    |
    +-- configured cloud provider(s)
    |
    +-- Unsloth local OpenAI-compatible endpoint
    |
    +-- future provider
```

Provider selection should be policy-driven and observable. It must not silently
route private evidence to an external provider when the request requires local-only
processing.

Useful local-model workloads may include:

- summarising already-redacted scanner evidence;
- candidate finding classification and prioritisation;
- duplicate/relationship suggestions;
- remediation drafting;
- code/security reasoning on explicitly approved source snapshots;
- retrieval over approved security knowledge;
- generating structured investigation proposals for later policy validation.

The model must not directly execute commands, scan targets, alter human labels, or
publish findings.

## Training and fine-tuning boundary

If Unsloth is later used for security-specific fine-tuning, existing VulnHunter ML
rules remain authoritative:

- do not train on unreviewed observations;
- preserve human labels as authority;
- redact secrets and sensitive evidence before dataset creation;
- deduplicate before splitting;
- keep scan groups isolated across splits;
- lock holdout data;
- record dataset, model, configuration, code, and metric provenance;
- label synthetic benchmark results as synthetic;
- never promote a model only because an aggregate score improved.

A possible future flow is:

```text
reviewed + redacted security corpus
        |
        v
governed dataset release
        |
        v
Unsloth LoRA/QLoRA/fine-tuning experiment
        |
        v
independent evaluation
        |
        v
model manifest + artifact hash
        |
        v
human promotion decision
```

Training workers and inference workers should be separate roles where practical.

## Service security requirements

Before activating a local Unsloth service:

1. Bind it to loopback or a private authenticated service network by default.
2. Do not expose Unsloth Studio publicly as the production inference boundary.
3. Keep provider/API credentials outside source control and model prompts.
4. Give the model service no scanner credentials or Docker/OpenSandbox control-plane
   credentials unless a future narrowly scoped design explicitly requires them.
5. Bound request bytes, context size, output tokens, concurrency, runtime, and GPU
   memory.
6. Redact before requests cross the VulnHunter-to-model boundary.
7. Record provider/model identity and model artifact digest with every material
   inference used in a finding or decision-support record.
8. Treat tool-calling output as an untrusted typed proposal, never as executable
   authority.
9. Fail closed when a local-only policy cannot reach the local provider.
10. Keep model downloads/updates explicit and pinned; do not auto-upgrade a model in
    the middle of an assessment.

## Relationship to OpenSandbox

Unsloth and OpenSandbox are complementary but independent:

```text
Unsloth/local model
       |
       | proposes bounded structured work
       v
VulnHunter policy/control plane
       |
       | issues immutable authorised plan
       v
OpenSandbox
       |
       v
scanner/tool
       |
       v
bounded evidence
       |
       v
VulnHunter verifier/reviewer
```

Do not run a model inside a scanner worker merely because OpenSandbox can host
arbitrary workloads. Model inference and security-tool execution have different
resource, data, trust, and lifecycle requirements.

## Planned implementation phases

### Phase 1 — provider interface

Define a narrow VulnHunter model-provider protocol independent of Unsloth. Preserve
existing provider integrations behind the same typed boundary.

### Phase 2 — local-model service

Deploy a separate local service and connect it through an authenticated
OpenAI-compatible endpoint. Start with inference only; no training capability in the
production service.

### Phase 3 — privacy and routing policy

Add explicit local-only/cloud-allowed routing, model manifests, request-size limits,
redaction evidence, health/readiness, and fail-closed behavior.

### Phase 4 — deterministic evaluation

Evaluate the local model on a reviewed security benchmark before giving it any role
in production finding analysis. Compare quality, latency, resource cost, abstention,
and hallucination/error behavior against the existing provider path.

### Phase 5 — security-specific fine-tuning

Only after a governed reviewed dataset exists, use a separate experiment/training
boundary for LoRA/QLoRA or other justified tuning. Promotion remains human-controlled.

### Phase 6 — hybrid reasoning

Use local inference for appropriate routine/private workloads and a separately
approved frontier provider for cases where stronger reasoning is justified. Routing
must remain explicit, logged, and privacy-aware.

## Explicit non-goals for the current OpenSandbox worker batch

The OpenSandbox Bandit worker batch must not:

- install Unsloth;
- add PyTorch/CUDA/model dependencies;
- start a local LLM server;
- change model-provider routing;
- fine-tune a model;
- let an LLM invoke the Bandit worker directly.

Those are separate implementation batches with separate acceptance criteria.
