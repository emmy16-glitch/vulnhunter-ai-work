# High-reasoning advisory analysis

VulnHunter can run an optional evidence-bound reasoning session after scanner evidence has been persisted and deterministic verification has completed.

The model is never the authority for authorization, scope, execution, verification, severity, publication, or human review. Deterministic services continue to own those controls, but deterministic copy is not a substitute for failed AI reasoning.

## Runtime flow

```text
approved private-lab scan
  -> persisted scanner evidence
  -> deterministic proof-capsule verification
  -> sanitised advisory queue item
  -> analyst with openai/gpt-oss-120b / high reasoning
  -> critic with openai/gpt-oss-120b / high reasoning
  -> synthesizer with openai/gpt-oss-120b / high reasoning
  -> stored untrusted advisory report
  -> human review
```

All three stages use one configured reasoning model. The default is `openai/gpt-oss-120b`, and every stage requests `high` reasoning effort.

There is no smaller-model fallback and no cross-provider fallback inside this reasoning session. If the configured model cannot complete a stage, the session abstains instead of silently lowering reasoning quality.

A normal successful finding therefore uses exactly three model requests. Queue delivery may retry the same queued analysis within its fixed delivery limit, but a retry does not select a weaker model.

## Supplied context

The remote provider receives only a bounded, redacted finding envelope:

- redacted scanner title, severity, and confidence;
- deterministic verification verdict and strategy;
- reviewed scanner template identity;
- a hashed target identity rather than a raw address or URL;
- safe structured observations;
- SHA-256 evidence references;
- prior structured stage outputs.

Raw evidence files, response bodies, customer data, authorization records, credentials, API keys, cookies, and private target addresses are not included.

Every model-provided evidence reference must match a digest that VulnHunter supplied. A stage that invents an evidence reference is rejected and the session abstains.

## Stage responsibilities

### Analyst

Builds possible vulnerability hypotheses, identifies assumptions, records missing information, and uses only the supplied evidence references.

### Critic

Challenges the analyst for false positives, missing preconditions, unsupported CWE mappings, contradictory evidence, and overconfidence.

### Synthesizer

Reconciles the first two stages into one conservative advisory conclusion, safe verification suggestions, and remediation options.

The application stores the structured conclusions, not hidden chain-of-thought.

## Failure behavior

The advisory layer fails safely without lowering model quality:

- missing key: the advisory stage does not run;
- disabled intelligence: no analysis is queued;
- timeout or rate limit: the stage abstains or the queue retries the same configured model within its fixed delivery limit;
- invalid JSON or schema: the response is rejected;
- invented evidence: the response is rejected;
- unavailable configured reasoning model: the session abstains;
- provider returns a different model than requested: the response is rejected;
- damaged optional activity timeline: the persisted advisory report remains unaffected.

No advisory failure changes a scanner finding or its deterministic verification result. No advisory failure authorizes a lower-capability model to answer in its place.

## Codespaces settings

The phone-oriented Codespaces setup writes these defaults:

```bash
VULNHUNTER_INTELLIGENCE_ENABLED=true
VULNHUNTER_INTELLIGENCE_MODEL=openai/gpt-oss-120b
VULNHUNTER_INTELLIGENCE_MAX_ATTEMPTS=2
VULNHUNTER_INTELLIGENCE_TIMEOUT_SECONDS=90
VULNHUNTER_INTELLIGENCE_MAX_INPUT_BYTES=64000
VULNHUNTER_INTELLIGENCE_MAX_OUTPUT_TOKENS=2400
```

The legacy split settings `VULNHUNTER_INTELLIGENCE_PRIMARY_MODEL` and `VULNHUNTER_INTELLIGENCE_DEEP_MODEL` are no longer part of the runtime contract. Older Codespaces may still contain them, but the worker ignores those values and uses `VULNHUNTER_INTELLIGENCE_MODEL` or its 120B default. This provides a migration path without allowing the legacy 20B value to become a fallback again.

The protected `GROQ_API_KEY` Codespaces secret is copied once into the owner-only key file expected by VulnHunter. The environment variable is then unset by the first-run script.

`start-vulnhunter.sh` starts two independent workers:

- the isolated Nuclei scanner worker;
- the advisory intelligence worker.

The intelligence worker starts only when Groq is enabled and the protected key file exists.

## Conversation reasoning policy

Conversation workspaces use `high` reasoning effort. Legacy `low` and `medium` workspace values are treated as `high` at runtime.

Provider selection is explicit. Legacy `auto` is normalized to the configured primary provider rather than enabling provider failover. If that high-reasoning provider is unavailable, ordinary chat reports the unavailable state instead of substituting a weaker model, another provider, or canned deterministic reasoning copy.

Deterministic routing remains available for authoritative workspace operations such as authorization checks, scope validation, status reads, approval state, cancellation, and execution control.

## Source Hunt policy

Source Hunt is pinned to the configured `VULNHUNTER_GROQ_MODEL`. Its CLI rejects an attempt to select a different model, and its worker allowlist contains only the configured model.

Source Hunt remains attacker-first source-code analysis. It does not gain tool execution or arbitrary exploitation authority from the reasoning-model change.

## Phone workspace behavior

The assessment card continues a separate bounded status check after scanner completion, for no more than three minutes, so the later advisory result can appear on a phone. Polling stops immediately when the result or safe abstention is recorded.

## Trust statement

All advisory reports include:

```text
advisory_only = true
trusted = false
```

A human reviewer remains responsible for accepting, rejecting, or changing the finding.
