# High-reasoning advisory analysis

VulnHunter can run optional advisory reasoning for ordinary conversation and can run a separate evidence-bound reasoning session after scanner evidence has been persisted and deterministic verification has completed.

The model is never the authority for authorization, scope, execution, verification, severity, publication, or human review. Deterministic services continue to own those controls, and deterministic copy is not represented as a substitute AI answer when a remote model fails.

## Runtime flow

The evidence-bound finding path remains:

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

All three finding-analysis stages use one configured reasoning model. The default is `openai/gpt-oss-120b`, and every stage requests `high` reasoning effort.

There is no smaller-model fallback and no cross-provider fallback inside this evidence-bound reasoning session. If the configured model cannot complete a stage, the session abstains instead of silently lowering reasoning quality.

A normal successful finding therefore uses exactly three model requests. Queue delivery may retry the same queued analysis within its fixed delivery limit, but a retry does not select a weaker model.

Ordinary chat is deliberately different because it carries no authorization or execution authority. Its bounded recovery path is documented under **Conversation reasoning policy** below.

## Supplied context

The evidence-bound remote provider receives only a bounded, redacted finding envelope:

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

The evidence-bound advisory layer fails safely without lowering model quality:

- missing key: the advisory stage does not run;
- disabled intelligence: no analysis is queued;
- timeout or rate limit: the stage abstains or the queue retries the same configured model within its fixed delivery limit;
- invalid JSON or schema: the response is rejected;
- invented evidence: the response is rejected;
- unavailable configured reasoning model: the session abstains;
- provider returns a different model than requested: the response is rejected;
- damaged optional activity timeline: the persisted advisory report remains unaffected.

No advisory failure changes a scanner finding or its deterministic verification result. Finding intelligence never authorizes a lower-capability model to answer in its place.

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

The legacy split settings `VULNHUNTER_INTELLIGENCE_PRIMARY_MODEL` and `VULNHUNTER_INTELLIGENCE_DEEP_MODEL` are no longer part of the finding-intelligence runtime contract. Older Codespaces may still contain them, but the worker ignores those values and uses `VULNHUNTER_INTELLIGENCE_MODEL` or its 120B default. This provides a migration path without allowing the legacy 20B value to become a fallback for protected finding intelligence.

The separate web-conversation settings include a primary Groq model and a configured fallback model. The fallback is eligible only for ordinary `chat` intent; it is not inherited by finding intelligence or Source Hunt.

The protected `GROQ_API_KEY` Codespaces secret is copied once into the owner-only key file expected by VulnHunter. The environment variable is then unset by the first-run script.

`start-vulnhunter.sh` starts two independent workers:

- the isolated Nuclei scanner worker;
- the advisory intelligence worker.

The intelligence worker starts only when Groq is enabled and the protected key file exists.

## Conversation reasoning policy

Conversation workspaces request `high` reasoning effort. Legacy `low` and `medium` workspace values are treated as `high` at runtime.

Ordinary non-authoritative conversation uses a smaller bounded context envelope than protected reasoning paths. VulnHunter first requests the configured primary Groq model. If that request abstains, times out, is rate-limited, returns the wrong model identity, or returns an unusable structured response, ordinary `chat` may make one recovery attempt using `VULNHUNTER_GROQ_FALLBACK_MODEL` on the **same Groq provider**.

The default conversation pair is:

```text
primary   openai/gpt-oss-120b
fallback  openai/gpt-oss-20b
```

This fallback is a usability path, not an authority path. It is permitted only after deterministic intent routing has classified the message as ordinary `chat`. Requests classified as scan, authorization, approval, status, results, cancellation, or other governed operations do not gain smaller-model fallback authority.

Provider selection remains explicit. Legacy `auto` is normalized to the configured primary provider rather than enabling provider failover. Groq failure never automatically switches the request to Hugging Face or another provider.

If both eligible ordinary-chat model attempts fail, the UI reports temporary conversation unavailability. It does not fabricate a model answer from deterministic copy.

Deterministic routing remains available for authoritative workspace operations such as authorization checks, scope validation, status reads, approval state, cancellation, and execution control. No conversational model may authorize, approve, execute, verify, set severity, review, adjudicate, merge, release, or publish.

## Source Hunt policy

Source Hunt is pinned to the configured `VULNHUNTER_GROQ_MODEL`. Its CLI rejects an attempt to select a different model, and its worker allowlist contains only the configured model.

The ordinary-chat fallback setting does not apply to Source Hunt. Source Hunt remains attacker-first source-code analysis and does not gain tool execution or arbitrary exploitation authority from the conversation-resilience change.

## Phone workspace behavior

The assessment card continues a separate bounded status check after scanner completion, for no more than three minutes, so the later advisory result can appear on a phone. Polling stops immediately when the result or safe abstention is recorded.

## Trust statement

All advisory reports include:

```text
advisory_only = true
trusted = false
```

Ordinary chat output is also advisory and untrusted. A human reviewer remains responsible for accepting, rejecting, or changing governed findings and decisions.
