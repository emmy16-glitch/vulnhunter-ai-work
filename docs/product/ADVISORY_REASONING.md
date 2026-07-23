# Bounded advisory reasoning

VulnHunter can run an optional evidence-bound reasoning session after scanner evidence has been persisted and deterministic verification has completed.

The model is never the authority for authorization, scope, execution, verification, severity, publication, or human review.

## Runtime flow

```text
approved private-lab scan
  -> persisted scanner evidence
  -> deterministic proof-capsule verification
  -> sanitised advisory queue item
  -> analyst with openai/gpt-oss-20b
  -> critic with openai/gpt-oss-20b
  -> synthesizer with openai/gpt-oss-120b
  -> stored untrusted advisory report
  -> human review
```

The synthesizer may fall back once to `openai/gpt-oss-20b` when the 120B model is unavailable. There is no open-ended self-reflection loop.

A normal successful finding therefore uses exactly three model requests. A deep-model failure can use one additional fallback request. Queue delivery is attempted at most twice by default.

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

The advisory layer fails safely:

- missing key: deterministic verification and human review continue;
- disabled intelligence: no analysis is queued;
- timeout or rate limit: the stage abstains or the queue retries within its fixed limit;
- invalid JSON or schema: the response is rejected;
- invented evidence: the response is rejected;
- unavailable 120B model: one 20B synthesis fallback is permitted;
- damaged optional activity timeline: the persisted advisory report remains unaffected.

No advisory failure changes a scanner finding or its deterministic verification result.

## Codespaces settings

The phone-oriented Codespaces setup writes these defaults:

```bash
VULNHUNTER_INTELLIGENCE_ENABLED=true
VULNHUNTER_INTELLIGENCE_PRIMARY_MODEL=openai/gpt-oss-20b
VULNHUNTER_INTELLIGENCE_DEEP_MODEL=openai/gpt-oss-120b
VULNHUNTER_INTELLIGENCE_MAX_ATTEMPTS=2
VULNHUNTER_INTELLIGENCE_TIMEOUT_SECONDS=90
VULNHUNTER_INTELLIGENCE_MAX_INPUT_BYTES=64000
VULNHUNTER_INTELLIGENCE_MAX_OUTPUT_TOKENS=2400
```

The protected `GROQ_API_KEY` Codespaces secret is copied once into the owner-only key file expected by VulnHunter. The environment variable is then unset by the first-run script.

`start-vulnhunter.sh` starts two independent workers:

- the isolated Nuclei scanner worker;
- the advisory intelligence worker.

The intelligence worker starts only when Groq is enabled and the protected key file exists.

## Phone workspace behavior

The assessment card continues a separate bounded status check after scanner completion, for no more than three minutes, so the later advisory result can appear on a phone. Polling stops immediately when the result or safe abstention is recorded.

## Trust statement

All advisory reports include:

```text
advisory_only = true
trusted = false
```

A human reviewer remains responsible for accepting, rejecting, or changing the finding.
