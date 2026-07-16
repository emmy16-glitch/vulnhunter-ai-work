# AI Routing and Privacy Gate

VulnHunter remains usable without any AI provider. Deterministic processing is
always authoritative for hashing, parsing, validation, authorization, scope,
approval, policy, limits, evidence integrity, and state transitions.

Central rule:

> Qwen proposes; Groq may review; VulnHunter verifies and enforces.

## Local provider

The local connector is loopback-only by default and uses the resource-safe
Ollama model `qwen3.5:2b-q4_k_m` on this VM. Ollama may preserve the display tag
as `qwen3.5:2b-q4_K_M`; inventory matching is deliberately case-insensitive,
while the configured lookup tag remains explicit.

The connector provides:

- one inference slot;
- no automatic model pull;
- no tool, scanner, shell, database, approval, or publication capability;
- a conservative 1,024-token context default;
- thinking disabled for bounded operational prompts;
- strict `PROPOSAL`, `CANDIDATE_ANALYSIS`, or `ABSTAIN` output;
- bounded request/response sizes and timeouts;
- cancellation and deterministic abstention;
- model, digest, endpoint, prompt-template, timestamp, and hash provenance;
- health checks that list models without loading them.

The 9B model was removed from this VM because it could not coexist reliably
with the operating system and VulnHunter inside approximately 5.3 GiB RAM.
The 2B model is installed, but local inference must remain disabled until
`python manage.py vh_verify_local_ai` passes after the VM-safe Ollama CPU
configuration is active.

## Hybrid routing contracts

Three explicit modes are represented without enabling cloud execution:

- `LOCAL_ONLY`: private, sensitive, and offline work remains local.
- `LOCAL_THEN_GROQ`: Groq may be considered only after the local model abstains,
  explicit policy permits remote processing, and deterministic sanitisation
  passes.
- `DUAL_REVIEW`: local and remote candidates may be compared independently;
  agreement remains unverified and disagreement requires human review.

The hybrid coordinator performs no network request and never reads a credential.
Groq remains `CREDENTIAL_PRESENT_BUT_NOT_ACCESSED` and
`INTENTIONALLY_DISABLED` until a separate activation review.

## Graph context

A validated Graphify artifact may supply a small bounded subgraph. When Graphify
is missing, stale, or runtime-incompatible, the context broker uses the native
deterministic repository graph and bounded file excerpts. It never fabricates a
graph or sends the complete repository to a provider.

## Deferred activation dependencies

- successful bounded local 2B inference through the VulnHunter adapter;
- separately approved Groq credential injection and model allowlist;
- remote privacy/sanitisation acceptance tests;
- external current-information lookup policy;
- Graphify regeneration compatibility or a documented stale-graph fallback.

## Groq-only resource-constrained deployment

For the current 5.3 GiB QEMU VM, local Ollama inference may remain disabled when
it cannot complete the bounded readiness request. VulnHunter can use a
GroqCloud advisory connector instead, while deterministic workflows continue
without any model when the network, credential, quota, or privacy gate is
unavailable.

Approved production model preference:

1. `openai/gpt-oss-120b`
2. `openai/gpt-oss-20b`

The connector discovers the account's current model inventory before use. It
sends no tools, code-execution request, browser-search request, MCP server, or
connector definition. Cloud-bound content must first pass the deterministic
privacy gate. Private source, customer data, secrets, credentials, complete
repositories, unrestricted graphs, and authorization records are denied.

Enable Groq only after Zero Data Retention has been enabled in the GroqCloud
Data Controls page and the controlled `vh_verify_groq` command succeeds. Model
output remains `PROPOSAL`, `CANDIDATE_ANALYSIS`, or `ABSTAIN`; it is never
trusted evidence, approval, authorization, verified severity, or publication.
