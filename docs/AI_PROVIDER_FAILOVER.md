# Conversational AI failover

VulnHunter's **ordinary conversational advisory path** can use a silent provider chain:

1. Groq (`openai/gpt-oss-120b` by deployment default)
2. Gemini
3. Ollama on loopback

The deterministic VulnHunter backend remains authoritative for authorization, scope, scanner execution, verification, severity, finding promotion, review, and publication. Provider failover applies only to ordinary conversational/advisory reasoning that is eligible for these providers under the deployment's data policy.

This chain does **not** weaken provider-bound protected workflows. Source Hunt remote source processing, exact provider/model approvals, and the multi-stage finding-intelligence session keep their own explicit provider/model contracts and do not inherit conversational cross-provider failover.

## What counts as a failover

The router continues to the next conversational provider when the current provider is disabled, not configured, times out, is rate-limited, returns a temporary server/transport error, abstains, or returns an unusable answer.

The browser does not receive provider-switch error details. A successful fallback is returned as a normal conversational answer with the provider identified internally as `auto` rather than exposing provider churn in user-facing copy.

If every configured conversational provider is unavailable, the user receives only a short retry message. Deterministic authorization, status reads, approvals, cancellation, execution control, evidence and review state remain available independently.

## Circuit breaker and automatic recovery

Each conversational provider has process-local health state. Repeated failures degrade the provider and, after the configured failure threshold, place it in a short cooldown. While that circuit is cooling down, the router skips the provider instead of repeatedly spending the full request timeout on the same failure.

After cooldown, the next eligible request probes that provider again. A successful probe returns it to `healthy`, so the preferred provider is automatically restored without resetting the conversation or task state.

Provider health affects advisory routing only. It is not vulnerability state, authorization state, worker readiness, or model-quality evidence.

## Timeout strategy

Remote/local reasoning can legitimately take longer than establishing a connection, so VulnHunter separates connection timeout from model read timeout where the fallback adapter owns the HTTP transport.

Gemini defaults:

```bash
VULNHUNTER_GEMINI_CONNECT_TIMEOUT_SECONDS=5
VULNHUNTER_GEMINI_TIMEOUT_SECONDS=75
```

Ollama defaults:

```bash
VULNHUNTER_OLLAMA_CONNECT_TIMEOUT_SECONDS=2
VULNHUNTER_OLLAMA_TIMEOUT_SECONDS=120
```

A dead/unreachable provider can therefore fail over within a few seconds, while a connected provider still receives a bounded reasoning window. Groq uses its own provider transport controls and remains the primary conversational route.

## Gemini

Create a Gemini Developer API key and store it as a secret. Do not commit the key to this repository.

Recommended environment values:

```bash
export VULNHUNTER_GEMINI_ENABLED=true
export VULNHUNTER_GEMINI_API_KEY='YOUR_KEY'
export VULNHUNTER_GEMINI_MODEL='gemini-3.6-flash'
export VULNHUNTER_GEMINI_CONNECT_TIMEOUT_SECONDS=5
export VULNHUNTER_GEMINI_TIMEOUT_SECONDS=75
```

For a file-based secret instead:

```bash
printf '%s' 'YOUR_KEY' > ~/.gemini-api-key
chmod 600 ~/.gemini-api-key
export VULNHUNTER_GEMINI_ENABLED=true
export VULNHUNTER_GEMINI_API_KEY_FILE="$HOME/.gemini-api-key"
```

In GitHub Codespaces, prefer a Codespaces secret/environment variable rather than writing the API key into a tracked file.

## Ollama

The default local fallback model is `qwen3:1.7b`.

Install/start Ollama in the same machine/container where the VulnHunter Django process runs, then pull the model:

```bash
ollama pull qwen3:1.7b
ollama serve
```

Configure VulnHunter:

```bash
export VULNHUNTER_OLLAMA_ENABLED=true
export VULNHUNTER_OLLAMA_API_BASE='http://127.0.0.1:11434'
export VULNHUNTER_OLLAMA_MODEL='qwen3:1.7b'
export VULNHUNTER_OLLAMA_CONNECT_TIMEOUT_SECONDS=2
export VULNHUNTER_OLLAMA_TIMEOUT_SECONDS=120
```

For safety, the integration accepts only loopback Ollama addresses (`127.0.0.1`, `localhost`, or `::1`). Do not expose an unauthenticated Ollama endpoint directly to the public internet.

### Codespaces and Termux

`127.0.0.1` always means the machine/container running VulnHunter. If Django is running in a GitHub Codespace while Ollama is running in Termux on an Android phone, the Codespace cannot reach the phone by using `127.0.0.1`.

For the simplest free development setup, either:

- run Django and Ollama together in Termux, or
- run Django and Ollama together in the same Codespace while that Codespace is active.

A remote phone-hosted Ollama fallback for a Codespace would need an authenticated private tunnel/proxy; do not make port 11434 public just to connect the two.

## Expected ordinary-chat behavior

```text
User message
    |
    v
  Groq
    | unavailable / rate limited / timeout / circuit cooldown
    v
 Gemini
    | unavailable / rate limited / timeout / circuit cooldown
    v
 Ollama (loopback)
    |
    v
Normal VulnHunter conversational response
```

The same redacted prompt, durable memory, recent conversation, and read-only workspace context are supplied through the existing conversation service, so switching providers does not create a new conversation or reset the authoritative task timeline.

No smaller-model downgrade is permitted merely because a provider failed. Provider switching is a conversational availability mechanism, not permission for a lower-quality or unapproved model profile.

## What does not fail over this way

The conversational chain above must not be confused with:

- deterministic authorization/scope/approval logic;
- scanner or worker execution;
- vulnerability verification or finding promotion;
- Source Hunt source-code approval bound to an exact provider/model;
- the analyst/critic/synthesizer finding-intelligence session that is pinned to its configured reasoning model;
- publication or human review.

Those systems keep their existing fail-closed contracts.

## Quick verification

Run the focused tests:

```bash
pytest -q \
  tests/unit/test_conversation_reasoning.py \
  tests/unit/test_activity_failover_continuity.py \
  tests/unit/test_ai_failover_reasoning_controls.py
```

The focused coverage includes Groq -> Gemini failover, Groq + Gemini -> Ollama failover, all-providers-unavailable behavior, circuit cooldown/recovery continuity, high-reasoning controls, and split connect/read timeout handling.
