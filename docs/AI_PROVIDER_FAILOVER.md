# Conversational AI failover

VulnHunter's conversational advisory path can use a silent provider chain:

1. Groq (existing primary)
2. Gemini (free-tier cloud fallback)
3. Ollama (local fallback)

The deterministic VulnHunter backend remains authoritative for authorization, scope, scanner execution, verification, severity, and publication. Provider failover applies only to conversational/advisory reasoning.

## What counts as a failover

The router continues to the next provider when the current provider is disabled, not configured, times out, is rate-limited, returns a temporary server/transport error, abstains, or returns an unusable answer.

The browser does not receive provider-switch error details. A successful fallback is returned as a normal conversational answer with the provider identified internally as `auto`.

If every configured provider is unavailable, the user receives only a short retry message.

## Gemini

Create a Gemini Developer API key and store it as a secret. Do not commit the key to this repository.

Recommended environment values:

```bash
export VULNHUNTER_GEMINI_ENABLED=true
export VULNHUNTER_GEMINI_API_KEY='YOUR_KEY'
export VULNHUNTER_GEMINI_MODEL='gemini-3.6-flash'
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

The default local model is `qwen3:1.7b`.

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
export VULNHUNTER_OLLAMA_TIMEOUT_SECONDS=120
```

For safety, the integration accepts only loopback Ollama addresses (`127.0.0.1`, `localhost`, or `::1`). Do not expose an unauthenticated Ollama endpoint directly to the public internet.

### Codespaces and Termux

`127.0.0.1` always means the machine/container running VulnHunter. If Django is running in a GitHub Codespace while Ollama is running in Termux on an Android phone, the Codespace cannot reach the phone by using `127.0.0.1`.

For the simplest free development setup, either:

- run Django and Ollama together in Termux, or
- run Django and Ollama together in the same Codespace while that Codespace is active.

A remote phone-hosted Ollama fallback for a Codespace would need an authenticated private tunnel/proxy; do not make port 11434 public just to connect the two.

## Expected behavior

```text
User message
    |
    v
  Groq
    | unavailable / rate limited / timeout
    v
 Gemini
    | unavailable / rate limited / timeout
    v
 Ollama
    |
    v
Normal VulnHunter response
```

The same redacted prompt, durable memory, recent conversation, and read-only workspace context are supplied through the existing conversation service, so switching providers does not create a new conversation.

## Quick verification

Run the focused tests:

```bash
pytest -q tests/unit/test_conversation_reasoning.py
```

The suite includes cases for Groq -> Gemini failover, Groq + Gemini -> Ollama failover, and the all-providers-unavailable path.
