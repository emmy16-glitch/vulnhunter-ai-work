# LLM runtime readiness

VulnHunter's conversational workspace can use Groq or the Hugging Face OpenAI-compatible router for advisory answers. Deterministic code still owns intent routing, target authorization, approval, scanner execution and publication.

A provider is not considered operational merely because its credential file exists. The supported readiness check now runs through the same bounded path used by the browser:

1. build the normal redacted conversational prompt;
2. invoke the selected provider wrapper;
3. validate the provider's structured response;
4. decode the user-facing chat answer;
5. verify a harmless readiness marker survived the complete path;
6. require provider and model identity in the final interpreted response.

## Configure Groq

Enable Groq in the deployment environment and set the configured owner-only key path. Then run:

```bash
python manage.py vh_configure_groq
```

The command stores the key with mode `0600` and immediately runs the exact web-chat readiness check. Use `--no-verify` only when network access is intentionally unavailable during setup.

## Configure Hugging Face

Enable Hugging Face in the deployment environment and set the configured owner-only token path. Then run:

```bash
python manage.py vh_configure_huggingface
```

The command stores the token with mode `0600` and immediately runs the exact web-chat readiness check.

## Verify an existing configuration

Use the provider-neutral command after configuration changes, model changes or deployment restarts:

```bash
python manage.py vh_verify_llm --provider auto
python manage.py vh_verify_llm --provider groq
python manage.py vh_verify_llm --provider huggingface
python manage.py vh_verify_llm --provider auto --json
```

A successful result reports the provider, exact model and reasoning budget. The command fails closed when:

- no remote provider completes the conversation path;
- the requested provider is not the provider that answered;
- the structured provider response cannot be decoded into a chat answer;
- the readiness marker is lost;
- model identity is absent;
- the application falls back to deterministic local copy.

## Scope

This check proves that one harmless LLM answer can pass through the deployed conversational integration. It does not authorize targets, run scanners, verify findings, measure model quality, prove security accuracy or grant the model decision authority.
