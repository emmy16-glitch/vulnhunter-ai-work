# AI Routing — Ordinary Chat Resilience Amendment

**Status:** BINDING SCOPED AMENDMENT  
**Amends:** `docs/product/AI_ROUTING.md`  
**Scope:** ordinary non-authoritative conversation only  
**Does not amend:** authorization, scope, approval, execution, evidence, verification, finding intelligence, Source Hunt, review, adjudication, release, publication, or remediation authority

## Purpose

`AI_ROUTING.md` intentionally established a high-only, no-downgrade rule so a failed protected reasoning request could never silently become a weaker authority path. That security principle remains correct for protected reasoning and every state-changing or evidence-bearing workflow.

Applying the same rule to ordinary chat, however, makes the conversation surface unusable when the primary model has a transient timeout, capacity event, malformed response, or rate-limit abstention. Ordinary chat has no authority to authorize or execute anything, so it may use one explicitly configured same-provider recovery model without weakening the deterministic security boundary.

This document supersedes the older global no-model-downgrade wording in `AI_ROUTING.md` **only where the deterministic intent is exactly `chat`**. All other `AI_ROUTING.md` requirements remain binding.

## Exact routing rule

The browser conversation path first classifies the request deterministically.

```text
message
→ deterministic_intent
→ chat?
   ├─ no  → protected/high-only advisory path; no model downgrade
   └─ yes → bounded ordinary-chat advisory path
            → configured Groq primary model
            → if usable: answer
            → if safe abstain/failure: one configured Groq fallback-model attempt
            → if usable: answer
            → otherwise: temporary conversation-unavailable state
```

The fallback is never selected because a model recommends it. It is selected only by deterministic application code after the message is already classified as ordinary `chat` and the primary response is unusable.

## Current ordinary-chat model contract

Default settings:

```text
primary   VULNHUNTER_GROQ_MODEL          openai/gpt-oss-120b
fallback  VULNHUNTER_GROQ_FALLBACK_MODEL openai/gpt-oss-20b
```

The fallback model must be explicitly configured and allowlisted by the same Groq provider wrapper for that invocation path. There is no arbitrary model name supplied by the browser or user.

The request still uses `high` reasoning effort. The fallback changes model size, not authority.

## Smaller chat envelope

Ordinary chat uses a deliberately smaller prompt envelope than protected high-reasoning workflows:

- at most 6 recent user/assistant context items;
- at most 600 characters per retained recent item;
- bounded durable-memory summary;
- bounded read-only workspace context;
- bounded user request;
- 6,000 conservative input-token ceiling;
- 1,200 output-token ceiling;
- 90-second internal reasoning budget, still capped by deployment timeout configuration.

The purpose is to keep normal conversation responsive and reduce avoidable provider pressure. It does not expand what data may be sent remotely. Existing redaction, privacy, target minimization, credential prohibition, and prompt-injection boundaries remain unchanged.

## Eligible primary failures

An ordinary-chat fallback attempt may occur when the primary advisory attempt produces no usable answer because of a safe provider failure such as:

- provider `ABSTAIN`;
- timeout;
- capacity/rate-limit abstention;
- rejected provider configuration at invocation time;
- unexpected returned model identity;
- malformed or unusable structured response.

The fallback receives the same already-sanitized, bounded ordinary-chat prompt. A failure never expands context or permissions.

## Provider failover remains prohibited

This amendment does **not** enable automatic Groq → Hugging Face or any other provider failover.

Provider choice happens before invocation. If Groq is the selected provider, the resilient ordinary-chat path remains inside Groq. A different provider requires an explicit eligible provider-selection path under the normal routing policy.

## Deterministic fallback remains prohibited as fake AI

VulnHunter still does not generate canned deterministic prose and label it as a model answer when both model attempts fail.

If no eligible model produces a valid answer, the UI reports temporary conversation unavailability and makes clear that no security action was authorized or executed. Deterministic status/authorization/action services may still operate independently where their own contracts allow them.

## Protected paths remain high-only

The ordinary-chat fallback model must never be used to gain or influence authority for:

- target authorization or scope expansion;
- scan-plan approval or confirmation;
- scanner/tool execution;
- cancellation authority;
- persisted evidence truth;
- deterministic verification;
- vulnerability validation or final severity;
- finding intelligence analyst/critic/synthesizer stages;
- Source Hunt processing;
- reviewer or adjudicator decisions;
- remediation execution;
- merge/release/publication decisions.

In particular, a request classified as `scan` does not retry on `VULNHUNTER_GROQ_FALLBACK_MODEL` after primary-model abstention.

## Output trust

Both primary and fallback ordinary-chat responses remain:

```text
advisory_only = true
trusted = false
```

They can explain, teach, summarize supplied safe context, and suggest next questions. They cannot make an authoritative lifecycle transition.

## Required provenance

Conversation state must remain able to distinguish the actual model that answered. Runtime status may expose:

- configured primary model;
- configured ordinary-chat fallback model;
- whether same-provider model fallback is enabled;
- fallback scope = `ordinary_chat_only`;
- provider fallback = false;
- reasoning effort = high.

The assistant message must not claim the primary model answered when the fallback model actually produced the response.

## Tests

The scoped amendment is not complete unless automated tests prove at least:

1. an ordinary chat request can use the configured same-provider fallback after primary abstention;
2. the fallback response records the actual fallback model identity;
3. the ordinary-chat envelope uses its smaller input/output budget;
4. a scan request does not invoke the fallback model;
5. provider-disabled chat does not start a scan or authorize an action;
6. both-model failure remains non-executing and produces an explicit unavailable state;
7. provider failover remains disabled;
8. existing authorization, worker, verification, review, and publication tests remain green.

## Permanent boundary

> Chat may degrade gracefully. Authority may not.

This amendment changes conversation availability only. VulnHunter's deterministic backend remains the sole authority for security-sensitive state and execution.
