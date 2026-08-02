# LLM and Hugging Face Runtime Readiness

**Status:** Implemented end-to-end provider verification plus binding capability-readiness standard  
**Routing policy:** [`AI_ROUTING.md`](AI_ROUTING.md)  
**Production architecture:** [`../intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md`](../intelligence/ML_AND_HUGGING_FACE_PRODUCTION_ARCHITECTURE.md)

## 1. Purpose

VulnHunter's conversational workspace can use optional Groq or Hugging Face advisory providers.

Deterministic code still owns:

- intent and action routing;
- authentication and role checks;
- target authorisation;
- approval;
- scanner/worker execution;
- lifecycle state;
- evidence integrity;
- finding verification;
- human review;
- report release and publication.

Runtime readiness proves only that an approved provider/model combination can complete its bounded deployed task contract.

It does not prove model quality, security accuracy, calibration, vulnerability-detection performance or production-classifier status.

## 2. Readiness dimensions

Do not collapse readiness into one boolean.

Track separately:

1. **enabled**
   - deployment allows the provider.

2. **credential configured**
   - credential path/configuration exists.

3. **credential file valid**
   - regular owner-controlled file;
   - strict permissions;
   - valid bounded token/key value.

4. **model profile approved**
   - provider/model/task/data-class profile exists and is not revoked.

5. **capability profile valid**
   - exact request parameters, context and output contract are known.

6. **endpoint reachable**
   - a current bounded network request can reach the approved endpoint.

7. **end-to-end path verified**
   - the exact browser conversational construction, provider wrapper, structured decoder and user-facing interpretation succeed.

8. **healthy/degraded/disabled**
   - current operational state, distinct from model quality.

9. **model quality state**
   - research/candidate/approved/shadow/active/degraded/etc.; this is a separate ML registry concern.

A provider may be configured but unreachable. It may be reachable but fail structured output. It may answer correctly while the model remains unsuitable for a security task.

## 3. Current end-to-end readiness check

The implemented provider-neutral verification path:

1. builds the normal redacted conversational prompt;
2. applies deterministic task routing;
3. invokes the selected provider wrapper;
4. validates the provider's structured response;
5. decodes the user-facing chat answer;
6. verifies a harmless readiness marker survived the full path;
7. requires provider and model identity in the interpreted response;
8. rejects deterministic local fallback as a remote-provider success.

This is stronger than testing credential presence or a low-level HTTP call.

## 4. Current providers

Supported optional advisory providers are:

- Groq;
- Hugging Face OpenAI-compatible router.

Either may be disabled. Core workflows remain operational when both are disabled.

## 5. Configure Groq

Enable Groq in deployment configuration and use the owner-private key path.

```bash
python manage.py vh_configure_groq
```

The command stores the key with mode `0600` and normally runs the exact web-chat readiness check.

Use `--no-verify` only when network access is intentionally unavailable during setup. That state is configured but not end-to-end verified.

## 6. Configure Hugging Face

Enable Hugging Face and use the owner-private token path.

```bash
python manage.py vh_configure_huggingface
```

The command stores the token with mode `0600` and normally runs the exact web-chat readiness check.

The current remote endpoint is the bounded Hugging Face OpenAI-compatible router. Local Hugging Face model acquisition, embeddings and feature extraction are separate future subsystems and are not configured by this command.

## 7. Verify existing configuration

```bash
python manage.py vh_verify_llm --provider auto
python manage.py vh_verify_llm --provider groq
python manage.py vh_verify_llm --provider huggingface
python manage.py vh_verify_llm --provider auto --json
```

A successful result reports the actual provider and model used through the complete path.

## 8. Current verification failures

Verification fails closed when:

- no remote provider completes the path;
- requested and actual provider differ;
- model identity is absent;
- structured response cannot be decoded;
- readiness marker is lost;
- output is `ABSTAIN` or degraded;
- response exceeds configured bounds;
- application uses deterministic fallback;
- credentials/configuration are invalid;
- provider timeout/rate limit/protocol failure occurs.

## 9. Exact model capability profile

The target architecture must replace model-name-only configuration with an approved capability profile.

Required fields:

- profile ID and version;
- provider;
- model repository/name;
- exact revision or provider-resolved version where available;
- tokenizer repository/revision when relevant;
- approved task/output kinds;
- approved data classes;
- context window;
- maximum input bytes/tokens;
- maximum output bytes/tokens;
- structured JSON support;
- streaming support;
- reasoning-parameter support;
- temperature/top-p support and approved values;
- endpoint/backend classification;
- license and model-card review;
- data retention/residency review;
- capability-test timestamp;
- application version compatibility;
- lifecycle state: approved/degraded/retired/revoked.

Request construction uses this profile and omits unsupported parameters.

## 10. Revision pinning

A Hugging Face repository ID or provider model name can change over time.

Readiness and provenance should therefore record the strongest exact identity available:

- repository ID;
- commit/revision;
- provider system fingerprint;
- model files and digests for local use;
- tokenizer files and digests;
- inference backend/version.

When the remote provider does not expose an immutable revision, that limitation is documented and can restrict the profile to advisory use.

## 11. Hugging Face remote-provider readiness

The Hugging Face profile must verify:

- endpoint exactly matches approved router classification;
- token file is private and valid;
- model is in the explicit allowlist/profile registry;
- model accepts the approved request shape;
- structured JSON output is supported or safely adapted;
- output kind is allowed;
- bounded input/output works;
- cancellation works;
- timeout and rate-limit failures become safe degraded output;
- malformed or unexpected JSON is rejected;
- error messages redact tokens;
- provider and model provenance are retained;
- no redirect or unapproved endpoint occurs.

## 12. Groq readiness

Groq profiles require equivalent checks:

- exact approved endpoint;
- key-file safety;
- model/profile identity;
- structured output;
- budgets;
- timeout/cancellation;
- safe errors;
- full browser path;
- no authority or tools.

Provider-specific behaviour remains behind the provider-neutral contract.

## 13. Configured versus reachable

A provider health object must not say `reachable=true` merely because configuration is syntactically valid.

Recommended state:

```json
{
  "provider": "huggingface_advisory",
  "enabled": true,
  "credential_configured": true,
  "credential_file_valid": true,
  "model_profile_approved": true,
  "capability_verified": true,
  "reachable": false,
  "last_success_at": null,
  "last_failure_code": "NETWORK_UNAVAILABLE",
  "degraded": true
}
```

Reachability is based on a current or recent bounded verification, with an explicit freshness policy.

## 14. Token and context readiness

The current provider path retains conservative byte and approximate token bounds.

Target readiness records the token-accounting method:

1. exact revision-pinned tokenizer;
2. validated provider token accounting;
3. documented conservative approximation.

Test:

- normal input;
- exact limit;
- over-byte limit;
- over-token limit;
- long Unicode input;
- structured truncation;
- output limit;
- provider usage disagreement.

Byte bounds remain a security control even when token counting is exact.

## 15. Structured-output readiness

Verify the exact schema and output kinds.

Tests include:

- valid JSON object;
- missing required fields;
- extra forbidden fields;
- wrong output kind;
- empty content;
- oversized content;
- JSON wrapped in markdown;
- malformed Unicode;
- provider text refusal;
- partial response;
- invented authority language.

An invalid response becomes `ABSTAIN` or typed degraded state. It does not reach the product as successful structured output.

## 16. Streaming readiness

Streaming remains disabled unless the exact profile and adapter pass:

- incremental UTF-8 parsing;
- cumulative byte/token bounds;
- cancellation;
- read timeout;
- connection interruption;
- final schema validation;
- final digest/provenance;
- partial-output failure handling;
- no partial action execution;
- correct conversation UI recovery.

Streaming support is a profile capability, not a global provider assumption.

## 17. Citation and retrieval readiness

After evidence-grounded retrieval is implemented, a provider profile used for assessment-specific answers must pass:

- assessment-scoped context construction;
- tenant and role filtering;
- citation-label preservation;
- cited ID verification;
- rejection of invented citations;
- source digest verification;
- stale/deleted source handling;
- prompt-injection tests;
- bounded context and truncation.

Provider reachability alone does not prove retrieval readiness.

## 18. Source-processing readiness

A profile used for Source Hunt additionally requires:

- exact repository revision/snapshot approval;
- eligible path limits;
- source-retention/terms review;
- context minimisation;
- returned path/hash/line validation;
- prompt-injection tests in code/comments;
- source-specific budgets;
- no remote source use under an ordinary conversation approval.

## 19. Local Hugging Face model readiness

A future local encoder/embedding profile must verify:

- repository and exact revision;
- license;
- model and tokenizer file digests;
- safe weight format;
- remote custom code disabled or separately reviewed;
- dependency lock;
- model load in an isolated environment;
- memory and latency;
- numerical output shape;
- deterministic or declared nondeterministic behaviour;
- offline cache operation;
- task-specific evaluation;
- feature/index compatibility;
- rollback/removal.

A model loading successfully is not evidence that it improves VulnHunter.

## 20. Model supply-chain readiness

Before production use, require:

- approved source;
- exact artifact manifest;
- digest verification;
- vulnerability/license review of dependencies;
- tokenizer review;
- no arbitrary pickle execution;
- no unreviewed `trust_remote_code`;
- SBOM or equivalent manifest;
- registry entry;
- revocation/disable path.

## 21. Privacy readiness

Verify the complete routed prompt, not only the provider wrapper.

Tests ensure:

- credentials are absent;
- cookies/tokens/private keys are absent;
- private evidence follows deployment policy;
- source requires exact approval;
- tenant/assessment boundaries are preserved;
- provider errors do not echo secrets;
- logs contain hashes and safe metadata rather than prohibited raw content.

## 22. Failure taxonomy

Use typed provider/model readiness failures:

- `PROVIDER_DISABLED`;
- `CREDENTIAL_NOT_CONFIGURED`;
- `CREDENTIAL_FILE_INVALID`;
- `MODEL_PROFILE_NOT_APPROVED`;
- `MODEL_PROFILE_REVOKED`;
- `CAPABILITY_NOT_VERIFIED`;
- `MODEL_IDENTITY_MISMATCH`;
- `ENDPOINT_MISMATCH`;
- `NETWORK_UNREACHABLE`;
- `RATE_LIMITED`;
- `TIMEOUT`;
- `CANCELLED`;
- `UNSUPPORTED_PARAMETER`;
- `CONTEXT_LIMIT`;
- `MALFORMED_RESPONSE`;
- `STRUCTURED_OUTPUT_INVALID`;
- `OUTPUT_LIMIT`;
- `PRIVACY_ROUTE_DENIED`;
- `SOURCE_APPROVAL_REQUIRED`;
- `CITATION_VALIDATION_FAILED`;
- `DETERMINISTIC_FALLBACK_USED`.

Errors expose safe operator action and stable redacted references.

## 23. Readiness freshness

A successful verification has a freshness window.

Reverify after:

- provider configuration change;
- model/profile change;
- credential rotation;
- deployment restart or image change;
- dependency/runtime change;
- endpoint/terms change;
- repeated failures;
- elapsed policy interval.

Stale readiness is shown as stale, not healthy.

## 24. Startup and deployment policy

Deployment startup may verify local configuration synchronously, but should not make the complete product unavailable solely because an optional remote provider is unreachable.

Recommended behaviour:

- deterministic application starts;
- provider state becomes configured/stale/degraded;
- optional verification runs through a bounded operation;
- provider actions remain unavailable until policy permits;
- UI explains deterministic fallback.

## 25. Operational monitoring

Record:

- verification attempts;
- provider/model profile;
- result and failure code;
- latency;
- request/response sizes;
- last success/failure;
- rate limit and timeout rates;
- structured-output rejection;
- fallback use;
- profile/config revisions.

Do not store secret-bearing request bodies in readiness telemetry.

## 26. Product presentation

Show separately:

- `Hugging Face configured`;
- `Capability verified`;
- `Currently reachable`;
- `Last checked ...`;
- `Advisory provider degraded`;
- `Deterministic assessment workflow available`.

Do not display `AI ready` as a single ambiguous green badge.

Provider controls belong behind progressive disclosure or Settings, not as dominant controls in every ordinary conversation.

## 27. Readiness evidence

A readiness run should retain machine-readable evidence:

- application version;
- provider/profile ID;
- actual model identity;
- prompt template version;
- harmless input/output digests;
- timestamps;
- limits;
- result/failure code;
- no raw credential;
- environment/deployment identifier.

## 28. Tests

Test:

- Groq only;
- Hugging Face only;
- both enabled;
- neither enabled;
- requested provider mismatch;
- invalid credential path/permissions;
- configuration but no network;
- model/profile mismatch;
- unsupported parameter;
- exact structured-output path;
- timeout/rate limit/cancellation;
- malformed/oversized output;
- deterministic fallback;
- stale readiness;
- credential/model rotation;
- local Hugging Face model manifest when implemented;
- streaming/citations/source profiles when implemented.

## 29. Current-versus-target classification

```text
OWNER-PRIVATE GROQ CONFIGURATION                IMPLEMENTED
OWNER-PRIVATE HUGGING FACE CONFIGURATION        IMPLEMENTED
PROVIDER-NEUTRAL FULL CHAT-PATH VERIFICATION    IMPLEMENTED
STRUCTURED RESPONSE AND MODEL IDENTITY CHECK    IMPLEMENTED
DETERMINISTIC FALLBACK REJECTION                IMPLEMENTED
EXACT REVISION CAPABILITY PROFILE               NOT COMPLETE
CONFIGURED VERSUS REACHABLE HEALTH              PARTIAL
MODEL-SPECIFIC PARAMETER MATRIX                 NOT COMPLETE
TOKENIZER-EXACT ACCOUNTING                      NOT COMPLETE
STREAMING READINESS                             NOT COMPLETE
RETRIEVAL/CITATION READINESS                    NOT COMPLETE
LOCAL HUGGING FACE MODEL READINESS              NOT COMPLETE
SUPPLY-CHAIN/SBOM READINESS                     NOT COMPLETE
```

## 30. Definition of done

Runtime readiness is production-complete only when:

- enabled/configured/credential/profile/capability/reachability states are distinct;
- exact approved model profiles drive requests;
- revision/model identity is as strong as the backend permits;
- token, structured-output and streaming capabilities are tested per profile;
- privacy and source-processing routes pass end-to-end tests;
- citation/retrieval readiness is separately verified;
- local Hugging Face models have supply-chain and task evaluation gates;
- stale/degraded/disabled states are truthful;
- deterministic workflows remain operational without providers;
- readiness is never misrepresented as model quality or vulnerability accuracy.