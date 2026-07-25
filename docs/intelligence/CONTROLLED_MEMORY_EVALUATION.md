# Controlled Memory and Evaluation

VulnHunter may improve from reviewed outcomes, but a model cannot silently rewrite its own
instructions, authorization rules, scope, severity, publication state, or tool permissions.

## Lifecycle

```text
AI analysis
→ pending memory candidate
→ authenticated human review
→ deterministic evaluation suite
→ authenticated administrator promotion
→ bounded retrieval in later advisory analysis
```

Only `PROMOTED` memory is retrievable by the intelligence worker. Pending, rejected, retired, or
unevaluated candidates never enter a model prompt.

The current memory classes are:

- **episodic**: a reviewed lesson from one assessment;
- **semantic**: a reviewed security fact or qualification;
- **procedural**: a reviewed verification or remediation method.

Every candidate is bound to its source analysis, finding, run, and evidence digests. Candidate
content is advisory-only and has no authority effect.

## Promotion gates

Promotion requires all of the following:

1. An authenticated governance reviewer or administrator approves the candidate and records a reason.
2. The controlled evaluation suite passes grounding, safety, usefulness, and regression checks.
3. An authenticated campaign administrator explicitly promotes the candidate.
4. The candidate remains evidence-bound and contains no self-granted authority instruction.

Store the governance secret in an owner-only file rather than placing it in shell history:

```bash
install -m 600 /dev/null ~/.vulnhunter-governance-secret
printf '%s' '<governance-secret>' > ~/.vulnhunter-governance-secret
```

Use the management command with the authenticated governance identity:

```bash
python manage.py vh_manage_learning --list \
  --actor analyst-id --secret-file ~/.vulnhunter-governance-secret
python manage.py vh_manage_learning --approve memory-... \
  --actor analyst-id --secret-file ~/.vulnhunter-governance-secret \
  --reason "Reviewed evidence supports this bounded lesson."
python manage.py vh_manage_learning --evaluate memory-... \
  --actor analyst-id --secret-file ~/.vulnhunter-governance-secret
python manage.py vh_manage_learning --promote memory-... \
  --actor campaign-admin-id --secret-file ~/.vulnhunter-governance-secret
```

When the command is run interactively, `--secret-file` may be omitted and the secret is requested
through a hidden prompt. Non-interactive runs must provide an owner-only secret file. Reviewer and
administrator identities may list, review and evaluate candidates; promotion requires the
`campaign_admin` governance role.

Enable candidate generation and memory retrieval with:

```text
VULNHUNTER_LEARNING_ENABLED=true
VULNHUNTER_LEARNING_ROOT=.local/controlled-memory
```

## High-impact capabilities

The AI may create a structured proposal for:

- a network request;
- an authorization change;
- a severity change;
- publication;
- an exploit action in an approved test environment.

A proposal is not permission. The capability broker requires the correct human role, exact active
scope where applicable, deterministic verification, and isolation for exploit actions. No capability
is automatically executable. Authorization grants remain controlled by an authorization owner;
severity changes require a security analyst; publication requires a publisher; exploit actions
require an approved isolated environment and its owner.

This lets VulnHunter plan powerful work without allowing the model to grant itself power.
