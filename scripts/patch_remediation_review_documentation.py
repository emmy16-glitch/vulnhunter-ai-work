from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block, found {count}")
    return text.replace(old, new)


architecture_path = Path("docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md")
architecture = architecture_path.read_text(encoding="utf-8")
architecture = replace_once(
    architecture,
    """This foundation records and evaluates typed retest evidence. Specialised website, source and APK retest runners, the independent remediation-review decision, final report generation, human-controlled merge, closure and publication remain separate unfinished milestones.

---
""",
    """This foundation records and evaluates typed retest evidence. Specialised website, source and APK retest runners, final report generation, human-controlled merge, closure and publication remain separate unfinished milestones.

## 5.12 Independent remediation review and report readiness — `DONE` foundation

- independent review starts only from an exact independently verified finding whose latest governed retest passed;
- the review plan binds the exact finding revision and fingerprint, remediation ID, fixed-verification receipt, passed retest receipt, fixed revision, evidence references, reviewer identity digest, creation time, expiry and immutable plan digest;
- the reviewer must hold an active governed reviewer identity and authenticate with the governance secret on a protected page; ordinary chat can route and report status but cannot consume the secret, checklist or decision authority;
- the reviewer is rejected when they are also the remediation owner, implementation builder, read-only fix verifier or retest operator;
- VulnHunter computes `approved`, `changes_requested`, `cannot_verify` or `blocked` from a typed evidence checklist rather than accepting an ungrounded approve value;
- the complete decision is stored in an append-only, identity-bound HMAC-SHA256 envelope using a dedicated owner-private signing-key file;
- compare-and-swap finding updates reject stale writers and delete a newly written signed receipt if the authoritative transition loses;
- approved review advances only to `ready_for_report`; changes requested, blocked and cannot-verify outcomes preserve all prior receipts and return the remediation to bounded review rework;
- the parent remediation graph and durable chat workspace project the same signed decision, report-readiness gate and rework state across browser or device reconnects.

This foundation does not generate the final report, merge code, mark the finding remediated or closed, release an artifact or publish a result. External portable signatures, key rotation and revocation remain later production-hardening work.

---
""",
    label="independent remediation review foundation",
)
architecture = replace_once(
    architecture,
    """| General agent-to-tool integration | `PARTIAL` | Website, APK, Source Hunt, Active Validation, verified-finding remediation planning, fixed-revision read-only verification and governed retest now use workspace-bound authoritative task graphs; controlled patch-execution integration, the independent review decision and final reporting still require migration. |""",
    """| General agent-to-tool integration | `PARTIAL` | Website, APK, Source Hunt, Active Validation, verified-finding remediation planning, fixed-revision read-only verification, governed retest and independent remediation review now use workspace-bound authoritative task graphs; controlled patch-execution integration and final reporting still require migration. |""",
    label="task graph gap row",
)
architecture = replace_once(
    architecture,
    """**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation, verified-finding remediation planning, immutable fixed-revision verification and governed retest now create or update workspace-bound authoritative task graphs and project approval, queue, execution readiness, bounded rework, fixed-verdict progression, before/after retest outcomes, independent-review readiness, cancellation, failed-closed and user-facing chat stages from durable stores. Controlled patch-execution integration, the independent remediation-review decision and final reporting still require migration to the shared graph.""",
    """**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation, verified-finding remediation planning, immutable fixed-revision verification, governed retest and signed independent remediation review now create or update workspace-bound authoritative task graphs and project approval, queue, execution readiness, bounded rework, fixed-verdict progression, before/after retest outcomes, reviewer decisions, report readiness, cancellation, failed-closed and user-facing chat stages from durable stores. Controlled patch-execution integration and final report generation still require migration to the shared graph.""",
    label="Step 18 status",
)
architecture = replace_once(
    architecture,
    """**Implementation status:** `IN_PROGRESS` — the verified-finding intake, human-owned bounded plan, exact targets, RED test, independent verification recipe, immutable plan digest, CAS finding transition, chat workspace binding, protected fixed-revision handoff, append-only deterministic security and regression receipts, independent read-only fix-verifier verdicts, bounded rework, governed before/after retest receipts and `awaiting_remediation_review` readiness are implemented. Developer-led patch execution through controlled engineering orchestration, the independent review decision and human-controlled merge remain unfinished.""",
    """**Implementation status:** `IN_PROGRESS` — the verified-finding intake, human-owned bounded plan, exact targets, RED test, independent verification recipe, immutable plan digest, CAS finding transition, chat workspace binding, protected fixed-revision handoff, append-only deterministic security and regression receipts, independent read-only fix-verifier verdicts, bounded rework, governed before/after retest receipts, identity-separated signed remediation review and `ready_for_report` gating are implemented. Developer-led patch execution through controlled engineering orchestration and human-controlled merge remain unfinished.""",
    label="Step 27 status",
)
architecture = replace_once(
    architecture,
    """### Step 29 — Complete report and export contracts

Deliver:
""",
    """### Step 29 — Complete report and export contracts

**Implementation status:** `IN_PROGRESS` — signed independent remediation review can now open an authoritative `ready_for_report` gate only after an exact passed retest. Stable final report schemas, evidence rendering, export manifests, integrity hashes, PDF activation and separate release authorisation remain unfinished.

Deliver:
""",
    label="Step 29 status",
)
architecture_path.write_text(architecture, encoding="utf-8")


env_path = Path(".env.example")
env = env_path.read_text(encoding="utf-8")
env = replace_once(
    env,
    "VULNHUNTER_REMEDIATION_REVIEW_ROOT=/srv/vulnhunter/evidence/remediation-reviews\n",
    "VULNHUNTER_REMEDIATION_REVIEW_ROOT=/srv/vulnhunter/evidence/remediation-reviews\nVULNHUNTER_REMEDIATION_REVIEW_SIGNING_KEY_FILE=/run/secrets/remediation_review_signing_key\n",
    label="review signing key configuration",
)
env_path.write_text(env, encoding="utf-8")
