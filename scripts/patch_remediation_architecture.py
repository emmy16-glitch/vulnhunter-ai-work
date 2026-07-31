from pathlib import Path

path = Path("docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md")
text = path.read_text(encoding="utf-8")

replacements = {
    """## 5.10 Governed remediation planning — `DONE` foundation

- ordinary chat can request remediation only by exact independently verified finding ID;
- password re-authentication and exact bounded plan confirmation remain on a protected page;
- the generic finding store atomically binds the remediation owner, exact finding revision and fingerprint, bounded target references, RED security test, independent verification recipe, evidence references, compatibility risks, expiry and immutable plan digest;
- compare-and-swap revision control rejects stale writers and timestamps cannot move the finding lifecycle backwards;
- the originating conversation receives a workspace-bound child task graph and deduplicated status events across browser or device reconnects;
- the graph stops truthfully at `awaiting_developer_implementation` and terminal cancellation returns the verified finding to triaged state while cancelling all future graph claims;
- no natural-language plan is executed as a command and no password is consumed from ordinary chat.

This foundation does not edit source, run engineering commands, record a changed revision, verify a fix, retest, merge, close a finding or publish a result. Replacement plans after terminal cancellation are also outside this slice.
""": """## 5.10 Governed remediation planning and fixed-revision verification — `DONE` foundation

- ordinary chat can request remediation only by exact independently verified finding ID and can open, resume and query the same durable remediation workspace;
- password re-authentication and exact bounded plan confirmation remain on a protected page;
- the generic finding store atomically binds the remediation owner, exact finding revision and fingerprint, bounded target references, RED security test, independent verification recipe, evidence references, compatibility risks, expiry and immutable plan digest;
- compare-and-swap revision control rejects stale writers and timestamps cannot move the finding lifecycle backwards;
- a protected implementation handoff accepts typed evidence only and binds the active plan to exact original and fixed repository snapshots, approved and changed paths, builder identity, deterministic security and regression receipts, fixed source references and the immutable verifier verdict;
- the existing independent `ReadOnlyFixVerifier` receives no write, shell, merge or publication authority, and submitted snapshot or receipt text is never executed as a command;
- every implementation attempt is retained as an integrity-checked append-only receipt; non-fixed verdicts return the same graph to bounded `needs_rework`, while only `fixed` advances the finding and graph to `ready_for_retest`;
- the originating conversation receives deduplicated receipt and verdict events across browser or device reconnects;
- terminal cancellation remains available before a fixed verdict and returns the verified finding to triaged state while cancelling all future graph claims.

This foundation does not implement or authorise source patch execution, run a governed retest, approve independent review, merge code, close a finding or publish a result. Replacement plans after terminal cancellation are also outside this slice.
""",
    """| General agent-to-tool integration | `PARTIAL` | Website, APK, Source Hunt, Active Validation and verified-finding remediation planning now use workspace-bound authoritative task graphs; developer implementation receipts, fix verification, retest, downstream review and reporting still require migration. |""": """| General agent-to-tool integration | `PARTIAL` | Website, APK, Source Hunt, Active Validation, verified-finding remediation planning and fixed-revision read-only verification now use workspace-bound authoritative task graphs; controlled patch-execution integration, governed retest, downstream review and reporting still require migration. |""",
    """**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation and verified-finding remediation planning now create workspace-bound authoritative task graphs and project approval, queue, execution readiness, cancellation, failed-closed and user-facing chat stages from durable stores. Developer implementation receipts, fix verification, retest, downstream evidence completion, review and reporting still require migration to the shared graph.""": """**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation, verified-finding remediation planning and immutable fixed-revision verification receipts now create or update workspace-bound authoritative task graphs and project approval, queue, execution readiness, bounded rework, fixed-verdict progression, cancellation, failed-closed and user-facing chat stages from durable stores. Controlled patch-execution integration, governed retest, downstream review and reporting still require migration to the shared graph.""",
    """**Implementation status:** `IN_PROGRESS` — the verified-finding intake, human-owned bounded plan, exact targets, RED test, independent verification recipe, immutable plan digest, CAS finding transition, chat workspace binding and pre-implementation cancellation are implemented. Developer-led patch execution, changed-revision receipts, GREEN and broader test evidence, read-only fix-verifier execution, independent review and human-controlled merge remain unfinished.""": """**Implementation status:** `IN_PROGRESS` — the verified-finding intake, human-owned bounded plan, exact targets, RED test, independent verification recipe, immutable plan digest, CAS finding transition, chat workspace binding, protected fixed-revision handoff, append-only deterministic security and regression receipts, independent read-only fix-verifier verdicts, bounded rework and `ready_for_retest` projection are implemented. Developer-led patch execution through controlled engineering orchestration, governed retest, independent review and human-controlled merge remain unfinished.""",
}

for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one canonical architecture block, found {count}")
    text = text.replace(old, new)

path.write_text(text, encoding="utf-8")
