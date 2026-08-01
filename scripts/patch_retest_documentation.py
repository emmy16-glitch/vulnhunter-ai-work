from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"Expected exactly one {label} block, found {count}")
    return text.replace(old, new)


agents_path = Path("AGENTS.md")
agents = agents_path.read_text(encoding="utf-8")
agents = replace_once(
    agents,
    "## 4. Required engineering workflow\n\nBefore changing code:\n",
    """## 4. Required engineering workflow

Substantial delivery must also follow
`docs/engineering/TEST_ENGINEERED_BATCH_DELIVERY.md`. Related capabilities may be
combined into one dependency-aligned batch when they share one authoritative
lifecycle, trust boundary, cancellation model and acceptance path. Unrelated
features must not be bundled merely to reduce pull-request count. No required
test, security, browser, phone, worker or repository gate may be bypassed or
weakened to make a batch pass.

Before changing code:
""",
    label="AGENTS engineering workflow",
)
agents_path.write_text(agents, encoding="utf-8")

architecture_path = Path("docs/intelligence/VULNHUNTER_MASTER_ARCHITECTURE.md")
architecture = architecture_path.read_text(encoding="utf-8")
architecture = replace_once(
    architecture,
    """This foundation does not implement or authorise source patch execution, run a governed retest, approve independent review, merge code, close a finding or publish a result. Replacement plans after terminal cancellation are also outside this slice.

---
""",
    """This foundation does not implement or authorise source patch execution, approve an independent review decision, merge code, close a finding or publish a result. Replacement remediation plans after terminal cancellation are also outside this slice.

## 5.11 Governed retest and independent-review readiness — `DONE` foundation

- a protected retest plan is bound to the exact independently verified finding, active remediation, latest fixed-verification receipt, fixed revision, original evidence identifiers, bounded check references, owner, expiry and immutable plan digest;
- ordinary chat can start, reopen and query the same durable retest workspace but cannot consume passwords, evidence JSON or deterministic check authority;
- typed before and after evidence references and deterministic check receipts are validated and stored in an integrity-checked append-only retest bundle; submitted text is never executed as a command;
- VulnHunter computes truthful `passed`, `failed`, `partial`, `cannot_verify`, `blocked` and `cancelled` outcomes rather than accepting a browser-selected result;
- compare-and-swap finding updates reject stale writers and remove a newly written receipt when the authoritative transition fails;
- a passed retest advances only to `awaiting_remediation_review`; it does not mark the finding remediated, closed, merged, reported or published;
- failed, partial, blocked and cannot-verify outcomes preserve prior evidence and return the remediation to a truthful rework state while keeping review and report stages blocked;
- cancellation is append-only and returns the exact fixed finding to `ready_for_retest` without reusing the terminal retest plan;
- the dedicated retest child graph and parent remediation graph survive browser disconnects and project the same outcome, independent-review readiness and preliminary report-blocking state into the originating chat workspace.

This foundation records and evaluates typed retest evidence. Specialised website, source and APK retest runners, the independent remediation-review decision, final report generation, human-controlled merge, closure and publication remain separate unfinished milestones.

---
""",
    label="governed retest foundation",
)
architecture = replace_once(
    architecture,
    """| General agent-to-tool integration | `PARTIAL` | Website, APK, Source Hunt, Active Validation, verified-finding remediation planning and fixed-revision read-only verification now use workspace-bound authoritative task graphs; controlled patch-execution integration, governed retest, downstream review and reporting still require migration. |""",
    """| General agent-to-tool integration | `PARTIAL` | Website, APK, Source Hunt, Active Validation, verified-finding remediation planning, fixed-revision read-only verification and governed retest now use workspace-bound authoritative task graphs; controlled patch-execution integration, the independent review decision and final reporting still require migration. |""",
    label="general task-graph status row",
)
architecture = replace_once(
    architecture,
    """**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation, verified-finding remediation planning and immutable fixed-revision verification receipts now create or update workspace-bound authoritative task graphs and project approval, queue, execution readiness, bounded rework, fixed-verdict progression, cancellation, failed-closed and user-facing chat stages from durable stores. Controlled patch-execution integration, governed retest, downstream review and reporting still require migration to the shared graph.""",
    """**Implementation status:** `IN_PROGRESS` — website, APK, Source Hunt, Active Validation, verified-finding remediation planning, immutable fixed-revision verification and governed retest now create or update workspace-bound authoritative task graphs and project approval, queue, execution readiness, bounded rework, fixed-verdict progression, before/after retest outcomes, independent-review readiness, cancellation, failed-closed and user-facing chat stages from durable stores. Controlled patch-execution integration, the independent remediation-review decision and final reporting still require migration to the shared graph.""",
    label="Step 18 status",
)
architecture = replace_once(
    architecture,
    """**Implementation status:** `IN_PROGRESS` — the verified-finding intake, human-owned bounded plan, exact targets, RED test, independent verification recipe, immutable plan digest, CAS finding transition, chat workspace binding, protected fixed-revision handoff, append-only deterministic security and regression receipts, independent read-only fix-verifier verdicts, bounded rework and `ready_for_retest` projection are implemented. Developer-led patch execution through controlled engineering orchestration, governed retest, independent review and human-controlled merge remain unfinished.""",
    """**Implementation status:** `IN_PROGRESS` — the verified-finding intake, human-owned bounded plan, exact targets, RED test, independent verification recipe, immutable plan digest, CAS finding transition, chat workspace binding, protected fixed-revision handoff, append-only deterministic security and regression receipts, independent read-only fix-verifier verdicts, bounded rework, governed before/after retest receipts and `awaiting_remediation_review` readiness are implemented. Developer-led patch execution through controlled engineering orchestration, the independent review decision and human-controlled merge remain unfinished.""",
    label="Step 27 status",
)
architecture = replace_once(
    architecture,
    """### Step 28 — Complete retest workflows

Website, source and APK retests must run only checks relevant to the remediation claim and preserve original evidence lineage.
""",
    """### Step 28 — Complete retest workflows

**Implementation status:** `IN_PROGRESS` — the generic governed retest foundation now binds the exact fixed revision and prior evidence, accepts typed before/after evidence and deterministic receipts, computes truthful outcomes, persists append-only receipts, survives reconnects, blocks review/report on non-passing outcomes and opens only independent-review readiness after a pass. Specialised website, source and APK retest runners and their operational acceptance remain unfinished.

Website, source and APK retests must run only checks relevant to the remediation claim and preserve original evidence lineage.
""",
    label="Step 28 status",
)
architecture_path.write_text(architecture, encoding="utf-8")
