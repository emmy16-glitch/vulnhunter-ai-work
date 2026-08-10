# UI Acceptance Criteria

A product-facing UI change is acceptable only when all applicable conditions pass:

1. Unauthorized routes/actions are rejected by backend services.
2. Assessment creation/execution cannot bypass the required authorization contract.
3. Scope, approval/confirmation, active state, blockers, cancellation and terminal state are truthful and understandable.
4. Findings preserve redaction, evidence provenance and assessment/workspace ownership.
5. Reviewer/adjudicator independence and other separation-of-duty rules remain backend-enforced.
6. Release/publication blockers are explicit and cannot be bypassed through UI state.
7. Every affected loading, empty, blocked, approval-required, authorization-required, recovery, failure, cancellation and success state is designed.
8. Long-running task state survives refresh/disconnect and reconstructs from persisted backend truth rather than browser memory.
9. While supported work is running, the composer remains usable and follow-up instructions can be visibly queued without interrupting the active task.
10. Desktop, tablet and mobile support the same critical workflow semantics; mobile is not an unrelated dashboard redesign.
11. Keyboard, focus, contrast, semantic labels, screen-reader announcements, touch targets and reduced-motion behaviour are verified.
12. Visuals comply with `docs/design/VULNHUNTER_UI_CONTRACT.md` and only approved reference usage in `docs/design/references/manifest.json`.
13. Shared tokens/components are reused; page-local colour, spacing, radius, shadow and typography systems are not introduced.
14. The everyday shell remains chat/task-first; specialist capabilities are progressively disclosed rather than all promoted to permanent top-level navigation.
15. No unsupported SSO, account tier, provider/model selector, Pause control, fake progress or reference-product branding is introduced from a screenshot.
16. A contextual card does not grant authority: authorization, approval, verification, review, adjudication, merge, release and publication remain backend decisions.
17. Any deliberate deviation from the locked UI contract is documented and approved as a product-design change before implementation.

Passing backend tests does not excuse a contradictory or non-compliant UI. A visually attractive screenshot does not excuse fabricated state or an unsupported action.
