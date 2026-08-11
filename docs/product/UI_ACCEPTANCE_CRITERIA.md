# UI Acceptance Criteria

**Binding visual contract:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Binding agent implementation standard:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`

A product-facing UI change is acceptable only when **all applicable conditions pass**. Backend correctness alone is not sufficient.

## 1. Security and state truth

1. Unauthorized routes/actions are rejected by backend services.
2. Assessment creation/execution cannot bypass the required authorization contract.
3. Scope, approval/confirmation, active state, blockers, cancellation and terminal state are truthful and understandable.
4. Findings preserve redaction, evidence provenance and assessment/workspace ownership.
5. Reviewer/adjudicator independence and other separation-of-duty rules remain backend-enforced.
6. Release/publication blockers are explicit and cannot be bypassed through UI state.
7. A contextual card never grants authority: authorization, confirmation, approval, verification, review, adjudication, merge, release and publication remain backend decisions.
8. The browser does not invent progress percentages, findings, evidence counts, readiness, authorization, approval, tool success, recovery success or completion.
9. Unknown/unavailable backend state is displayed as unknown/unavailable rather than replaced with demonstration data.

## 2. Product architecture

10. The everyday product remains conversation/task-first rather than dashboard-first.
11. The primary shell is a compact task/chat sidebar or mobile drawer + main conversation/task flow + persistent composer.
12. Specialist capabilities are progressively disclosed instead of all promoted to permanent top-level navigation.
13. Findings, evidence, approvals, authorization requirements, Source Hunt setup, APK uploads, tool receipts, recovery/failure and report readiness appear contextually in chat/task flow first when practical.
14. A specialist/deep view renders the same persisted workspace state rather than creating a competing workflow.
15. A contextual desktop detail drawer/panel is closed by default and opens only when detail is requested or required.
16. Source Hunt can be initiated from the conversational/task experience; a giant standalone form is not the primary product entry point.

## 3. Reference conformance

17. MonkeyCode is used only for task/workspace structure and interaction patterns.
18. Beautiful UI is used only for appropriate AI-native components/microinteractions.
19. VulnHunter keeps its own branding, product terminology, capability, security rules and warm editorial visual system.
20. No reference-product branding, Projects/account tiers, unsupported SSO, provider/model selector, Pause control, Fine-tune control, dictation feature or sample action is introduced without repository-backed capability and explicit product approval.
21. A “Thinking” state, when present, contains only safe user-facing activity text and never hidden chain-of-thought/private model reasoning.

## 4. Visual identity

22. The working canvas remains warm cream/off-white with the canonical subtle dotted treatment.
23. Dusty pink remains the primary/active accent; near-black remains the main technical text/border color; the compact dark sidebar remains the everyday shell anchor.
24. Normal cards/controls remain square or nearly square rather than adopting generic large SaaS radii.
25. Important elevation uses hard zero-blur offset shadows rather than soft floating shadows/glow.
26. No generic blue/white SaaS, neon cyberpunk, glassmorphism, frosted blur or decorative gradient system is introduced.
27. Typography follows the canonical grotesk-heading + monospace-technical roles.
28. Assistant/body copy has readable contrast against the cream canvas.
29. Whitespace is purposeful: the UI is not densely packed, but it also does not create giant empty regions while important task information is tiny.

## 5. Explicit anti-regression gates

A change **fails acceptance immediately** if it introduces or preserves any of these patterns on the affected surface without a separately approved exception:

30. Four large top cards for `Authorization / Scope / Approval / Active` on the ordinary chat workspace.
31. A default horizontal page toolbar containing `Source Hunt / Search / Export / History / New workspace`.
32. `Runs / Scanner / Execution / Entry point` KPI cards as the primary assessment workspace/history presentation.
33. A giant dark Source Hunt/admin panel as the normal conversational experience.
34. Multiple simultaneously competing navigation systems.
35. A permanent contextual detail panel when nothing has been opened.
36. A desktop grid/toolbar mechanically squeezed into the phone viewport.
37. Clipped primary actions or essential horizontal page scrolling on phone.
38. Tiny or low-contrast assistant/body text.
39. Another late-loaded global CSS patch layer created merely to override earlier contradictory styling.
40. A test weakened to preserve deprecated markup rather than update the presentation to the canonical contract.

## 6. Long-running task behavior

41. Every affected loading, empty, blocked, approval-required, authorization-required, queued, running, recovery, failure, cancellation and success state is designed.
42. Long-running task state survives refresh/disconnect and reconstructs from persisted backend truth rather than browser memory.
43. While supported work is running, the composer remains usable.
44. Follow-up instructions that cannot run immediately can be visibly queued where the backend supports that contract.
45. Refresh/reconnect does not restart work.
46. Cancel appears only when safe backend cancellation exists.
47. Pause does not appear unless an explicit backend pause/resume contract exists.

## 7. Mobile and responsive acceptance

48. Desktop, tablet and mobile support the same critical workflow semantics.
49. Mobile is a one-column AI task workspace; the desktop sidebar becomes an overlay drawer.
50. Meaningful workspace changes are checked at representative widths near `360`, `390`, `412`, `768`, `1024`, `1280` and `1440` CSS pixels.
51. There is no essential horizontal page scroll at supported phone widths.
52. Primary actions are not clipped or truncated.
53. Critical touch targets are at least approximately `44px`.
54. Primary phone body copy is normally in a readable range around `15–17px`; secondary metadata may be smaller but must remain legible.
55. The composer remains reachable and usable on phone during running, queued, approval and recovery states.
56. Large evidence/code/tables adapt to drawers, sheets, prioritized fields or deep views instead of shrinking the whole desktop presentation.
57. Long URLs, hashes, filenames and code do not break the viewport.

## 8. Accessibility

58. Keyboard navigation and logical focus order are verified.
59. Focus states remain visible.
60. Interactive controls have accessible names/labels.
61. Status is communicated by text/icon semantics as well as color.
62. Dialogs/drawers/sheets preserve and restore focus appropriately.
63. Reduced-motion preferences are respected.
64. Meaningful task-state updates are accessible to assistive technology where applicable.

## 9. Presentation architecture

65. Shared tokens/components/primitives are reused.
66. Page-local color, spacing, radius, shadow and typography systems are not introduced.
67. Before adding CSS, the implementation identifies the existing component/style owner.
68. Contradictory CSS is consolidated/refactored rather than hidden under cascade-order patches or routine `!important` use.
69. Duplicate mobile behavior for the same component is not spread unnecessarily across multiple override files.
70. CSP/no-inline-script requirements remain intact.

## 10. Required evidence of completion

71. A meaningful UI change is verified in a real browser, not only by template/unit tests.
72. Applicable phone evidence includes new/empty workspace, mobile drawer, running task, approval/confirmation, evidence/finding, Source Hunt/APK/recovery states when changed.
73. Applicable desktop evidence includes new/empty workspace, running task and contextual detail behavior.
74. The implementation is reviewed against the approved reference hierarchy and the explicit anti-regression gates above.
75. Actual tests/checks and remaining limitations are reported; rendering without an exception is not treated as UI acceptance.

## Final rule

Passing backend tests does not excuse a contradictory or non-compliant UI. A visually attractive screenshot does not excuse fabricated state or an unsupported action. A desktop-only interface does not satisfy the product. A generic dashboard does not satisfy VulnHunter even when every button works.
