# UI Acceptance Criteria

**Status:** BINDING PRODUCT-FACING ACCEPTANCE GATE  
**Visual contract:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Agent standard:** `docs/design/AI_AGENT_UI_IMPLEMENTATION_STANDARD.md`  
**Live execution:** `docs/product/LIVE_EXECUTION_ACTIVITY.md`  
**Public targets:** `docs/product/PUBLIC_TARGET_ASSESSMENT.md`

A product-facing UI change is acceptable only when **all applicable conditions pass**. Backend correctness alone is not sufficient, and attractive screenshots do not excuse false state.

---

## 1. Security and state truth

1. Unauthorized routes/actions are rejected by backend services.
2. Assessment creation/execution cannot bypass authorization.
3. Public target status does not imply permission.
4. A public-target UI cannot claim execution capability when the selected worker is private-only.
5. Scope, confirmation, approval, running, blockers, cancellation and terminal state are truthful.
6. Findings preserve redaction, provenance and assessment/workspace ownership.
7. Reviewer/adjudicator independence remains backend-enforced.
8. Release/publication blockers remain backend-enforced.
9. A card never grants authorization/approval/verification/review/release authority.
10. Browser code never invents progress, findings, evidence counts, worker/tool identity, readiness, recovery or completion.
11. Unknown/unavailable state remains unknown/unavailable.
12. A browser `allow_public` flag, checkbox or URL class never becomes execution permission.

---

## 2. Product architecture

13. Everyday product remains conversation/task-first rather than dashboard-first.
14. Primary shell is compact task/chat navigation + main conversation/task flow + persistent composer.
15. Specialist capabilities are progressively disclosed.
16. Findings, evidence, authorization, plan decisions, Source Hunt, APK state, live activity, recovery/failure and report readiness appear contextually first when practical.
17. Specialist/deep views render the same persisted workspace/assessment state.
18. Desktop contextual detail is closed by default.
19. Source Hunt can be initiated from conversation/task context.
20. Website/private/public workflows share one product shell and lifecycle semantics.

---

## 3. Reference conformance

21. MonkeyCode is used only for task/workspace structure and interaction patterns.
22. Beautiful UI is used only for appropriate AI-native components/microinteractions.
23. VulnHunter keeps its own branding, terminology, capabilities, security rules and warm editorial visual system.
24. No reference-derived SSO, account tier, provider/model selector, Pause, Fine-tune, dictation or sample action is added without repository-backed capability.
25. “Thinking”/activity contains safe operational state only and never hidden chain-of-thought.

---

## 4. Visual identity

26. Working canvas remains canonical warm cream/off-white with subtle dotted treatment.
27. Dusty pink remains primary/active accent; near-black remains main text/border; compact dark sidebar remains shell anchor.
28. Cards/controls remain square/nearly square rather than generic large SaaS radii.
29. Important elevation uses hard zero-blur offset shadows rather than soft glow/floating shadows.
30. No generic blue/white SaaS, neon cyberpunk, glassmorphism, frosted blur or decorative gradient system.
31. Typography follows canonical grotesk heading + monospace technical roles.
32. Assistant/body copy is readable and high contrast.
33. Whitespace is purposeful and does not leave giant empty regions while critical task state is tiny.

---

## 5. Explicit anti-regression gates

A change fails immediately if it introduces/preserves on the affected surface without approved exception:

34. four large `Authorization / Scope / Approval / Active` cards on ordinary chat;
35. default horizontal `Source Hunt / Search / Export / History / New workspace` toolbar;
36. `Runs / Scanner / Execution / Entry point` KPI cards as primary workspace/history presentation;
37. giant dark Source Hunt/admin panel as ordinary conversation flow;
38. giant Source Hunt form as the main source-analysis entry point;
39. multiple competing navigation systems;
40. permanent context panel when no detail is opened;
41. desktop toolbar/grid mechanically squeezed onto phone;
42. clipped primary phone actions or essential horizontal page scroll;
43. tiny/low-contrast assistant/body text;
44. late-loaded global CSS patch layer created merely to override contradictory styling;
45. a test weakened to preserve deprecated markup;
46. a generic “backend is executing; go elsewhere to monitor” message as the only meaningful running-task state when the backend has activity data;
47. a public-target card that implies the scan is permitted merely because the hostname is public;
48. a fake tool/progress/activity indicator not backed by persisted state.

---

## 6. Long-running task behavior

49. Loading, queued, running, blocked, approval-required, authorization-required, recovery, failure, cancellation and success states are designed.
50. Long-running state survives refresh/disconnect and reconstructs from persisted backend truth.
51. Composer remains usable while supported work runs.
52. Follow-up instructions are visibly queued where backend supports it.
53. Refresh/reconnect does not restart work.
54. Cancel appears only when safe backend cancellation exists.
55. Pause does not appear without a real pause/resume backend contract.
56. Measured progress is shown only from bytes/declared stages/real emitted item counts.
57. Elapsed-time or browser-lifecycle fake percentages are forbidden.

---

## 7. Live execution activity acceptance

For each affected long-running workflow:

58. queued/running task has one stable persisted task identity.
59. current stage is derived from backend state/events.
60. completed stages remain visible.
61. next/pending stages are understandable.
62. active worker/tool is shown only when known.
63. latest persisted activity is visible in or directly from the conversation.
64. real receipt/evidence/candidate counts are surfaced where useful.
65. `View activity` opens the same persisted activity stream, not a separate browser-owned timeline.
66. reconnect deduplicates by stable event ID/sequence.
67. previously persisted events do not reanimate as new after reconnect.
68. failure preserves completed stages and evidence/receipt references.
69. recovery updates the same task.
70. terminal completion remains stable after refresh.
71. zero findings does not erase activity/evidence/history.
72. hidden model reasoning is never displayed.
73. if a workflow is `running` but the projection exposes only a generic timestamp despite richer worker information being available, acceptance fails.

See `docs/product/LIVE_EXECUTION_ACTIVITY.md`.

---

## 8. Public-target acceptance

When public-target UI is affected:

74. target is visibly classified as public where useful to the decision.
75. exact target/scheme/port/path are shown for authorization/plan decisions.
76. absence of authorization produces an explicit authorization-required state.
77. authorization basis/evidence reference is collected only through backend-supported flow.
78. an existing active exact authorization is reused instead of repeatedly asking for the same evidence.
79. private-only worker capability produces a truthful blocker, not a fake queued/running state.
80. a public-capable worker is shown only after backend capability says it is available.
81. immutable plan shows relevant target/profile/rate/concurrency/prohibited-action/digest state.
82. changed plan requires a new backend decision.
83. expired/revoked authorization updates the workspace truthfully.
84. public-target transport/security details are available under technical details when relevant, but ordinary task copy remains understandable.
85. UI cannot override DNS/address containment, worker target-class policy or private-network pivot protection.

See `docs/product/PUBLIC_TARGET_ASSESSMENT.md`.

---

## 9. Source Hunt acceptance

86. Source Hunt begins conversationally or contextually.
87. specialist setup is a focused continuation, not a separate product.
88. preflight shows resolved root/revision and predictable file/byte blockers when available.
89. effective file-count/repository-byte limits are shown from runtime configuration rather than stale hard-coded assumptions.
90. permitted-path wording matches actual snapshot/processing semantics.
91. predictable file-count/byte-limit failure is surfaced before full submission where practical.
92. queued Source Hunt binds to the originating workspace.
93. running hunt projects snapshot/inventory/hunt/falsification/capability/remediation activity where backend records it.
94. failure preserves snapshot/approval/activity/report identity.
95. reconnect does not create a new hunt.

---

## 10. Mobile and responsive acceptance

96. Desktop/tablet/mobile support the same critical workflow semantics.
97. Mobile is a one-column task workspace; desktop sidebar becomes overlay drawer.
98. Meaningful workspace changes are checked near `360`, `390`, `412`, `768`, `1024`, `1280`, `1440` CSS pixels.
99. No essential horizontal page scroll at supported phone widths.
100. Primary actions are not clipped/truncated.
101. Critical touch targets are approximately 44px minimum.
102. Primary phone body copy is normally around 15–17px; secondary metadata remains legible.
103. Composer remains reachable with keyboard open during running/queued/approval/recovery.
104. Evidence/code/tables adapt to sheets/cards/deep views instead of shrinking the desktop layout.
105. Long URLs/hashes/file paths do not break viewport.
106. Live activity/tool chips wrap cleanly on phone.

---

## 11. Accessibility

107. Keyboard navigation and logical focus order are verified.
108. Focus states are visible.
109. Interactive controls have accessible names.
110. Status is conveyed by text/icon semantics, not color alone.
111. Dialog/drawer/sheet focus is contained and restored.
112. Reduced motion is respected.
113. Meaningful task-state changes are available to assistive technology where applicable.
114. High-frequency activity updates do not overwhelm screen-reader users; announce important lifecycle changes rather than every heartbeat.

---

## 12. Presentation architecture

115. Shared tokens/components/primitives are reused.
116. Page-local palette/radius/shadow/type systems are not introduced.
117. Existing component/style owner is identified before adding CSS.
118. Contradictory CSS is consolidated/refactored rather than hidden behind cascade patches/`!important`.
119. Duplicate mobile behavior is not scattered across multiple override files.
120. CSP/no-inline-script requirements remain intact.
121. Browser lifecycle/state is not duplicated in a second frontend store when server projection already owns it.

---

## 13. Required evidence of completion

122. Meaningful UI changes are verified in a real browser.
123. Browser evidence uses real backend-connected routes/state, not only a static mock.
124. Phone evidence includes applicable new/empty, drawer, running, authorization/approval, activity, evidence/finding, Source Hunt/APK/recovery states.
125. Desktop evidence includes applicable empty/running/context-detail behavior.
126. Public-target changes include blocked and success scenarios only when the runtime can truthfully execute them.
127. Live-execution changes compare rendered activity with persisted events/receipts.
128. Actual tests/checks and remaining limitations are reported.
129. Rendering without an exception is not treated as acceptance.

---

## Final rule

Backend tests do not excuse a contradictory UI. Attractive UI does not excuse fabricated state. Documentation does not prove runtime capability. A public URL does not prove authorization. A running spinner does not prove live execution.

VulnHunter UI is accepted only when **security truth + persisted task truth + canonical product design + mobile/accessibility evidence** agree.
