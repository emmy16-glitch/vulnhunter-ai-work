# VulnHunter UI Reference Audit

## Current implementation findings

The conversation workspace already has the correct overall identity: dark navigation, warm cream dotted canvas, dusty-pink controls, compact metadata, persisted activity entries, a unified mobile execution block, and a real inspector controller. The main mismatch is presentation hierarchy rather than missing backend state.

The current APK path renders two overlapping activity representations. `conversation-mobile.js` appends every mobile progress snapshot as a first-class `vh-chat-activity-entry` and also upserts a separate live execution block. The main `conversation.js` renderer appends persisted assessment activity entries independently. The template additionally keeps a compact run card with an Activity disclosure containing event history. This creates the repeated-event-card pattern described in the approved requirements.

The canonical UI should therefore be one evolving APK task projection inside the conversation feed. It should contain the artifact header, real stage rows, real tool rows, a safe reasoning summary only when a persisted summary exists, real candidate findings, and a collapsed technical-activity disclosure. Raw persisted events remain available behind progressive disclosure and are not deleted.

The current CSS uses individually bordered activity cards, large vertical gaps, and a bordered composer whose visible attach control is structurally present but must remain the only visible file action. The reference target requires compact nested rows, fewer outer borders, tighter spacing, stronger stage hierarchy, and a stable composer at the bottom of the conversation.

The current inspector implementation is already the correct data boundary for deep inspection: it consumes assessment projection, task card, mobile plan, mobile execution, findings, artifacts, reports, and persisted events. The UI refinement should preserve those hooks and improve layout rather than create a second inspector data path.

## Non-negotiable state rules

All labels, filenames, sizes, counts, durations, tools, statuses, findings, evidence, and timestamps must come from authoritative backend state. No reference-image sample values may be hardcoded. Percentages must be rendered only when a real measurable progress value is present. A tool is only marked completed, failed, or running when persisted worker state confirms it. Dynamic analysis remains fail-closed. Safe reasoning summaries must not expose hidden chain-of-thought, provider names, prompts, tokens, or secrets.

## Implementation target

Refine the existing conversation UI into the hierarchy `Conversation → Task → Stage → Tool → Technical activity`. Update the same task DOM in place when SSE/WebSocket events arrive. Keep technical history collapsed by default, preserve refresh/reconnect behavior, retain the existing real inspector and composer wiring, add truthful empty/error/loading states, and maintain accessible expansion semantics and reduced-motion behavior.

## Verification target

Use real browser screenshots and functional checks for desktop active APK, desktop inspector, empty workspace, mobile active APK, and login. Check representative widths 320, 390, 768, 1024, 1280, 1440, and 1920, with no horizontal overflow. Verify real upload, real task transitions, persisted reload, reconnect cursor continuity, finding/inspector context, composer attachment/send, and clean browser/server logs.
