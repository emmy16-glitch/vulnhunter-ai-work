# APK Task UI Contract

## Canonical hierarchy

The conversation renders one authoritative APK task block per `run_id`:

```text
Conversation
  → APK task
      → top-level stage
          → tool row
      → technical activity disclosure
```

The task block is an evolving projection of the latest persisted mobile plan, mobile execution snapshot, and signed progress events. It is not a second source of truth. The existing backend and inspector projections remain authoritative.

## Data mapping

| UI region | Authoritative source | Rendering rule |
|---|---|---|
| Task title and artifact chip | Attachment / mobile plan | Use actual filename, size, DEX count, native count, and digest. |
| Task state | Mobile execution state or run state | Map centrally to queued, running, completed, failed, cancelled, blocked, or pending. |
| Stage rows | Mobile plan rounds and persisted execution stages | Render only stages/tools present in the real plan or in persisted progress. |
| Tool rows | Plan tools plus progress tool states | Update an existing row by stable `tool_id` and stage key; never append duplicates. |
| Current detail | Latest persisted progress event | Show concise safe detail; do not invent percentages or reasoning. |
| Technical activity | Persisted events/progress events | Keep collapsed by default and show the real event count. |
| Analysis note | Persisted safe summary or backend-provided reason | Render only when a real summary exists; never synthesize hidden reasoning. |
| Findings | Persisted candidate/finding objects | Render only persisted objects; no placeholder finding card. |
| Inspector | Existing assessment projection and selected finding/evidence | Preserve existing inspector data binding and context actions. |

## Status mapping

The shared client mapping is:

| Backend state | Marker | Semantics |
|---|---|---|
| `queued`, `pending` | open circle | Waiting for worker or stage. |
| `running`, `executing`, `evaluating` | pink activity marker | Authoritative work is active. |
| `completed`, `success`, `succeeded`, `verified` | check | Persisted completion. |
| `failed`, `error`, `blocked`, `rejected`, `cancelled` | warning mark | Terminal negative or governed stop. |
| unknown/recorded | neutral dot | Do not infer a stronger state. |

## Update and reconnect rules

A task block is keyed by `run_id`. A tool row is keyed by `run_id`, `stage`, and `tool_id`. Progress events are keyed by persisted sequence or event identifier. On SSE reconnect, the existing row is updated from the cursor response. Browser refresh reconstructs the task from the server-rendered plan/execution payload and then resumes the persisted stream. No frontend timer can promote a state or create an event.

## Presentation rules

The main task block is compact and human-readable. Raw event history is behind a native `details` disclosure labeled with the actual persisted count. The outer task has one restrained shell; nested stages use separators rather than independent cards. The composer remains fixed to the conversation surface and the inspector remains a contextual deep-view. Desktop uses a three-zone composition when the inspector is open; mobile converts navigation and inspector to drawers or full-width views.

## Accessibility rules

Stage and technical-activity disclosures use native `details`/`summary` or equivalent `aria-expanded` controls. Status is represented by both marker and text. Tool rows remain keyboard reachable. Focus returns to the invoking control after inspector or drawer close. Reduced-motion users receive state updates without decorative animation.
