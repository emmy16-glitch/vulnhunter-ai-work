# Information Architecture

**Canonical visual/navigation rules:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Workflow contract:** `docs/product/CHAT_FIRST_WORKSPACE.md`

VulnHunter is conversation/task-first. The current assessment workspace is the primary operating surface; specialist pages are contextual deep views of the same persisted backend state.

## Everyday navigation

The default authenticated shell prioritizes:

1. **New assessment**;
2. **Chats / Tasks** — current and recent assessment conversations;
3. **Task history / Assessment History**;
4. **Manage** — progressive disclosure for role-allowed specialist areas;
5. **Settings**;
6. current user identity/role.

The sidebar must not expose every backend subsystem as an equal permanent destination merely because a route exists.

## Specialist/deep views

Role-backed specialist capabilities may include:

- Source Hunt;
- Authorizations;
- Findings and evidence;
- Review Queue;
- Adjudications;
- Campaigns;
- Releases;
- Datasets;
- Analysis Services;
- Audit Log;
- Reports.

These surfaces may open from `Manage`, a contextual chat result, a notification or a direct permitted route. Backend permission checks remain authoritative regardless of whether a navigation item is visible.

## State ownership

Chat, task history, specialist views, evidence, findings and reports must render the same assessment/workspace identity and lifecycle. A specialist page must not create a second hidden workflow or competing state machine.

Findings, approvals, authorization requirements, Source Hunt setup, APK uploads, recovery/failure states and report readiness should appear in chat first when practical; larger or identity-bound actions may then open a deep view and must project their persisted result back into the originating conversation.

The previous dashboard-flow hierarchy (`Overview → Collection → Analysis → Independent Review → Governance → Intelligence → Assurance`) and the campaign-control-room-as-primary-surface model are retired. Campaigns remain a governed capability, not the product's everyday centre of gravity.
