# VulnHunter Product Interface Blueprint

**Canonical visual contract:** `docs/design/VULNHUNTER_UI_CONTRACT.md`  
**Canonical workflow contract:** `docs/product/CHAT_FIRST_WORKSPACE.md`

## Purpose

This blueprint describes the browser product hierarchy. It does not create API authority, execution authority, permissions, model authority or policy exceptions. Backend services remain authoritative for authorization, scope, verification, review, adjudication, release eligibility, audit integrity and worker state.

## Product character

VulnHunter is a calm, precise, conversation-controlled security workspace rather than a decorative cyberpunk dashboard or a generic enterprise admin console.

The primary experience is:

```text
Ask or attach something in the workspace
→ resolve the exact authorized object
→ show the governed plan/required decision
→ execute through persisted task state
→ surface progress, blockers, findings, evidence and reports in the same conversation
→ open a specialist deep view only when additional room or an identity-bound action is required
```

## Primary surface

The **Assessment Workspace** is the product's centre of gravity. It owns the user's current conversational/task context and projects the same backend state that supporting pages inspect.

The everyday shell prioritizes:

- New assessment;
- Chats / Tasks;
- Task / Assessment History;
- progressively disclosed `Manage` specialist areas;
- Settings;
- user identity/role.

## Supporting/deep views

Repository-backed capabilities such as Source Hunt, Authorizations, Findings, Evidence, Review Queue, Adjudications, Campaigns, Releases, Datasets, Analysis Services, Audit Log and Reports remain supported. They are deep views or specialist operations, not independent products competing with chat.

A finding, report, approval requirement, authorization requirement, Source Hunt setup, APK upload, worker recovery/failure or review status should normally be visible in chat before navigation to a larger view is required.

## Visual language

Do not restate or override visual tokens here. The locked rules for cream dotted surfaces, dusty-pink accents, square geometry, hard black offset shadows, typography, spacing and responsive behaviour live in `docs/design/VULNHUNTER_UI_CONTRACT.md`.

## Non-negotiable boundary

A hidden, disabled or visually unavailable control is not a security control. Every permission, separation-of-duty rule, authorization requirement, release blocker and assessment boundary must also be enforced by backend services.
