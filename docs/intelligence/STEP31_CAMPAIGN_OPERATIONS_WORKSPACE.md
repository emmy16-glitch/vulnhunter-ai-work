# Step 31 Campaign Operations Workspace

## Purpose

The campaign operations workspace gives a governed operator one truthful, read-only view of what must be true before an approved campaign is activated, before an active campaign performs genuine collection, and before a completed campaign release is used.

It extends the existing protected campaign-detail page. It does not create a second campaign state machine or bypass the governance service.

## Read-only boundary

The workspace cannot:

- create or edit a campaign;
- register an application;
- issue or repair an authorization;
- approve or activate a campaign;
- discover a target or start a scan;
- assign reviewers;
- submit a primary review;
- adjudicate a dispute;
- complete a campaign;
- create a dataset release manifest;
- create or overwrite a campaign release package;
- train, select, promote or deploy a model.

Every state-changing action remains in its existing governed service and identity-separation boundary.

## Activation prerequisites

The assessment verifies:

- the governance store and its hash-chained audit events pass integrity verification;
- the campaign meets its minimum application count;
- the campaign meets its minimum declared application-family count;
- every application remains bound to the exact immutable authorization hash recorded at registration;
- the authorization target still matches the registered application target;
- every authorization is active and within its validity window;
- the campaign limits remain narrower than or equal to the authorization limits;
- approved target addresses remain loopback or private addresses;
- each current authorization records an owner declaration, purpose, evidence reference and a separate approving authority;
- the campaign has a distinct approved immutable manifest before activation.

A campaign is reported as activation-ready only while it is in the `approved` state and all prerequisites pass. A campaign is reported as genuine-collection-ready only while it is in the `active` state and the same prerequisites still pass.

## Ownership interpretation

`owner`, `approved_by` and `evidence_reference` are persisted declarations. Their presence is necessary for a genuine campaign plan, but the software cannot prove that the declaration is truthful.

Before any genuine run, a human operator must independently verify that the evidence reference authorizes the exact target, path boundary, environment and collection purpose. The workspace intentionally displays only counts and gate status; it does not expose the evidence reference itself in the browser.

## Application-family coverage

For each declared family, the workspace reports:

- registered application count;
- declared environments;
- authorization count;
- current exact authorization count;
- ownership-evidence declaration count;
- linked scan count;
- retained observation count.

Local scan-database paths are not rendered.

## Review and adjudication workload

The workspace derives read-only workload from the existing linked scan records, assignments and repository review cases:

- total retained observations;
- assigned and unassigned observations;
- assignments awaiting completion of two primary reviews;
- disputed reviews awaiting independent adjudication;
- consensus cases;
- adjudicated cases;
- final governed labels;
- unavailable or invalid review records.

It does not infer consensus from a model prediction and does not treat one review as final.

## Release provenance

For completed campaigns, the workspace verifies the immutable dataset release state and inspects the configured append-only campaign release package without creating directories or files.

Package state is reported as:

- `not_released`: no dataset release exists, so no package is expected;
- `missing`: a dataset release exists but its package is absent;
- `verified`: the persisted package hash and exact governed-state reconstruction match;
- `invalid`: storage is unsafe, the package is malformed, its hash is wrong, or it no longer matches governed evidence.

The browser does not expose the package root or source repository paths.

## Fail-closed behavior

Missing stores, invalid governance state, stale or changed authorizations, public approved addresses, unresolved review work, unsafe package storage, and mismatched release provenance remain blockers. The workspace provides ordered next actions but performs none of them.

## Acceptance coverage

Tests prove:

- a draft with complete owned-target declarations still remains blocked on independent approval;
- an active campaign with missing ownership evidence and only one primary review is not genuine-collection-ready or release-ready;
- a completed, fully reviewed campaign reports its append-only release package as verified;
- the protected browser page renders the operational gates while withholding evidence references and local filesystem paths.
