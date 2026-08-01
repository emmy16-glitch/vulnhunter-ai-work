# Step 30 Closeout and Step 31 Governed Campaign Foundation

**Branch:** `impl/governed-publication-service`  
**Pull request:** `#62`  
**Status:** Step 30 implementation complete on the draft branch; Step 31 operational foundation started.

## Step 30 closeout

The dedicated final-report publication service now provides the complete declared
Step 30 foundation:

- exact signed final-report and export-manifest binding;
- separately authenticated requester, approver and publisher authorities;
- configured local-directory destinations with format allowlists;
- digest verification before and after copying artifacts;
- append-only signed publication manifests;
- explicit correction through a new three-person release chain;
- independent revocation with preserved artifacts and signed notices;
- protected responsive browser controls that never accept destination paths;
- deployment preflight for keys, configuration, authorities and destinations;
- signed-state and copied-artifact integrity verification;
- inspect-first interrupted-operation recovery;
- narrowly safe restoration of missing deterministic metadata;
- stale staging cleanup that never deletes publication artifacts;
- operator runbooks, backup boundaries and manual-escalation rules.

Step 30 remains activation-gated. Completing this implementation does not publish
anything automatically, add a public network destination, close a finding, merge
source code or deploy the application.

## Existing Step 31 controls

The governance layer already enforces the core real-data campaign state machine:

- exact time-bounded target authorisations;
- campaign creator and independent approver separation;
- immutable approved campaign manifests;
- minimum application and application-family diversity requirements;
- exact application environment, family and authorisation snapshot metadata;
- completed-scan linkage to validation, start and completion audit evidence;
- two distinct primary reviewers for every retained observation;
- reviewer conflict and campaign owner/creator exclusion;
- a separate assigned adjudicator for disputed reviews;
- identity-bound append-only review attestations;
- fail-closed completion and immutable dataset release manifests.

These controls prove the software workflow. They do not claim that a diverse real
campaign has already been run.

## New Step 31 release provenance package

`vulnhunter.governance.release_package` adds a deterministic append-only package
that is created only after an existing governed dataset release passes integrity
verification.

The package binds:

- the exact campaign record and approved campaign-manifest hashes;
- the existing dataset release ID and manifest hash;
- every application ID and application record hash;
- application family and environment metadata;
- exact authorisation IDs and authorisation record hashes;
- every observation assignment hash;
- both assigned primary reviewer identities;
- both primary attestation IDs, record hashes and repository decision hashes;
- the final consensus or adjudicated state;
- the assigned adjudicator and exact adjudication provenance when required;
- the effective label already frozen in the dataset release manifest.

The package store is owner-private and append-only. Repeating creation with the
same verified state is idempotent. Existing different content, unsafe symlinks,
missing repositories, changed decisions, incomplete attestations or mismatched
release state fail closed.

## Operator command

Create or verify one package after a governed campaign release:

```bash
python manage.py vh_campaign_release_package \
  --campaign-id campaign-example \
  --output-root /srv/vulnhunter/evidence/campaign-release-packages
```

Machine-readable output:

```bash
python manage.py vh_campaign_release_package \
  --campaign-id campaign-example \
  --output-root /srv/vulnhunter/evidence/campaign-release-packages \
  --json
```

The command opens only the scan repositories already bound into the governed
campaign. It does not discover targets, run scans, submit reviews, adjudicate,
release a dataset or modify the governance state machine.

## Acceptance boundary

The automated acceptance scenario uses owned synthetic local data to prove:

1. two separately authorised applications from two declared families;
2. one linked completed scan and observation per application;
3. two independent primary reviews per observation;
4. one consensus outcome;
5. one disagreement resolved by the assigned independent adjudicator;
6. campaign completion and immutable dataset release;
7. exact release-package generation and reload;
8. fail-closed behaviour when an attestation disappears;
9. refusal to overwrite changed package content.

A real Step 31 campaign still requires Emmanuel or another named owner to provide
multiple intentionally diverse owned or explicitly authorised applications. No
real-world model-performance claim is permitted until those campaigns, reviews,
holdout controls and evaluations are completed.
