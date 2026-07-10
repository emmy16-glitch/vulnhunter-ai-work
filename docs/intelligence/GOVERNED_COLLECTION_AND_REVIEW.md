# Governed Collection and Authenticated Review

## Purpose

This subsystem turns authorised passive scans into traceable campaign datasets.
It does not grant scan permission and does not automatically collect data.

## Campaign lifecycle

1. An authenticated campaign administrator creates a draft with narrower scan
   limits and explicit minimum application, family, and observation counts.
2. The creator registers exact active authorization records and application
   metadata.
3. A different authenticated administrator approves the SHA-256 digest of the
   complete draft and application set.
4. Activation revalidates every authorization and verifies that the approved
   manifest has not changed.
5. Completed scans may be linked only when the authorization log contains the
   matching validation, scan-start, and scan-completion evidence. Completion
   evidence must bind the authorization ID, normalized scan database, scan ID,
   normalized target URL, and persisted scan snapshot hash.
6. Every linked observation receives two distinct assigned reviewers and,
   where required, a distinct adjudicator.
7. Completion and release require every linked observation to reach consensus
   or authenticated adjudication.

## Identity model

The first local administrator is created through a one-time empty-registry
bootstrap. Later accounts require an authenticated campaign administrator.
Secrets are hashed with scrypt using a random per-account salt. Secrets and
credential hashes must never appear in normal CLI output, audit event detail,
exports, prompts, or reports.

Roles are explicit:

- `campaign_admin` creates, approves, activates, completes, and releases;
- `reviewer` submits one immutable primary decision per assignment;
- `adjudicator` resolves a disagreement only when explicitly assigned.

Identities may be disabled and later reactivated. Revocation is permanent.
Previously recorded decisions remain auditable, but a revoked identity blocks a
new dataset release so a possible credential compromise can be investigated.

## Separation and conflicts

The campaign creator cannot approve their own campaign. Campaign creators and
owners cannot review their own campaign data. Primary reviewers must be
distinct. An adjudicator must be distinct from both primary reviewers.
Application and identity conflict tags are compared before assignment.

## Review attestation

The observation database remains authoritative for review cases and labels.
The governance database stores a hash-bound attestation for each repository
review decision. A decision made through a legacy or direct review path is not
silently adopted. If a repository decision exists without the matching
campaign attestation, the governed workflow stops safely.

## Dataset release gate

A release is allowed only when:

- the campaign is completed;
- the approved manifest still matches;
- application and family diversity minima are met;
- linked scan snapshots still match the observation databases;
- all authorization records remain active and unchanged;
- every collected observation has an assignment;
- each assignment has two authenticated primary attestations;
- disputes have an authenticated assigned-adjudicator attestation;
- no required reviewer or adjudicator has been revoked;
- the minimum reviewed-observation count is met.

The release output is a provenance manifest. It is not yet a cryptographic
signature and does not by itself establish real-world model performance.

## Pilot readiness evidence

`vulnhunter governance campaign readiness` is a read-only assessment over an
existing governed release. It does not approve campaigns, submit reviews,
adjudicate disputes, create releases, run scans, or train a model.

The report separates:

- hard release blockers, such as missing or tampered release manifests,
  unavailable authorization provenance, scan snapshot changes, unresolved
  reviews, and revoked or disabled reviewer evidence;
- model-training blockers, such as insufficient samples, missing classes,
  insufficient scan diversity, and duplicate evidence requiring deduplication;
- warnings, including duplicate fingerprints and duplicate evidence payloads;
- informational metrics, including application-family diversity, review
  agreement and disagreement rates, adjudication count, class balance,
  dataset SHA-256, release-manifest SHA-256, and report SHA-256.

This evidence is suitable for controlled local pilot operations only. Human
operators still must create authorizations, approve campaigns, run bounded
local scans, review observations, adjudicate disputes, and release eligible
campaigns through the existing role-separated workflow.

## Operational limitations

The local identity registry is not SSO, MFA, a hardware token, or proof that two
accounts are operated by two different people. Campaign hashes detect local
record changes but are not externally signed. Real validation still requires
diverse authorised applications, disciplined reviewers, frozen group-isolated
splits, and an untouched external holdout.
