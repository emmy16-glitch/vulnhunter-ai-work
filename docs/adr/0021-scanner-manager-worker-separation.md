# ADR-0021: Separate scanner management from scanner execution

- Status: Accepted
- Date: 2026-07-16

## Context

VulnHunter already owns authorization, scope validation, immutable planning,
human approval, evidence trust, and finding review. Running external scanners in
the Django web process would combine policy and process execution, make
cancellation and recovery unreliable, increase the impact of scanner defects,
and encourage tool-specific command construction throughout the application.

Nuclei, OpenVAS, and mobile-analysis tools also have different process, feed,
version, and isolation requirements. They still need one governance model.

## Decision

VulnHunter will use a versioned scanner-control protocol between the manager and
future isolated workers.

The manager owns:

- authorization and exact target scope;
- immutable plan and approval binding;
- adapter, engine, feed, and checksum policy;
- lifecycle and audit records;
- evidence acceptance and finding trust state.

A future worker owns only:

- a scanner process created from a validated internal specification;
- bounded capture and cancellation enforcement;
- evidence production within the approved directory.

The worker cannot grant authorization, broaden scope, accept arbitrary shell
commands, approve its own work, retrieve unrestricted secrets, or confirm a
finding.

Scanner protocol `1.0` is shared by Nuclei, planned OpenVAS, and planned mobile
analysis. Adapter registration does not activate execution. Engine/feed
compatibility is centrally pinned, and missing versions fail closed rather than
resolving to `latest`.

Milestone 31 implements the contracts, disabled worker boundary, and a Nuclei
production runner that always blocks. It does not implement a real scanner
launcher or manager-to-worker transport.

## Consequences

### Positive

- scanner defects and resource use are isolated from Django;
- authorization policy remains tool independent;
- OpenVAS and mobile adapters cannot create alternate approval paths;
- versions, feeds, checksums, and compatibility become reviewable release data;
- cancellation, timeout, recovery, and evidence contracts are explicit.

### Costs

- authenticated transport and durable scheduling are still required;
- worker image provenance and deployment operations add future complexity;
- real execution remains unavailable until a separate security review.

## Rejected alternatives

- Run scanner subprocesses directly from Django views or request handlers.
- Allow each tool integration to define its own authorization and approval
  semantics.
- Store caller-supplied command strings, arbitrary argv, or process
  environments.
- Automatically install or upgrade to the latest scanner or feed release.
