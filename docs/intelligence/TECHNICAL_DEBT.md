# Technical Debt

| Item | Risk | Priority | Exit condition |
|---|---|---:|---|
| Local reviewer authentication lacks external proof | Local scrypt secrets do not provide SSO, MFA, hardware-backed identity, or proof that separate accounts are separate people | High | External identity provider, MFA, or cryptographically signed review decisions |
| Local pseudonymous orchestration roles | Role separation is recorded but identities are not authenticated | High | Account-backed identities or signed role attestations |
| Synthetic benchmark dependence | Misleading generalisation | High | Diverse authorised application dataset and external grouped holdout |
| SQLite-only local storage | Limited concurrent/multi-user operation | Medium | Documented storage interface and migration plan |
| Application-level experiment isolation | A fully privileged local account is not OS-sandboxed | High | Dedicated low-privilege runner, container, VM, or sandbox profile |
| Local unsigned artifacts | Integrity depends on local filesystem | Medium | Artifact signing and verification |
| CLI-only review | Lower reviewer productivity | Medium | Stable review contracts plus optional UI |
| Limited performance profiling | Unknown scaling limits | Medium | Repeatable mapper/storage/feature benchmarks |
| Manual intelligence-note updates | Documentation drift | Medium | CI check for required files and audit freshness |
| Unsigned authorization evidence | Registry records reference permission evidence but do not verify an external signature | Medium | Signed approval evidence and documented retention policy |
| No OS-level unattended runner isolation | A permitted process still shares the host security boundary | High | Dedicated low-privilege sandbox with filesystem and network confinement |
| Pseudonymous rather than authenticated control-plane actors | Actor strings do not prove real identity | High | Signed identities and external key verification |
| No production scheduler integration | Control plane must currently be invoked explicitly | Medium | Scheduler adapter that cannot bypass manifest checks |
| Disabled scanner worker has no authenticated transport | The manager/worker boundary is defined but cannot safely accept jobs | High | Authenticated, replay-resistant transport bound to exact request digests and identities |
| No real isolated scanner image provenance | Container boundary is disabled and unsigned | High | Signed image, SBOM, verified scanner binary/feed provenance, and rollback evidence |
| OpenVAS and mobile adapters are planned only | Shared contracts exist but no reviewed engine/feed integration exists | Medium | Version-pinned adapters passing the same authorization, evidence, and isolation gates |

## Debt-handling rule

Do not silently work around technical debt. Link significant implementation changes to an item here or add a new entry.

## Resolved debt

| Item | Resolution |
|---|---|
| Socket-level DNS pinning | Connection-time address subset validation, direct approved-IP TCP connections, peer verification, original-host TLS validation, and per-request connection isolation |
| Authenticated browser security foundation | Django sessions, CSRF protection, authenticated routes, and route-level authorization now back the operational web surface |

## Governed collection follow-up

- Replace local shared-secret authentication with optional MFA or an external
  identity provider when deployment requirements justify the added trust and
  operational complexity.
- Add cryptographic signing and protected key rotation for campaign releases and
  other durable artifacts.
- Add a migration framework before the governance SQLite schema changes in a
  backward-incompatible way.
- Add a campaign dashboard only after the CLI workflow and real-data operating
  process are stable.
- Approve a browser-capable framework only when it can enforce authenticated
  sessions, CSRF protection, and route-level authorization without duplicating
  domain policy.
