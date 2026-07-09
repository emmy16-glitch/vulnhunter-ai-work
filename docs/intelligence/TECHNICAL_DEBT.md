# Technical Debt

| Item | Risk | Priority | Exit condition |
|---|---|---:|---|
| Socket-level DNS pinning | Connection may resolve after validation | High | Transport binds an approved address while preserving TLS hostname checks |
| Pseudonymous local reviewer IDs | IDs are not authenticated identities | High | Account-backed roles or cryptographically signed review decisions |
| Local pseudonymous orchestration roles | Role separation is recorded but identities are not authenticated | High | Account-backed identities or signed role attestations |
| Synthetic benchmark dependence | Misleading generalisation | High | Diverse authorised application dataset and external grouped holdout |
| SQLite-only local storage | Limited concurrent/multi-user operation | Medium | Documented storage interface and migration plan |
| Local unsigned artifacts | Integrity depends on local filesystem | Medium | Artifact signing and verification |
| CLI-only review | Lower reviewer productivity | Medium | Stable review contracts plus optional UI |
| Limited performance profiling | Unknown scaling limits | Medium | Repeatable mapper/storage/feature benchmarks |
| Manual intelligence-note updates | Documentation drift | Medium | CI check for required files and audit freshness |
| Unsigned authorization evidence | Registry records reference permission evidence but do not verify an external signature | Medium | Signed approval evidence and documented retention policy |

## Debt-handling rule

Do not silently work around technical debt. Link significant implementation changes to an item here or add a new entry.
