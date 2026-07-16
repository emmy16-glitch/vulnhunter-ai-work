# Milestone 27 Gap Matrix

| Area | Status | Gap | Resolution in this milestone |
| --- | --- | --- | --- |
| Machine Oracle proof capsules | PARTIAL | No canonical capsule contract existed. | Added immutable, hashed `ProofCapsule`. |
| pentest-ai connector | EXTERNAL_DEPENDENCY | No isolated service, production keys, or signature infrastructure is installed or activated. | Added disabled-by-default connector contract, injected authenticator boundary, and durable replay ledger. |
| Oracle verdicts | PARTIAL | No independent verifier verdict model existed. | Added verdict enum and deterministic verifier. |
| Oracle sessions | COMPLETE | Task graph existed but no transactionally consistent Oracle checkpoint record. | Added canonical immutable sessions in SQLite with atomic compare-and-swap updates and complete typed history validation. |
| Attack paths | FOUNDATION_ONLY | Advanced profile named attack paths but no graph contract. | Added typed graph that blocks confirmed labels with unverified steps. |
| Repository coverage | COMPLETE | Audit inventory existed but no repository-bound review coverage model. | Added deterministic path/state/exclusion-sensitive inventory with non-following traversal, canonical containment, stable descriptor reads, and auditable safe exclusions. |
| Knowledge extensions | INTENTIONALLY_DEFERRED | Existing knowledge system remains untrusted ingestion. | Documented later reviewed-Oracle-fact path. |
| AI routing | PARTIAL | Provider registry existed without route decision records. | Added deterministic-first route policy and privacy fail-closed behavior. |
| Analyst feedback | MISSING | Review outcomes were not normalized for Oracle/evaluation. | Added structured outcomes and actual-record metrics. |
| Improvement proposals | MISSING | Research could evaluate changes, but no proposal record. | Added proposal model that cannot activate production config. |
| Dynamic APK analysis | EXTERNAL_DEPENDENCY | Requires isolated disposable emulator and approval. | Deferred; no APK execution support added. |
| Live security tools | EXTERNAL_DEPENDENCY | Requires installed tools and authorization. | Deferred; contracts remain disabled by default. |
| Cloud AI | EXTERNAL_DEPENDENCY | Requires credentials and privacy approval. | Deferred; no provider activation added. |
| Privileged broker | EXTERNAL_DEPENDENCY | Requires separate broker install and human approval. | Deferred; no sudo or broker activation added. |
| Exploitation, publication, propagation | PROHIBITED_OPERATION | Outside VulnHunter boundary. | No implementation added. |
