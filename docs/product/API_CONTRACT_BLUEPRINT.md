# API Contract Blueprint

The machine-readable API resources describe intended product contracts, not
implemented endpoints. The future API layer should expose versioned resources and
call existing domain services rather than reimplementing governance in controllers.

## Contract rules

- Every mutation is authenticated and authorized.
- Object-level separation is checked using actual actor and record identities.
- Scan creation requires an active authorization reference.
- Scope and connection-pinning failures are first-class error responses.
- Review and adjudication decisions are immutable after submission except through
  an explicit audited correction process.
- Release publication requires a ready assessment and matching manifest hash.
- No API endpoint permits release bypass, connector enablement, or model training in
  this blueprint milestone.
