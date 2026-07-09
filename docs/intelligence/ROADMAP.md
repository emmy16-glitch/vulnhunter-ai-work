# Roadmap

## Now — Project intelligence and reproducibility

- maintain `AGENTS.md`;
- keep atomised architecture and governance notes;
- generate repository audits;
- keep experiment history and ADRs current.

## Next — Real authorised data collection

- define an authorisation record for each target;
- collect observations from multiple intentionally diverse local applications;
- document application family and deployment context;
- introduce second-review/adjudication support;
- build a balanced reviewed dataset without benchmark leakage.

## Next — Transport hardening

- research connection-level address pinning;
- preserve TLS hostname verification while binding approved addresses;
- add explicit proxy architecture only if required;
- add more transport-level integration tests.

## Later — Model validation

- external grouped holdout;
- repeated grouped cross-validation;
- calibration and threshold analysis;
- category-specific performance;
- application-family generalisation;
- model-card documentation;
- artifact signing and release process.

## Later — Product workflow

- resumable scans;
- controlled exports;
- richer reviewer productivity;
- structured authorisation records;
- safe report generation;
- optional graphical review interface.

## Explicitly deferred

- exploitation;
- credential attacks;
- arbitrary Internet scanning;
- autonomous approval/rejection;
- production performance claims from synthetic data.
