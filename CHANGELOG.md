# Changelog

All notable project changes are documented here. The project has not yet made a
production release.

## Unreleased

- corrected the supported Nuclei engine pin to the official `v3.8.0` release
  across runtime policy, compatibility records, readiness validation, remote
  worker examples, tests, and operator documentation;
- added exact version-token parsing and cross-manifest pin consistency checks
  without enabling scanner execution or signed-job enqueue.

### Milestone 31 — Controlled Nuclei Execution Harness

- added scanner protocol `1.0` shared by Nuclei, planned OpenVAS, and planned
  mobile-analysis adapters;
- separated scanner-manager contracts from the future isolated worker process;
- added immutable Nuclei execution requests, lifecycle transitions, hash-linked
  audit events, file-backed recovery, cancellation, and timeout contracts;
- added bounded redacted stdout/stderr capture and content-addressed execution
  summaries;
- added a production runner that always returns
  `blocked_execution_disabled` and a deterministic no-process test runner;
- added central scanner, adapter, engine, feed, checksum, and deployment
  compatibility tracking;
- added a disabled, networkless, non-root container worker boundary;
- retained `execution_enabled=false`, candidate-only observations, and all
  Milestone 29/30 authorization and approval controls.
