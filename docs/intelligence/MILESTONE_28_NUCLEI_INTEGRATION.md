# Milestone 28 — Governed Nuclei Integration

## Status

`FOUNDATION_READY_FOR_MANUAL_INSTALL_AND_REVIEW`

## Scope completed by this installer

- upgraded the existing basic Nuclei adapter into a fixed governed policy;
- added passive, standard, intrusive, and retest profiles;
- applied two-core-safe rate and concurrency ceilings;
- prohibited cloud upload, public OAST, AI-generated templates, raw flags,
  local-file access, DAST server mode, Uncover, code templates, file templates,
  and self-contained templates;
- required signed templates and disabled update checks;
- added candidate-only Nuclei JSONL normalization;
- added read-only engine/template readiness reporting;
- added focused policy, command, parser, and data-leak regression tests;
- documented no-sudo installation and the remaining activation gates.

## Canonical remaining implementation register

The existing total-programme work remains authoritative. Nuclei is added as a
governed external-engine workstream alongside the already deferred or
activation-gated items:

1. lifecycle-aware worker cancellation and isolated worker enforcement;
2. deployment of optional scanners and exact dependency provenance;
3. private databases/queues/object storage where production scale requires it;
4. local model, Groq fallback, benchmark, and privacy-gated provider activation;
5. Graphify installation, graph learning period, native graph, and context-broker
   operationalization;
6. third-party skill trust, restricted MCP services, and connector activation;
7. mobile dynamic analysis, disposable Android runtime, ADB/Frida/MobSF controls;
8. binary dynamic analysis and privileged validation brokers;
9. authenticated scanning secret injection and credential lifecycle;
10. private OAST/Interactsh and safe out-of-band validation;
11. Nuclei template trust registry, signing, pinning, isolated headless/JavaScript
    runtime, and execution-time version enforcement;
12. attack-path verification, proof-capsule maturity, and report publication gates;
13. unattended operations, agentic-threat containment, incident recovery, and
    operator emergency controls;
14. analyst-feedback evaluation, controlled learning, reinforcement/reward
    governance, and rollback;
15. production deployment, backups, observability, migrations, and disaster
    recovery;
16. independent security review and controlled live-pilot acceptance.

## Explicit non-actions

The installer does not download Nuclei, update templates, scan a target, execute
a template, contact Interactsh, upload to ProjectDiscovery cloud, create a
credential, enable a connector, enable tool execution, commit, push, merge, or
deploy.
