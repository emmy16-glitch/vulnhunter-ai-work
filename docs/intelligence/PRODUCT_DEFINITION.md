# Product Definition

## Problem

Security-testing tools often collect excessive data, leave scope enforcement implicit, and report passive signals as vulnerabilities. Machine-learning prototypes frequently inflate performance through duplicate data or train/test leakage.

## Product

VulnHunter AI is an authorised, laboratory-only research platform that:

1. validates target scope before network activity;
2. passively maps approved web applications;
3. creates structured, redacted security observations;
4. requires human review for labels;
5. builds leakage-resistant reviewed datasets;
6. trains reproducible decision-support models;
7. preserves model and dataset provenance.

## Human/automation boundary

Automation may:

- collect bounded passive evidence;
- prioritise a review queue;
- detect duplicates and label conflicts;
- create features;
- train and evaluate models;
- produce predictions and diagnostics.

Only humans may:

- authorise target testing;
- interpret the meaning of evidence;
- confirm or reject findings;
- resolve conflicting labels;
- approve claims about real-world performance.

## Non-goals

VulnHunter is not intended to:

- perform exploitation;
- prove exploitability;
- attack public systems;
- bypass access controls;
- replace qualified security review;
- automatically publish vulnerability claims;
- use synthetic benchmark scores as marketing evidence.
