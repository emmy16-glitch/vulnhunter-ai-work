# Controlled Pilot Plans

This directory contains versioned **plan-validation inputs**, not authorizations.

Passing validation does not authorize a scan, create authorization or identity
records, create a campaign, activate a connector, approve a finding, release a
dataset, or permit model training.

`example-plan.json` is synthetic. Validate it from the repository root:

```bash
python -m vulnhunter.pilot validate   --plan config/pilot/example-plan.json   --format text
```

Never store passwords, personal access tokens, API keys, private keys, session
cookies, or other real credentials in a pilot plan.
