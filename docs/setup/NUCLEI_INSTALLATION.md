# Manual Nuclei Installation and Activation

The repository now contains a controlled execution harness, but it still does
not install Nuclei, update templates, or enable scanning. Install and activation
remain separate human-controlled steps. The production runner is deliberately
disabled.

## Required repository state

Update your existing VulnHunter checkout to the reviewed merged baseline before
performing a manual installation:

```bash
cd /path/to/your/vulnhunter-checkout
git switch main
git pull --ff-only origin main
git status --short
git rev-parse HEAD
```

The `git status --short` command must print nothing. Record the commit printed by
`git rev-parse HEAD` in the installation evidence so the installed engine and
template set can be traced to the exact reviewed VulnHunter baseline. Do not use
a hardcoded historical commit from an older milestone.

## No-sudo binary layout

Use a user-owned layout:

```text
~/.local/bin/nuclei
~/.local/share/nuclei-templates-v10.4.5/
```

The engine candidate is `v3.8.0` and the template candidate is `v10.4.5`.
Download the matching Linux architecture assets from the official
[ProjectDiscovery v3.8.0 release](https://github.com/projectdiscovery/nuclei/releases/tag/v3.8.0),
verify the published checksums, and only then place the executable in
`~/.local/bin`.

Do not use `@latest`, automatic self-update, or an unpinned template checkout
for governed activation.

## Readiness only

After manual installation:

```bash
export PATH="$HOME/.local/bin:$PATH"
python scripts/nuclei_readiness.py
cat artifacts/nuclei-readiness/readiness.json
```

The readiness command runs only local version probes. It performs no target
scan, update, upload, or template execution.

## Activation remains blocked

Do not change `execution_enabled` or the Nuclei runtime flag until all of these
exist:

- engagement authorization and approved targets;
- exact approved scan profile;
- reviewed/pinned template set;
- pre-execution approval gate;
- approved evidence directory;
- isolated runtime for intrusive/headless/JavaScript work;
- successful focused and full-suite validation;
- human review of the generated command plan.

Public targets must retain local-network restriction. Internal targets require
explicit private-range scope approval. Public Interactsh and ProjectDiscovery
cloud upload remain prohibited by default.

## Future controlled local-lab pilot

Milestone 29 supports offline preparation only. For a future pilot, a human must
create a time-limited engagement authorization, review exact normalized target
URLs and current address pins, populate the template manifest with reviewed
relative paths and SHA-256 digests, select an existing approved evidence
directory, review the immutable command-plan digest, and issue a separate
expiring approval for that digest.

Do not interpret the resulting `APPROVED_EXECUTION_DISABLED` state as permission
to run Nuclei. The empty template manifest, disabled runtime flags, missing
isolated runner, and remaining blockers in
`docs/intelligence/MILESTONE_29_NUCLEI_ACTIVATION_CONTROLS.md` must all be
resolved through separately reviewed changes before any local-lab execution.

## Milestone 31 worker boundary

The disabled container files under `deploy/scanner-worker/` demonstrate process
separation only. They contain no Nuclei binary, use no network, start no
listener, and exit with `blocked_execution_disabled`. Do not treat the container
skeleton as an installation or activation method.
