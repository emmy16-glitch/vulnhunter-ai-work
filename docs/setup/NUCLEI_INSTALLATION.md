# Manual Nuclei Installation and Activation

This milestone does not install Nuclei, update templates, or enable scanning.
Install and activation remain separate human-controlled steps.

## Required repository state

Update the repository to the reviewed merged baseline before running the
Milestone 28 installer:

```bash
cd /mnt/vulnhunter-data/Projects/vulnhunter-ai
git switch main
git pull --ff-only origin main
git status --short
```

The final command must print nothing. The expected baseline commit is:

```text
5346758fb728a6f9e68f986879b99f3c975c0ec5
```

## No-sudo binary layout

Use a user-owned layout:

```text
~/.local/bin/nuclei
~/.local/share/nuclei-templates-v10.4.5/
```

The engine candidate is `v3.11.0` and the template candidate is `v10.4.5`.
Download the matching Linux architecture release assets from the official
ProjectDiscovery GitHub releases page, verify the published checksums, and only
then place the executable in `~/.local/bin`.

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
