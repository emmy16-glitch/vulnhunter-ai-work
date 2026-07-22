# Phone-Only Private Laboratory

This workflow needs only an Android phone, Termux, a private GitHub Codespace and
the phone browser. The scan runs inside the private Codespace; the phone is the
operator interface.

## Boundary

The included lab supports one deliberately vulnerable local HTTP service on the
Codespace's non-loopback RFC1918 address. The only scanner workflow is the pinned
passive Nuclei worker with rate limit `1`, concurrency `1`, no redirects, no public
OAST and one reviewed security-header template.

It is not a public website scanner.

## Create and open the Codespace

From Termux:

```bash
pkg update
pkg install gh openssh
gh auth login
gh codespace create \
  --repo emmy16-glitch/vulnhunter-ai-work \
  --branch main \
  --devcontainer-path .devcontainer/devcontainer.json \
  --display-name vulnhunter-phone \
  --idle-timeout 30m \
  --retention-period 72h \
  --status
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
```

The post-create process installs the Python application, checksum-verifies Nuclei
`v3.8.0`, prepares reviewed templates, creates an ignored signing key and worker
policy, initializes databases and writes a strict readiness report.

## Create separated identities

Run:

```bash
bash .devcontainer/first-run.sh
```

Create two different accounts:

- **operator** — product role `campaign-operator`; creates the assessment;
- **approver** — product role `system-administrator`; approves or denies the exact plan.

The approval store rejects self-approval, so the identities and web users must be
different.

## Start the complete lab

```bash
bash .devcontainer/start-phone-lab.sh
```

The command:

1. discovers the Codespace RFC1918 address;
2. starts the deliberate HTTP target on port `8010` without forwarding it publicly;
3. re-verifies Nuclei and all template digests;
4. creates or reuses the exact temporary authorization;
5. starts a separate worker polling the signed spool;
6. starts the web UI on private port `8002`.

Get the private browser address from a second Termux session:

```bash
gh codespace ports \
  --repo emmy16-glitch/vulnhunter-ai-work \
  --json sourcePort,browseUrl,visibility \
  --jq '.[] | select(.sourcePort == 8002) | .browseUrl'
```

Keep port `8002` private.

## Run the real assessment

1. Sign in as the operator.
2. Create a passive assessment using the authorization and target printed by the start command.
3. Sign out.
4. Sign in as the approver.
5. Review and approve the exact plan digest once.
6. The separate worker claims the signed job and records genuine scanner evidence.
7. Inspect the assessment, candidate finding, proof capsule, audit events and review state.

Expected flow:

```text
awaiting approval → queued → running → completed
→ candidate evidence → deterministic verification → human review
```

## Logs and shutdown

Runtime logs are stored below ignored `.codespaces/phone-lab/`. Stop the foreground
command with `Ctrl+C`; its cleanup trap stops the worker and target. Stop or delete
the Codespace when finished.
