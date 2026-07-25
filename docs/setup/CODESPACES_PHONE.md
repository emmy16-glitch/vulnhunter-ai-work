# Phone Preview, Codex, and Private Lab with GitHub Codespaces

This setup runs VulnHunter and Codex inside a private GitHub Codespace. Termux is
the remote terminal and the phone browser is used for the VulnHunter UI.

Codex does **not** run on Android in this setup. It runs on the Codespace's Linux
machine while its terminal is displayed in Termux.

## What is prepared automatically

The `.devcontainer` configuration:

- uses Python 3.12;
- installs Node.js LTS and the official `@openai/codex` CLI;
- installs the project and development dependencies;
- downloads official Nuclei `v3.8.0` for Linux `amd64` or `arm64`;
- verifies the release archive against the official checksum file;
- copies the reviewed passive template set into an ignored runtime directory;
- creates an ignored owner-private signing key and worker policy;
- verifies engine, release and template-file digests without scanning;
- enables SSH access for `gh codespace ssh`;
- forwards web port `8002` privately;
- does not forward the internal target port `8010`;
- keeps generated state below ignored local directories;
- does not store login passwords, governance secrets or signing keys in GitHub.

## Prepare Termux

```bash
pkg update
pkg install gh openssh
gh auth login
```

Choose GitHub.com, HTTPS and browser authentication.

## Create the Codespace

Until pull request 34 is merged, create the Codespace from its feature branch:

```bash
gh codespace create \
  --repo emmy16-glitch/vulnhunter-ai-work \
  --branch feature/unified-chat-mobile-hunt \
  --devcontainer-path .devcontainer/devcontainer.json \
  --display-name vulnhunter-phone \
  --idle-timeout 30m \
  --retention-period 72h \
  --status
```

After the feature is merged, replace the branch value with `main`.

The first build installs Codex automatically. Wait for the post-create process to
finish before connecting over SSH.

## Connect from Termux

```bash
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
```

Confirm that Codex is installed:

```bash
codex --version
```

Start Codex:

```bash
codex
```

Choose **Continue with ChatGPT** and complete the authentication instructions shown
in the terminal. The authentication belongs to the Codespace, so Termux does not
need a separate Codex installation.

A useful first request is:

```text
Inspect this repository, read AGENTS.md and the current pull request, then explain
what is failing before changing any files.
```

Run Codex from the repository directory so its workspace is scoped correctly.

## Prepare the VulnHunter application

From the same Codespace shell:

```bash
bash .devcontainer/first-run.sh
```

The first-run setup creates the governance identity and web account used by the
VulnHunter workspace.

## Start VulnHunter

For the complete real passive private lab:

```bash
bash .devcontainer/start-phone-lab.sh
```

For UI-only preview:

```bash
bash .devcontainer/start-preview.sh
```

Keep that Termux session connected while the foreground server is running. Use a
second Termux session for Codex, or start the server under a terminal multiplexer.

## Get the private browser address

In a second Termux session:

```bash
gh codespace ports \
  --repo emmy16-glitch/vulnhunter-ai-work \
  --json sourcePort,browseUrl,visibility \
  --jq '.[] | select(.sourcePort == 8002) | .browseUrl'
```

Copy the returned authenticated `https://...-8002.app.github.dev` address into the
phone browser. Keep the port private:

```bash
gh codespace ports visibility 8002:private \
  --repo emmy16-glitch/vulnhunter-ai-work
```

## Reconnect later

```bash
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
codex
```

## Rebuild after devcontainer changes

An existing Codespace will not automatically apply a newly added Node feature.
Rebuild it from Termux:

```bash
gh codespace rebuild --full \
  --repo emmy16-glitch/vulnhunter-ai-work
```

Reconnect after the rebuild finishes and verify:

```bash
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
node --version
npm --version
codex --version
```

## Stop or delete

Stop it when you are finished so it does not continue consuming Codespaces time:

```bash
gh codespace stop --repo emmy16-glitch/vulnhunter-ai-work
```

Delete it when no longer needed:

```bash
gh codespace delete --repo emmy16-glitch/vulnhunter-ai-work
```

See `PHONE_ONLY_PRIVATE_LAB.md` for the operator workflow and safety boundary.
