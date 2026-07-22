# Phone Preview and Private Lab with GitHub Codespaces

This setup runs VulnHunter inside a private GitHub Codespace while Termux is used
as the terminal and the phone browser is used for the UI.

## What is prepared automatically

The `.devcontainer` configuration:

- uses Python 3.12;
- installs the project and development dependencies;
- downloads official Nuclei `v3.8.0` for Linux `amd64` or `arm64`;
- verifies the release archive against the official checksum file;
- copies the reviewed passive template set into an ignored runtime directory;
- creates an ignored owner-private signing key and worker policy;
- verifies engine, release and template-file digests without scanning;
- enables SSH access for `gh codespace ssh`;
- forwards web port `8002` privately;
- does not forward the internal target port `8010`;
- keeps all generated state below ignored local directories;
- does not store login passwords, governance secrets or signing keys in GitHub.

## Prepare Termux

```bash
pkg update
pkg install gh openssh
gh auth login
```

Choose GitHub.com, HTTPS and browser authentication.

## Create the Codespace

```bash
gh codespace create \
  --repo emmy16-glitch/vulnhunter-ai-work \
  --branch main \
  --devcontainer-path .devcontainer/devcontainer.json \
  --display-name vulnhunter-phone \
  --idle-timeout 30m \
  --retention-period 72h \
  --status
```

## Connect and create accounts

```bash
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
bash .devcontainer/first-run.sh
```

The first-run setup creates separate operator and approver identities and web
accounts. This separation is required because requesters cannot approve their own
assessment plan.

## Start

For the complete real passive private lab:

```bash
bash .devcontainer/start-phone-lab.sh
```

For UI-only preview:

```bash
bash .devcontainer/start-preview.sh
```

Keep that Termux session connected while the server is running.

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

## Stop, reconnect or delete

```bash
gh codespace stop --repo emmy16-glitch/vulnhunter-ai-work
```

Reconnect later:

```bash
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
bash .devcontainer/start-phone-lab.sh
```

Delete it when no longer needed:

```bash
gh codespace delete --repo emmy16-glitch/vulnhunter-ai-work
```

See `PHONE_ONLY_PRIVATE_LAB.md` for the operator workflow and safety boundary.
