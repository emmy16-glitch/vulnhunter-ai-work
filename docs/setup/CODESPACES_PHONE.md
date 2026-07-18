# Phone Preview with GitHub Codespaces and Termux

This setup runs VulnHunter inside a private GitHub Codespace while Termux is used as the terminal.

## What is prepared automatically

The `.devcontainer` configuration:

- uses Python 3.12;
- installs the project and development dependencies;
- enables SSH access for `gh codespace ssh`;
- prepares Django migrations and the agent store;
- forwards port `8002` privately;
- keeps generated runtime state in ignored local directories;
- does not store login passwords or API keys in GitHub.

## Prepare Termux

```bash
pkg update
pkg install gh openssh
```

Authenticate GitHub CLI:

```bash
gh auth login
```

Choose GitHub.com, HTTPS, and browser authentication when prompted.

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

## Connect from Termux

```bash
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
```

## Create the first local login

```bash
bash .devcontainer/first-run.sh
```

The script asks for the local identity, username, and hidden passwords. Those values are not committed to GitHub.

## Start VulnHunter

```bash
bash .devcontainer/start-preview.sh
```

Keep that Termux session connected while the server is running.

## Get the private browser address

Open a second Termux session and run:

```bash
gh codespace ports \
  --repo emmy16-glitch/vulnhunter-ai-work \
  --json sourcePort,browseUrl,visibility \
  --jq '.[] | select(.sourcePort == 8002) | .browseUrl'
```

Copy the returned `https://...-8002.app.github.dev` address into the phone browser.

Keep the port private:

```bash
gh codespace ports visibility 8002:private \
  --repo emmy16-glitch/vulnhunter-ai-work
```

## Stop or reconnect later

```bash
gh codespace stop --repo emmy16-glitch/vulnhunter-ai-work
```

Reconnect later:

```bash
gh codespace ssh --repo emmy16-glitch/vulnhunter-ai-work
cd /workspaces/vulnhunter-ai-work
bash .devcontainer/start-preview.sh
```

Delete it when it is no longer needed:

```bash
gh codespace delete --repo emmy16-glitch/vulnhunter-ai-work
```
