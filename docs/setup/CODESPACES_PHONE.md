# Phone, Codex, and Governed Mobile Lab with GitHub Codespaces

This setup runs VulnHunter and Codex inside a private GitHub Codespace. Termux is
the remote terminal and the phone browser is used for the responsive VulnHunter UI.

Codex does **not** run on Android in this setup. It runs on the Codespace Linux
machine while its terminal is displayed in Termux.

## What is prepared automatically

The `.devcontainer` configuration:

- uses Python 3.12, Java 21 and Node.js LTS;
- installs the official `@openai/codex` CLI;
- installs the project and development dependencies;
- downloads official Nuclei `v3.8.0` for Linux `amd64` or `arm64` and verifies it;
- installs or discovers AAPT/AAPT2, apksigner, Apktool, APKiD and ADB;
- installs pinned Androguard, YARA Python bindings and Frida client tools;
- downloads digest-verified JADX, Radare2 and Ghidra release assets when available;
- writes an owner-private mobile worker policy containing only verified local paths;
- creates signed Nuclei/mobile worker keys and a separate runtime-approval key;
- enables private Docker support for the separately isolated MobSF service;
- enables SSH access for `gh codespace ssh`;
- forwards VulnHunter port `8002` privately;
- forwards MobSF setup port `8008` privately;
- does not forward the internal deliberate-target port `8010`;
- keeps generated state below ignored local directories;
- does not store passwords, API keys, governance secrets or signing keys in GitHub.

Missing tools remain visibly gated. A package download alone never makes a tool
appear completed in the UI.

## Prepare Termux

```bash
pkg update
pkg install gh openssh
gh auth login
gh auth refresh -h github.com -s codespace
```

Choose GitHub.com, HTTPS and browser authentication.

## Connect to the existing Codespace

List complete names:

```bash
gh codespace list \
  -R emmy16-glitch/vulnhunter-ai-work \
  --json name,displayName,state,lastUsedAt \
  --jq '.[] | [.name, .displayName, .state, .lastUsedAt] | @tsv'
```

Connect using the exact first-column name:

```bash
gh codespace ssh -c vulnhunter-phone-gpqw9j44xwvcwqpq
cd /workspaces/vulnhunter-ai-work
```

## Rebuild after this branch is merged

The Java, Node, Docker and SSH devcontainer features require a full rebuild:

```bash
gh codespace rebuild --full -c vulnhunter-phone-gpqw9j44xwvcwqpq
```

Reconnect after the rebuild:

```bash
gh codespace ssh -c vulnhunter-phone-gpqw9j44xwvcwqpq
cd /workspaces/vulnhunter-ai-work
```

Verify the main tools:

```bash
python --version
java -version
node --version
npm --version
codex --version
jadx --version || true
rabin2 -v || true
analyzeHeadless 2>&1 | head || true
adb version || true
frida --version || true
```

A command marked `|| true` may remain unavailable when its verified release asset
could not be installed. The generated worker policy is the authoritative readiness
source.

## Start Codex

```bash
codex
```

Choose **Continue with ChatGPT** and complete the authentication instructions shown
in the terminal. Run Codex from the repository directory so its workspace is scoped
correctly.

## Prepare the VulnHunter account and services

```bash
bash .devcontainer/first-run.sh
```

The guided setup:

1. creates or reuses the governance identity;
2. creates the web account;
3. optionally protects a Groq key in an owner-only file;
4. optionally starts the private MobSF container on loopback port `8008`;
5. asks for the MobSF REST key through a hidden prompt;
6. explains how to register a disposable Android emulator for ADB and Frida.

When configuring MobSF, open the private Codespaces port `8008` page, change the
default web password, copy the REST API key, then return to the hidden terminal
prompt. The API key is written only to `.codespaces/runtime/mobsf-api.key` with
owner-only permissions.

Keep the MobSF port private:

```bash
gh codespace ports visibility 8008:private \
  -c vulnhunter-phone-gpqw9j44xwvcwqpq
```

## Register an authorised disposable Android runtime

ADB and Frida are intentionally unavailable until a real emulator is online and
its exact identity is registered. The emulator may run on an authorised Linux host
or another controlled Android-lab machine reachable through the approved ADB/Frida
connection. Do not register a personal phone or an untrusted shared device.

After the emulator and matching Frida server are ready:

```bash
source .codespaces/vulnhunter.env
python scripts/register_mobile_runtime.py \
  --policy "$VULNHUNTER_MOBILE_RUNTIME_POLICY" \
  --runtime-id emulator-lab-01 \
  --adb-serial emulator-5554 \
  --frida-device-id emulator-5554
```

Registration verifies and stores:

- the exact ADB serial;
- emulator status;
- Android build fingerprint;
- API level and ABI;
- Frida client version;
- an expiry time.

Every runtime execution must additionally match the exact APK SHA-256, package
name, plan digest, runtime identity and signed approval. The executor force-stops
and uninstalls the approved package during cleanup.

## Start VulnHunter

```bash
bash .devcontainer/start-vulnhunter.sh
```

Startup launches the controlled private target, Nuclei worker, mobile static/native
worker and configured intelligence worker. It starts MobSF only when its protected
policy and key exist. ADB/Frida remains labelled as gated until a non-expired
runtime registration exists.

Keep that Termux session connected while the foreground web server is running. Use
a second Termux session for Codex, or use a terminal multiplexer.

## Open the responsive workspace

In a second Termux session:

```bash
gh codespace ports \
  -c vulnhunter-phone-gpqw9j44xwvcwqpq \
  --json sourcePort,browseUrl,visibility \
  --jq '.[] | select(.sourcePort == 8002) | .browseUrl'
```

Open the returned authenticated URL in the phone or desktop browser. Keep the port
private:

```bash
gh codespace ports visibility 8002:private \
  -c vulnhunter-phone-gpqw9j44xwvcwqpq
```

The APK analysis inspector is state-driven:

- no analysis panel is shown before an APK is attached;
- upload validation reveals artifact identity and inventory;
- plan creation reveals only selected and deferred tools;
- signed worker progress moves real tools through planned, running, completed,
  failed or gated states;
- findings appear only after deterministic judging;
- evidence artifacts appear only after real execution;
- the graph appears only when evidence-bound nodes and relationships exist;
- desktop uses the conversation plus right inspector;
- tablet/mobile uses a slide-over inspector and bottom workspace switcher.

## Run validation inside the Codespace

```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest -q
node --check vulnhunter/web/static/web/conversation-mobile-inspector.js
node --check vulnhunter/web/static/web/conversation-mobile-deferred-tools.js
bash -n .devcontainer/post-create.sh
bash -n .devcontainer/start-vulnhunter.sh
bash -n scripts/start-mobsf-private.sh
```

## Reconnect later

```bash
gh codespace ssh -c vulnhunter-phone-gpqw9j44xwvcwqpq
cd /workspaces/vulnhunter-ai-work
source .codespaces/vulnhunter.env
codex
```

## Stop or delete

Stop the Codespace when finished:

```bash
gh codespace stop -c vulnhunter-phone-gpqw9j44xwvcwqpq
```

Delete it when no longer needed:

```bash
gh codespace delete -c vulnhunter-phone-gpqw9j44xwvcwqpq
```

See `PHONE_ONLY_PRIVATE_LAB.md` for the operator workflow and authorization boundary.
