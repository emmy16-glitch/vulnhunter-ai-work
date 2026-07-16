# Dependency and Download Matrix

## Security-tool readiness update — 2026-07-15

The dated 2026-07-13 environment snapshot below is retained as historical
installation provenance. The governed integration installed on 2026-07-15 now
reports all 14 standard tools ready: Nmap, ProjectDiscovery httpx, Nuclei, ffuf,
testssl.sh, Trivy, Bearer, Bandit, detect-secrets, Gitleaks, Syft, Grype,
OSV-Scanner, and capa. The authoritative machine-readable evidence is
`var/readiness/security-tool-integration.json`.

Readiness means that the executable and bounded version probe succeeded. It does
not enable execution, establish target authorization, approve network access,
or activate an adapter. Rows below that say these tools were absent describe the
older snapshot and must not override the newer readiness evidence.

## Environment snapshot

- Recorded: `2026-07-13`
- Host: Ubuntu 26.04 LTS, 2 CPUs, 9 GiB RAM, 1 GiB swap.
- Free space: approximately 50 GiB on `/mnt/vulnhunter-data`; 4.6 GiB on `/`.
- No dependency was installed, upgraded, downloaded, activated, or started by
  this audit.
- `ALREADY_INSTALLED` means executable presence and, where inexpensive,
  version output were observed. It does not prove adapter readiness.
- `REVIEW_REQUIRED` in an install field is fail-closed: no exact safe command
  can be approved until version, source, license, package hash, and resource
  impact are recorded.

## Candidate matrix

| Dependency | Purpose / adapter | Required | Detected version | Recommended version | Source / license | Approx. download / installed size | CPU/RAM/disk and network | Sudo / credential | Scope | Wave | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Nmap | bounded network discovery | Optional | 7.98 | retain detected pending adapter tests | OS package; license review recorded before redistribution | already present | low/moderate; network target authorization required | no / no | system | 4 | ALREADY_INSTALLED |
| ProjectDiscovery httpx | HTTP metadata adapter | Optional | absent | REVIEW_REQUIRED | upstream release; license review required | REVIEW_REQUIRED | low/moderate; network authorization required | no preferred / no | isolated user tool | 4 | MANUAL_SYSTEM_INSTALL |
| Nuclei | bounded template assessment | Optional | absent | REVIEW_REQUIRED | upstream release/templates require separate provenance | REVIEW_REQUIRED; templates add disk/network | moderate; network authorization required | no preferred / no | isolated user tool | 4 | MANUAL_SYSTEM_INSTALL |
| ffuf | approved wordlist discovery | Optional | absent | REVIEW_REQUIRED | upstream release; license review required | REVIEW_REQUIRED plus wordlists | moderate/high request load | no preferred / no | isolated user tool | 4 | MANUAL_SYSTEM_INSTALL |
| OWASP ZAP | web/API connector | Optional | absent | REVIEW_REQUIRED | OWASP upstream; Apache-family license review | hundreds of MiB expected | high RAM/CPU; network authorization required | no preferred / no | isolated service | 4 | MANUAL_LARGE_DOWNLOAD |
| testssl.sh | TLS assessment | Optional | absent | REVIEW_REQUIRED | upstream Git tag; GPL-family review | small repository plus OpenSSL tools | moderate; network authorization required | no / no | isolated user tool | 4 | MANUAL_SYSTEM_INSTALL |
| Semgrep CE | source SAST | Optional | absent | REVIEW_REQUIRED | official package; license/ruleset review | potentially hundreds of MiB | moderate/high on repository scans; registry rules may use network | no / possible registry | isolated user tool | 4 | MANUAL_LARGE_DOWNLOAD |
| Bandit | Python SAST | Optional | absent | REVIEW_REQUIRED | PyPI; Apache-family license review | tens of MiB | low/moderate; no network after install | no / no | isolated user tool | 4 | SAFE_PROJECT_LOCAL_INSTALL |
| Gitleaks | secret scanning | Optional | absent | REVIEW_REQUIRED | signed upstream release; MIT-family review | tens of MiB | low/moderate; no scan network | no / no | isolated user tool | 4 | MANUAL_SYSTEM_INSTALL |
| detect-secrets | secret scanning | Optional | absent | REVIEW_REQUIRED | PyPI; Apache-family review | tens of MiB | low/moderate; plugins may vary | no / no | isolated user tool | 4 | SAFE_PROJECT_LOCAL_INSTALL |
| Trivy | filesystem/image/SBOM | Optional | absent | REVIEW_REQUIRED | official release; Apache-family review | tens to hundreds of MiB plus vulnerability DB | moderate/high; DB network/download | no preferred / no | isolated user tool | 4/12 | MANUAL_LARGE_DOWNLOAD |
| Grype | dependency/image findings | Optional | absent | REVIEW_REQUIRED | official release; Apache-family review | tens of MiB plus DB | moderate; DB network/download | no / no | isolated user tool | 4 | MANUAL_LARGE_DOWNLOAD |
| Syft | SBOM generation | Optional | absent | REVIEW_REQUIRED | official release; Apache-family review | tens of MiB | moderate; normally local | no / no | isolated user tool | 4/12 | MANUAL_SYSTEM_INSTALL |
| OSV-Scanner | dependency audit | Optional | absent | REVIEW_REQUIRED | official release; Apache-family review | tens of MiB | moderate; advisory network/cache | no / no | isolated user tool | 4 | MANUAL_SYSTEM_INSTALL |
| JADX | DEX/source inspection | Optional | executable at `~/.local/bin/jadx`; version command did not complete inside 5s | retain only after readiness check | existing local install; provenance pending | already present | moderate/high CPU/RAM on APKs | no / no | user tool | 7 | ALREADY_INSTALLED |
| Apktool | manifest/resource/smali decode | Optional | installed; version command did not complete inside 5s | retain after readiness check | OS package; Apache-family review | already present | moderate; local APK only | no / no | system | 7 | ALREADY_INSTALLED |
| Android build/platform tools | `apksigner`, `aapt`, `aapt2`, `adb` | Static tools required; ADB dynamic-only | AAPT Debian 0.2; AAPT2 Debian 2.19; ADB 34.0.5 | retain detected for static; ADB disabled | Android SDK package/license | already present | static low/moderate; ADB requires isolated emulator | no / no | system | 7 | ALREADY_INSTALLED |
| MobSF | complex static/dynamic mobile connector | Optional | absent | REVIEW_REQUIRED | official project; GPL-family review | multi-GB with container/images | high CPU/RAM/disk; service network | manual / no | isolated service | 7 | RESOURCE_DEFERRED |
| Frida / Objection | dynamic instrumentation | Optional | absent | REVIEW_REQUIRED | official packages; license review | hundreds of MiB plus matching server | high; isolated emulator/device only | no preferred / no | isolated environment | 7 | MANUAL_LARGE_DOWNLOAD |
| YARA | governed static rules | Optional | absent | REVIEW_REQUIRED | OS/upstream; BSD-family review; rules separate | small binary plus reviewed rules | low/moderate | manual / no | system or isolated tool | 7/8 | MANUAL_SYSTEM_INSTALL |
| Ghidra | native reverse engineering | Optional | absent | REVIEW_REQUIRED | official distribution; Apache 2.0 | hundreds of MiB to >1 GiB | high CPU/RAM/disk; never execute sample | no / no | isolated user tool | 7/8 | RESOURCE_DEFERRED |
| capa | binary capability mapping | Optional | absent | REVIEW_REQUIRED | official release; Apache-family review; rules provenance | tens to hundreds of MiB | moderate/high; local static only | no / no | isolated user tool | 8 | MANUAL_LARGE_DOWNLOAD |
| radare2 / rabin2 | binary metadata | Optional | absent | REVIEW_REQUIRED | official release/OS package; LGPL-family review | tens of MiB | moderate; local static only | manual / no | system or isolated tool | 8 | MANUAL_SYSTEM_INSTALL |
| binwalk | firmware/archive inspection | Optional | absent | REVIEW_REQUIRED | official package; license/plugin review | tens of MiB plus extractors | moderate/high; extraction requires quarantine | manual / no | isolated tool | 8 | MANUAL_SYSTEM_INSTALL |
| GNU binutils and file | `file`, `strings`, `readelf`, `objdump`, `nm` | Required for light static binary path | file 5.46; binutils 2.46 | retain detected | Ubuntu packages; distribution licenses | already present | low/moderate; no sample execution | no / no | system | 8 | ALREADY_INSTALLED |
| Graphify CLI (`graphifyy`) | non-authoritative repository graph learning | Optional | absent | 0.9.12 candidate, pinned only after review | official PyPI/GitHub; MIT; wheel roughly 1-2 MB plus dependencies | estimated <200 MiB isolated install; generated graph varies | code-only mode local; semantic backends require network/credentials; query log exists | no / no for code-only | isolated user tool | reconciliation/2 | MANUAL_INSTALL_REQUIRED |
| Graphify MCP extras | later restricted local graph queries | Optional | absent | none approved | optional upstream extras; separate review | unknown, larger than core | local service adds memory/process exposure | no / no | isolated local service | later | LATE_STAGE_GATED |
| Ollama | local provider runtime | Optional | client 0.31.2; server unavailable | retain client; no model approved | existing system install; upstream license/model licenses separate | no new client download; models often multi-GB | server/model RAM exceeds light tasks; no model auto-load | no / no | system client | 3 | ACTIVATION_REQUIRED |
| llama.cpp-compatible server | alternative local provider | Optional | absent | REVIEW_REQUIRED | upstream build/release and model licenses | binary modest; models multi-GB | CPU/RAM intensive; manual model download | no preferred / no | isolated user tool | 3 | RESOURCE_DEFERRED |
| OpenAI / Anthropic / Gemini / Groq | remote AI providers | Optional | contracts only | API-specific reviewed version | external services; terms/data-processing review | no local model; network usage/cost | protected data prohibited without explicit policy | no / yes | external | 3 | CREDENTIAL_REQUIRED |
| Docker or Podman | disposable services/emulators | Optional | absent | no engine selected | OS/upstream; daemon/rootless security review | hundreds of MiB plus images | high disk/RAM; network downloads | manual system action / no | system | 7/14 | MANUAL_SYSTEM_INSTALL |
| PostgreSQL | production database readiness | Optional | absent | no deployment version selected | OS/upstream; PostgreSQL license | hundreds of MiB including data | service RAM/disk; no current need | manual / secret at deployment | system service | 14 | NOT_REQUIRED |
| Redis | queue/cache readiness | Optional | absent | no deployment version selected | OS/upstream; license review required | tens of MiB plus data | resident service RAM; no current need | manual / secret at deployment | system service | 14 | NOT_REQUIRED |
| Privileged broker | allowlisted privileged actions | Optional | absent | no installable artifact exists | VulnHunter-native future component | unknown | separate process and audit storage | manual / short-lived grants | system service | 11 | MANUAL_SYSTEM_INSTALL |
| Reverse proxy / production services | deployment | Optional | absent/unselected | no deployment target selected | deployment-specific | unknown | persistent services and external exposure | manual / deployment secrets | system | 14 | NOT_REQUIRED |

## Installation command policy

- Installed tools are not reinstalled or upgraded during this programme.
- Rows marked `REVIEW_REQUIRED` deliberately have no executable installation
  command yet. Adding a command before choosing a pinned version and verifying
  source, hash, license, and resource impact would violate the dependency gate.
- Graphify is the only absent dependency with a prompt-mandated preparatory
  runbook. Its exact disabled-by-default procedure is in
  `MANUAL_INSTALL_RUNBOOK.md`; it must not be run until separately approved.
- Large models, services, containers, emulators, Ghidra, MobSF, Frida, and
  dynamic-analysis infrastructure remain manual or resource-deferred.

## Graphify provenance note

The official project identifies the PyPI distribution as `graphifyy` while the
CLI is `graphify`. It documents local AST parsing for code-only corpora, optional
remote/local semantic backends, optional MCP service modes, and a query log.
VulnHunter must force code-only/local behavior for the learning period, disable
hooks and MCP, set an isolated output/cache location, disable query logging, and
treat all graph output as untrusted non-authoritative evidence.

Authoritative sources consulted:

- <https://github.com/Graphify-Labs/graphify>
- <https://github.com/Graphify-Labs/graphify/releases>
- <https://pypi.org/project/graphifyy/>

## Canonical reconciliation status

- Reconciliation passed with `608` explicit rows and `UNMAPPED=0`.
- Graphify remains `MANUAL_INSTALL_REQUIRED`; the CLI learning period remains
  `EXTERNAL_PREREQUISITE`; the restricted MCP service remains
  `LATE_STAGE_GATED`.
- Wave 1 requires no new package, credential, model, service, or download.
- No dependency was installed, downloaded, upgraded, started, or activated
  during reconciliation.
