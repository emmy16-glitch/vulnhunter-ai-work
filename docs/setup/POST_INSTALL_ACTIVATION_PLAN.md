# Post-install activation plan

The core completion package intentionally performs no system installation.
Activate optional capabilities one at a time after reviewing the dependency
matrix.

## Recommended order

1. Run `python3 scripts/dependency_readiness.py`.
2. Review `docs/setup/DEPENDENCY_AND_DOWNLOAD_MATRIX.md`.
3. Validate already installed tools through the restricted adapter readiness
   checks before adding new tools.
4. Install Graphify only through the reviewed manual runbook, keep it local and
   non-authoritative, and complete the learning period before relying on it.
5. Select one local AI runtime only when the VM has adequate memory and a model
   license has been reviewed.
6. Add remote provider credentials only through environment/secret management;
   never put them in the repository.
7. Create an isolated disposable environment before any dynamic APK or binary
   execution.
8. Deploy only after an independent security review, production key setup,
   backup/restore validation and an authorized pilot plan.

## Explicitly not automatic

- sudo or system package installation;
- Graphify or MCP activation;
- Ollama model downloads;
- cloud provider configuration;
- scanner/template downloads;
- Docker, emulator, MobSF, Frida or Ghidra installation;
- privileged service installation;
- production database or reverse-proxy setup;
- scans against any external target.
