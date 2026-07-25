#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.codespaces/vulnhunter.env"
RUNTIME_DIR="$ROOT/.codespaces/runtime"
SIGNING_KEY="$RUNTIME_DIR/mobile-extension-worker.key"
SPOOL_ROOT="$ROOT/.local/mobile-extension-spool"
RESULT_ROOT="$ROOT/.local/mobile-extension-results"

[[ -f "$ENV_FILE" ]] || {
  printf 'VulnHunter environment file is unavailable: %s\n' "$ENV_FILE" >&2
  exit 2
}
mkdir -p "$RUNTIME_DIR" "$SPOOL_ROOT" "$RESULT_ROOT"
chmod 700 "$RUNTIME_DIR" "$SPOOL_ROOT" "$RESULT_ROOT"
if [[ ! -f "$SIGNING_KEY" ]]; then
  umask 077
  python -c 'import secrets,sys; sys.stdout.buffer.write(secrets.token_bytes(48))' > "$SIGNING_KEY"
fi
chmod 600 "$SIGNING_KEY"

ENV_FILE="$ENV_FILE" SIGNING_KEY="$SIGNING_KEY" SPOOL_ROOT="$SPOOL_ROOT" RESULT_ROOT="$RESULT_ROOT" python - <<'PY'
import os
from pathlib import Path

path = Path(os.environ["ENV_FILE"])
keys = {
    "VULNHUNTER_MOBILE_EXTENSION_SIGNING_KEY_FILE": os.environ["SIGNING_KEY"],
    "VULNHUNTER_MOBILE_EXTENSION_SPOOL_ROOT": os.environ["SPOOL_ROOT"],
    "VULNHUNTER_MOBILE_EXTENSION_RESULT_ROOT": os.environ["RESULT_ROOT"],
}
lines = path.read_text(encoding="utf-8").splitlines()
prefixes = tuple(f"export {key}=" for key in keys)
lines = [line for line in lines if not line.startswith(prefixes)]
insert_at = next(
    (index for index, line in enumerate(lines) if line.startswith("export PATH=")),
    len(lines),
)
exports = [f'export {key}="{value}"' for key, value in keys.items()]
lines[insert_at:insert_at] = exports
path.write_text("\n".join(lines) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

printf 'Configured the signed mobile extension worker.\n'
