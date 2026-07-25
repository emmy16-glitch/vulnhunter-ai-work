#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p "$HOME/.local/bin"
chmod 700 "$HOME/.local" "$HOME/.local/bin" 2>/dev/null || true
export PATH="$HOME/.local/bin:$PATH"

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
bash .devcontainer/install-codex.sh
bash .devcontainer/install-mobile-static-tools.sh
bash .devcontainer/install-nuclei.sh

STATE_DIR="$ROOT/.codespaces"
RUNTIME_DIR="$STATE_DIR/runtime"
ENV_FILE="$STATE_DIR/vulnhunter.env"
NUCLEI_BIN="$STATE_DIR/tools/nuclei-v3.8.0/bin/nuclei"
TEMPLATE_ROOT="$RUNTIME_DIR/pilot-templates"
POLICY_FILE="$RUNTIME_DIR/nuclei-worker.json"
SIGNING_KEY="$RUNTIME_DIR/nuclei-worker.key"
MOBILE_POLICY_FILE="$RUNTIME_DIR/mobile-static-worker.json"
MOBILE_SIGNING_KEY="$RUNTIME_DIR/mobile-static-worker.key"
MOBILE_WORKSPACE="$ROOT/.local/mobile-static-workspace"
MOBILE_SPOOL_ROOT="$ROOT/.local/mobile-static-spool"
MOBILE_ARTIFACT_ROOT="$ROOT/.local/mobile-artifacts"
MOBSF_POLICY_FILE="$RUNTIME_DIR/mobsf.json"
MOBSF_API_KEY_FILE="$RUNTIME_DIR/mobsf-api.key"
MOBILE_RUNTIME_POLICY_FILE="$RUNTIME_DIR/mobile-runtime.json"
MOBILE_RUNTIME_APPROVAL_KEY="$RUNTIME_DIR/mobile-runtime-approval.key"
GROQ_KEY="$STATE_DIR/groq-api-key"
mkdir -p "$RUNTIME_DIR" "$TEMPLATE_ROOT"
chmod 700 "$STATE_DIR" "$RUNTIME_DIR"

rm -rf "$TEMPLATE_ROOT"
mkdir -p "$TEMPLATE_ROOT"
cp -a "$ROOT/config/security_tools/pilot_templates/." "$TEMPLATE_ROOT/"
find "$TEMPLATE_ROOT" -type d -exec chmod 0555 {} +
find "$TEMPLATE_ROOT" -type f -exec chmod 0444 {} +

if [[ ! -f "$SIGNING_KEY" ]]; then
  umask 077
  python -c 'import secrets,sys; sys.stdout.buffer.write(secrets.token_bytes(48))' > "$SIGNING_KEY"
fi
chmod 600 "$SIGNING_KEY"

if [[ ! -f "$MOBILE_SIGNING_KEY" ]]; then
  umask 077
  python -c 'import secrets,sys; sys.stdout.buffer.write(secrets.token_bytes(48))' > "$MOBILE_SIGNING_KEY"
fi
chmod 600 "$MOBILE_SIGNING_KEY"

if [[ ! -f "$MOBILE_RUNTIME_APPROVAL_KEY" ]]; then
  umask 077
  python -c 'import secrets,sys; sys.stdout.buffer.write(secrets.token_bytes(48))' > "$MOBILE_RUNTIME_APPROVAL_KEY"
fi
chmod 600 "$MOBILE_RUNTIME_APPROVAL_KEY"

POLICY_FILE="$POLICY_FILE" NUCLEI_BIN="$NUCLEI_BIN" TEMPLATE_ROOT="$TEMPLATE_ROOT" python - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["POLICY_FILE"])
payload = {
    "schema_version": "1.0",
    "enabled": True,
    "worker_id": "codespaces-vulnhunter-worker",
    "nuclei_executable": os.environ["NUCLEI_BIN"],
    "template_root": os.environ["TEMPLATE_ROOT"],
    "maximum_rate_limit": 1,
    "maximum_concurrency": 1,
    "maximum_observations": 25,
    "poll_interval_seconds": 0.1,
    "private_targets_only": True,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
chmod 600 "$POLICY_FILE"

python scripts/prepare_mobile_static_worker.py \
  --policy "$MOBILE_POLICY_FILE" \
  --workspace "$MOBILE_WORKSPACE" \
  --worker-id codespaces-mobile-static-worker
chmod 600 "$MOBILE_POLICY_FILE"
MOBILE_WORKER_ENABLED="$(MOBILE_POLICY_FILE="$MOBILE_POLICY_FILE" python - <<'PY'
import json
import os
from pathlib import Path

payload = json.loads(Path(os.environ["MOBILE_POLICY_FILE"]).read_text(encoding="utf-8"))
print("true" if payload.get("enabled") is True else "false")
PY
)"

cat > "$ENV_FILE" <<EOF2
export VULNHUNTER_WEB_DEBUG=true
export VULNHUNTER_WEB_HTTPS=false
export VULNHUNTER_WEB_ALLOWED_HOSTS=".app.github.dev,localhost,127.0.0.1"
export VULNHUNTER_WEB_CSRF_TRUSTED_ORIGINS="https://*.app.github.dev,https://localhost:8002"
export VULNHUNTER_WEB_DATABASE="$ROOT/.local/vulnhunter-web.sqlite3"
export VULNHUNTER_AUTHORIZATION_DATABASE="$ROOT/.local/runtime/authorization/authorizations.db"
export VULNHUNTER_GOVERNANCE_DATABASE="$ROOT/.local/runtime/governance/governance.db"
export VULNHUNTER_AGENT_DATABASE="$ROOT/.local/runtime/agent/agent.db"
export VULNHUNTER_APPROVAL_DATABASE="$ROOT/.local/approvals.sqlite3"
export VULNHUNTER_AGENT_ACTIVITY_ROOT="$ROOT/.local/agent-activity"
export VULNHUNTER_SECURITY_EVIDENCE_ROOT="$ROOT/.local/security-evidence"
export VULNHUNTER_MOBILE_ARTIFACT_ROOT="$MOBILE_ARTIFACT_ROOT"
export VULNHUNTER_MOBILE_STATIC_WORKER_POLICY="$MOBILE_POLICY_FILE"
export VULNHUNTER_MOBILE_STATIC_SIGNING_KEY_FILE="$MOBILE_SIGNING_KEY"
export VULNHUNTER_MOBILE_STATIC_SPOOL_ROOT="$MOBILE_SPOOL_ROOT"
export VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED=$MOBILE_WORKER_ENABLED
export VULNHUNTER_MOBSF_POLICY="$MOBSF_POLICY_FILE"
export VULNHUNTER_MOBSF_API_KEY_FILE="$MOBSF_API_KEY_FILE"
export VULNHUNTER_MOBILE_RUNTIME_POLICY="$MOBILE_RUNTIME_POLICY_FILE"
export VULNHUNTER_MOBILE_RUNTIME_APPROVAL_KEY_FILE="$MOBILE_RUNTIME_APPROVAL_KEY"
export VULNHUNTER_NUCLEI_EXECUTABLE="$NUCLEI_BIN"
export VULNHUNTER_NUCLEI_TEMPLATE_ROOT="$TEMPLATE_ROOT"
export VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST="$ROOT/config/security_tools/nuclei_template_manifest.json"
export VULNHUNTER_NUCLEI_READINESS_REPORT="$RUNTIME_DIR/readiness.json"
export VULNHUNTER_NUCLEI_WORKER_POLICY="$POLICY_FILE"
export VULNHUNTER_NUCLEI_WORKER_SIGNING_KEY_FILE="$SIGNING_KEY"
export VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT="$ROOT/.local/nuclei-worker-spool"
export VULNHUNTER_NUCLEI_EXECUTION_ROOT="$ROOT/.local/nuclei-executions"
export VULNHUNTER_VERIFICATION_ROOT="$ROOT/.local/verification"
export VULNHUNTER_NUCLEI_PILOT_ENQUEUE_ENABLED=true
export VULNHUNTER_LAB_TARGET_PORT=8010
export VULNHUNTER_GROQ_ENABLED=true
export VULNHUNTER_GROQ_API_KEY_FILE="$GROQ_KEY"
export VULNHUNTER_INTELLIGENCE_ENABLED=true
export VULNHUNTER_INTELLIGENCE_ROOT="$ROOT/.local/intelligence"
export VULNHUNTER_INTELLIGENCE_PRIMARY_MODEL="openai/gpt-oss-20b"
export VULNHUNTER_INTELLIGENCE_DEEP_MODEL="openai/gpt-oss-120b"
export VULNHUNTER_INTELLIGENCE_MAX_ATTEMPTS=2
export VULNHUNTER_INTELLIGENCE_TIMEOUT_SECONDS=90
export VULNHUNTER_INTELLIGENCE_MAX_INPUT_BYTES=64000
export VULNHUNTER_INTELLIGENCE_MAX_OUTPUT_TOKENS=2400
export PATH="$HOME/.local/bin:$(dirname "$NUCLEI_BIN"):${PATH}"
if [[ -f "$STATE_DIR/vulnhunter-user.env" ]]; then
  source "$STATE_DIR/vulnhunter-user.env"
fi
EOF2
chmod 600 "$ENV_FILE"

SOURCE_LINE="source \"$ENV_FILE\""
if ! grep -Fqx "$SOURCE_LINE" "$HOME/.bashrc" 2>/dev/null; then
  printf '\n# VulnHunter Codespaces environment\n%s\n' "$SOURCE_LINE" >> "$HOME/.bashrc"
fi

source "$ENV_FILE"
mkdir -p \
  "$(dirname "$VULNHUNTER_WEB_DATABASE")" \
  "$(dirname "$VULNHUNTER_AUTHORIZATION_DATABASE")" \
  "$(dirname "$VULNHUNTER_GOVERNANCE_DATABASE")" \
  "$(dirname "$VULNHUNTER_AGENT_DATABASE")" \
  "$VULNHUNTER_AGENT_ACTIVITY_ROOT" \
  "$VULNHUNTER_SECURITY_EVIDENCE_ROOT" \
  "$VULNHUNTER_MOBILE_ARTIFACT_ROOT" \
  "$VULNHUNTER_MOBILE_STATIC_SPOOL_ROOT" \
  "$MOBILE_WORKSPACE" \
  "$VULNHUNTER_NUCLEI_WORKER_SPOOL_ROOT" \
  "$VULNHUNTER_NUCLEI_EXECUTION_ROOT" \
  "$VULNHUNTER_VERIFICATION_ROOT" \
  "$VULNHUNTER_INTELLIGENCE_ROOT"

python scripts/nuclei_readiness.py \
  --executable "$VULNHUNTER_NUCLEI_EXECUTABLE" \
  --manifest "$VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST" \
  --template-root "$VULNHUNTER_NUCLEI_TEMPLATE_ROOT" \
  --execution-enabled \
  --output "$VULNHUNTER_NUCLEI_READINESS_REPORT" \
  --require-ready
python manage.py migrate --noinput
python manage.py vh_init_agent_store

printf '\nVulnHunter Codespace is prepared with Codex, bounded reasoning, the pinned Nuclei worker, and the governed mobile worker stack.\n'
printf 'Codex: %s\n' "$(codex --version)"
printf 'Mobile static enqueue enabled: %s\n' "$VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED"
printf 'MobSF policy path: %s\n' "$VULNHUNTER_MOBSF_POLICY"
printf 'Disposable runtime policy path: %s\n' "$VULNHUNTER_MOBILE_RUNTIME_POLICY"
printf 'Run: bash .devcontainer/first-run.sh\n'
