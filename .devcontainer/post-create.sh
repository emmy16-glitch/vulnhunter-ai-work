#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

STATE_DIR="$ROOT/.codespaces"
ENV_FILE="$STATE_DIR/vulnhunter.env"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

cat > "$ENV_FILE" <<EOF
export VULNHUNTER_WEB_DEBUG=true
export VULNHUNTER_WEB_HTTPS=false
export VULNHUNTER_WEB_ALLOWED_HOSTS=".app.github.dev,localhost,127.0.0.1"
export VULNHUNTER_WEB_CSRF_TRUSTED_ORIGINS="https://*.app.github.dev"
export VULNHUNTER_WEB_DATABASE="$ROOT/.local/vulnhunter-web.sqlite3"
export VULNHUNTER_AUTHORIZATION_DATABASE="$ROOT/.local/runtime/authorization/authorizations.db"
export VULNHUNTER_GOVERNANCE_DATABASE="$ROOT/.local/runtime/governance/governance.db"
export VULNHUNTER_AGENT_DATABASE="$ROOT/.local/runtime/agent/agent.db"
export VULNHUNTER_AGENT_ACTIVITY_ROOT="$ROOT/.local/agent-activity"
EOF
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
  "$VULNHUNTER_AGENT_ACTIVITY_ROOT"

python manage.py migrate --noinput
python manage.py vh_init_agent_store

printf '\nVulnHunter Codespace is prepared. Run: bash .devcontainer/first-run.sh\n'
