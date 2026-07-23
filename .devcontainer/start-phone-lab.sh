#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
printf 'This compatibility launcher now starts the unified VulnHunter workspace.\n' >&2
exec bash "$ROOT/.devcontainer/start-vulnhunter.sh" "$@"
