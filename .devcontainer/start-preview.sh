#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/.codespaces/vulnhunter.env"

printf 'Starting the UI preview only. For a real private-lab worker, use:\n  bash .devcontainer/start-phone-lab.sh\n'
python manage.py migrate --noinput
exec python manage.py runserver 0.0.0.0:8002
