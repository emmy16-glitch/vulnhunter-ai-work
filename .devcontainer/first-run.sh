#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/.codespaces/vulnhunter.env"

read -r -p "Governance identity [phone-admin]: " REVIEWER_ID
REVIEWER_ID="${REVIEWER_ID:-phone-admin}"
read -r -p "Display name [Phone Admin]: " DISPLAY_NAME
DISPLAY_NAME="${DISPLAY_NAME:-Phone Admin}"
read -r -p "Web username [emmanuel]: " WEB_USERNAME
WEB_USERNAME="${WEB_USERNAME:-emmanuel}"

if python -m vulnhunter.governance identity list \
  --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE" \
  | grep -Fq "$REVIEWER_ID"; then
  printf 'Governance identity already exists: %s\n' "$REVIEWER_ID"
else
  python -m vulnhunter.governance identity bootstrap \
    --reviewer "$REVIEWER_ID" \
    --display-name "$DISPLAY_NAME" \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
fi

if python manage.py shell -c \
  "from django.contrib.auth import get_user_model; raise SystemExit(0 if get_user_model().objects.filter(username='$WEB_USERNAME').exists() else 1)"; then
  printf 'Web user already exists: %s\n' "$WEB_USERNAME"
else
  python manage.py vh_create_web_user \
    --username "$WEB_USERNAME" \
    --governance-identity "$REVIEWER_ID" \
    --product-role system-administrator
fi

WEB_USERNAME="$WEB_USERNAME" python manage.py shell -c \
  'import os; from django.contrib.auth import get_user_model; user=get_user_model().objects.get(username=os.environ["WEB_USERNAME"]); user.is_staff=True; user.save(update_fields=["is_staff"]); print("Staff access enabled for", user.username)'

printf '\nFirst-time setup is complete. Start the site with:\n  bash .devcontainer/start-preview.sh\n'
