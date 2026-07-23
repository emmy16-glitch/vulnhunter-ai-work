#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/.codespaces/vulnhunter.env"

python manage.py migrate --noinput

read -r -p "VulnHunter governance identity [vulnhunter-user]: " USER_ID
USER_ID="${USER_ID:-vulnhunter-user}"
read -r -p "Display name [VulnHunter User]: " USER_DISPLAY
USER_DISPLAY="${USER_DISPLAY:-VulnHunter User}"
read -r -p "Web username [vulnhunter]: " USERNAME
USERNAME="${USERNAME:-vulnhunter}"

identity_listing() {
  python -m vulnhunter.governance identity list \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
}

IDENTITIES="$(identity_listing)"
USER_LINE="$(awk -v id="$USER_ID" '$1 == id {print; exit}' <<<"$IDENTITIES")"
if [[ -n "$USER_LINE" ]]; then
  if [[ "$USER_LINE" != *"campaign_admin"* ]]; then
    printf 'Existing identity %s is not a campaign administrator.\n' "$USER_ID" >&2
    exit 2
  fi
  printf 'VulnHunter governance identity already exists: %s\n' "$USER_ID"
elif grep -Fq "No governance identities found." <<<"$IDENTITIES"; then
  python -m vulnhunter.governance identity bootstrap \
    --reviewer "$USER_ID" \
    --display-name "$USER_DISPLAY" \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
else
  EXISTING_ADMIN="$(awk '/roles=.*campaign_admin/ {print $1; exit}' <<<"$IDENTITIES")"
  if [[ -z "$EXISTING_ADMIN" ]]; then
    printf 'No active campaign administrator is available to create the VulnHunter identity.\n' >&2
    exit 2
  fi
  read -r -p "Existing campaign administrator [$EXISTING_ADMIN]: " ADMIN_ID
  ADMIN_ID="${ADMIN_ID:-$EXISTING_ADMIN}"
  printf '\nAuthenticate %s, then choose a governance secret for %s.\n' \
    "$ADMIN_ID" "$USER_ID"
  python -m vulnhunter.governance identity create \
    --actor "$ADMIN_ID" \
    --reviewer "$USER_ID" \
    --display-name "$USER_DISPLAY" \
    --role campaign_admin \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
fi

if WEB_USERNAME="$USERNAME" python manage.py shell -c \
  'import os; from django.contrib.auth import get_user_model; raise SystemExit(0 if get_user_model().objects.filter(username=os.environ["WEB_USERNAME"]).exists() else 1)'; then
  printf 'Web user already exists: %s\n' "$USERNAME"
else
  printf '\nChoose the VulnHunter login password for %s.\n' "$USERNAME"
  python manage.py vh_create_web_user \
    --username "$USERNAME" \
    --governance-identity "$USER_ID" \
    --product-role security-analyst
fi

WEB_USERNAME="$USERNAME" GOVERNANCE_ID="$USER_ID" python manage.py shell -c \
  'import os; from django.contrib.auth import get_user_model; from vulnhunter.web.models import WebUserMapping; user=get_user_model().objects.get(username=os.environ["WEB_USERNAME"]); mapping=WebUserMapping.objects.get(user=user); mapping.governance_identity_id=os.environ["GOVERNANCE_ID"]; mapping.product_roles=["security-analyst"]; mapping.full_clean(); mapping.save(); user.is_staff=True; user.save(update_fields=["is_staff"]); print("Configured", user.username, "as Security Analyst")'

USERS_FILE="$ROOT/.codespaces/vulnhunter-user.env"
cat > "$USERS_FILE" <<EOF2
export VULNHUNTER_USER_ID="$USER_ID"
export VULNHUNTER_USERNAME="$USERNAME"
EOF2
chmod 600 "$USERS_FILE"

GROQ_KEY_FILE="${VULNHUNTER_GROQ_API_KEY_FILE:-$ROOT/.codespaces/groq-api-key}"
if [[ ! -s "$GROQ_KEY_FILE" ]]; then
  printf '\nGroq powers conversational request interpretation and result assistance.\n'
  read -r -p "Configure your Groq API key now? [Y/n]: " CONFIGURE_GROQ
  CONFIGURE_GROQ="${CONFIGURE_GROQ:-Y}"
  if [[ "${CONFIGURE_GROQ,,}" != "n" && "${CONFIGURE_GROQ,,}" != "no" ]]; then
    python manage.py vh_configure_groq --key-file "$GROQ_KEY_FILE"
  else
    printf 'Groq was left unconfigured. Deterministic planning will remain available.\n'
  fi
else
  printf 'Groq key file already exists: %s\n' "$GROQ_KEY_FILE"
fi

printf '\nVulnHunter setup is complete. Start the workspace with:\n'
printf '  bash .devcontainer/start-vulnhunter.sh\n\n'
printf 'Login username: %s\n' "$USERNAME"
printf 'The same account creates, confirms and monitors each bounded assessment.\n'
