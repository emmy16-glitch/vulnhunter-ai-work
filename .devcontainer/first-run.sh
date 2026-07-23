#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/.codespaces/vulnhunter.env"

python manage.py migrate --noinput

read -r -p "Operator governance identity [vulnhunter-user]: " OPERATOR_ID
OPERATOR_ID="${OPERATOR_ID:-vulnhunter-user}"
read -r -p "Operator display name [VulnHunter Operator]: " OPERATOR_DISPLAY
OPERATOR_DISPLAY="${OPERATOR_DISPLAY:-VulnHunter Operator}"
read -r -p "Operator web username [vulnhunter]: " OPERATOR_USERNAME
OPERATOR_USERNAME="${OPERATOR_USERNAME:-vulnhunter}"

read -r -p "Approver governance identity [vulnhunter-approver]: " APPROVER_ID
APPROVER_ID="${APPROVER_ID:-vulnhunter-approver}"
read -r -p "Approver display name [VulnHunter Approver]: " APPROVER_DISPLAY
APPROVER_DISPLAY="${APPROVER_DISPLAY:-VulnHunter Approver}"
read -r -p "Approver web username [vulnhunter-approver]: " APPROVER_USERNAME
APPROVER_USERNAME="${APPROVER_USERNAME:-vulnhunter-approver}"

if [[ "${OPERATOR_ID,,}" == "${APPROVER_ID,,}" \
  || "${OPERATOR_USERNAME,,}" == "${APPROVER_USERNAME,,}" ]]; then
  printf 'The operator and approver must use different governance identities and web accounts.\n' >&2
  exit 2
fi

identity_listing() {
  python -m vulnhunter.governance identity list \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
}

IDENTITIES="$(identity_listing)"
OPERATOR_LINE="$(awk -v id="$OPERATOR_ID" '$1 == id {print; exit}' <<<"$IDENTITIES")"
if [[ -n "$OPERATOR_LINE" ]]; then
  if [[ "$OPERATOR_LINE" != *"reviewer"* && "$OPERATOR_LINE" != *"campaign_admin"* ]]; then
    printf 'Existing operator identity %s lacks a permitted governance role.\n' "$OPERATOR_ID" >&2
    exit 2
  fi
  printf 'Operator governance identity already exists: %s\n' "$OPERATOR_ID"
elif grep -Fq "No governance identities found." <<<"$IDENTITIES"; then
  python -m vulnhunter.governance identity bootstrap \
    --reviewer "$OPERATOR_ID" \
    --display-name "$OPERATOR_DISPLAY" \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
else
  EXISTING_ADMIN="$(awk '/roles=.*campaign_admin/ {print $1; exit}' <<<"$IDENTITIES")"
  if [[ -z "$EXISTING_ADMIN" ]]; then
    printf 'No active campaign administrator is available to create the operator identity.\n' >&2
    exit 2
  fi
  read -r -p "Existing campaign administrator [$EXISTING_ADMIN]: " ADMIN_ID
  ADMIN_ID="${ADMIN_ID:-$EXISTING_ADMIN}"
  printf '\nAuthenticate %s, then choose a governance secret for %s.\n' \
    "$ADMIN_ID" "$OPERATOR_ID"
  python -m vulnhunter.governance identity create \
    --actor "$ADMIN_ID" \
    --reviewer "$OPERATOR_ID" \
    --display-name "$OPERATOR_DISPLAY" \
    --role reviewer \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
fi

IDENTITIES="$(identity_listing)"
APPROVER_LINE="$(awk -v id="$APPROVER_ID" '$1 == id {print; exit}' <<<"$IDENTITIES")"
if [[ -n "$APPROVER_LINE" ]]; then
  if [[ "$APPROVER_LINE" != *"campaign_admin"* ]]; then
    printf 'Existing approver identity %s is not a campaign administrator.\n' "$APPROVER_ID" >&2
    exit 2
  fi
  printf 'Approver governance identity already exists: %s\n' "$APPROVER_ID"
else
  EXISTING_ADMIN="$(awk '/roles=.*campaign_admin/ {print $1; exit}' <<<"$IDENTITIES")"
  if [[ -z "$EXISTING_ADMIN" ]]; then
    printf 'No active campaign administrator is available to create the approver identity.\n' >&2
    exit 2
  fi
  read -r -p "Existing campaign administrator [$EXISTING_ADMIN]: " ADMIN_ID
  ADMIN_ID="${ADMIN_ID:-$EXISTING_ADMIN}"
  printf '\nAuthenticate %s, then choose a separate governance secret for %s.\n' \
    "$ADMIN_ID" "$APPROVER_ID"
  python -m vulnhunter.governance identity create \
    --actor "$ADMIN_ID" \
    --reviewer "$APPROVER_ID" \
    --display-name "$APPROVER_DISPLAY" \
    --role campaign_admin \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
fi

ensure_web_user() {
  local username="$1"
  local identity="$2"
  local role="$3"
  if WEB_USERNAME="$username" python manage.py shell -c \
    'import os; from django.contrib.auth import get_user_model; raise SystemExit(0 if get_user_model().objects.filter(username=os.environ["WEB_USERNAME"]).exists() else 1)'; then
    printf 'Web user already exists: %s\n' "$username"
  else
    printf '\nChoose the web login password for %s.\n' "$username"
    python manage.py vh_create_web_user \
      --username "$username" \
      --governance-identity "$identity" \
      --product-role "$role"
  fi
  WEB_USERNAME="$username" GOVERNANCE_ID="$identity" PRODUCT_ROLE="$role" \
    python manage.py shell -c \
    'import os; from django.contrib.auth import get_user_model; from vulnhunter.web.models import WebUserMapping; user=get_user_model().objects.get(username=os.environ["WEB_USERNAME"]); mapping=WebUserMapping.objects.get(user=user); mapping.governance_identity_id=os.environ["GOVERNANCE_ID"]; mapping.product_roles=[os.environ["PRODUCT_ROLE"]]; mapping.full_clean(); mapping.save(); user.is_staff=True; user.save(update_fields=["is_staff"]); print("Configured", user.username, "as", os.environ["PRODUCT_ROLE"])'
}

ensure_web_user "$OPERATOR_USERNAME" "$OPERATOR_ID" "campaign-operator"
ensure_web_user "$APPROVER_USERNAME" "$APPROVER_ID" "system-administrator"

USERS_FILE="$ROOT/.codespaces/vulnhunter-user.env"
cat > "$USERS_FILE" <<EOF2
export VULNHUNTER_USER_ID="$OPERATOR_ID"
export VULNHUNTER_USERNAME="$OPERATOR_USERNAME"
export VULNHUNTER_OPERATOR_ID="$OPERATOR_ID"
export VULNHUNTER_OPERATOR_USERNAME="$OPERATOR_USERNAME"
export VULNHUNTER_APPROVER_ID="$APPROVER_ID"
export VULNHUNTER_APPROVER_USERNAME="$APPROVER_USERNAME"
EOF2
chmod 600 "$USERS_FILE"

GROQ_KEY_FILE="${VULNHUNTER_GROQ_API_KEY_FILE:-$ROOT/.codespaces/groq-api-key}"
if [[ ! -s "$GROQ_KEY_FILE" && -n "${GROQ_API_KEY:-}" ]]; then
  umask 077
  printf '%s' "$GROQ_API_KEY" > "$GROQ_KEY_FILE"
  chmod 600 "$GROQ_KEY_FILE"
  unset GROQ_API_KEY
  printf 'Configured the protected Groq key file from the Codespaces secret.\n'
fi
if [[ ! -s "$GROQ_KEY_FILE" ]]; then
  printf '\nGroq powers conversational request interpretation and bounded finding analysis.\n'
  read -r -p "Configure your Groq API key now? [Y/n]: " CONFIGURE_GROQ
  CONFIGURE_GROQ="${CONFIGURE_GROQ:-Y}"
  if [[ "${CONFIGURE_GROQ,,}" != "n" && "${CONFIGURE_GROQ,,}" != "no" ]]; then
    python manage.py vh_configure_groq --key-file "$GROQ_KEY_FILE"
  else
    printf 'Groq was left unconfigured. Deterministic planning will remain available.\n'
  fi
else
  printf 'Groq key file is ready: %s\n' "$GROQ_KEY_FILE"
fi

printf '\nVulnHunter setup is complete. Start the workspace with:\n'
printf '  bash .devcontainer/start-vulnhunter.sh\n\n'
printf 'Create and monitor assessments as: %s\n' "$OPERATOR_USERNAME"
printf 'Approve exact plans as the separate account: %s\n' "$APPROVER_USERNAME"
