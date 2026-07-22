#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/.codespaces/vulnhunter.env"

read -r -p "Approver governance identity [phone-approver]: " APPROVER_ID
APPROVER_ID="${APPROVER_ID:-phone-approver}"
read -r -p "Approver display name [Phone Approver]: " APPROVER_DISPLAY
APPROVER_DISPLAY="${APPROVER_DISPLAY:-Phone Approver}"
read -r -p "Approver web username [phone-approver]: " APPROVER_USERNAME
APPROVER_USERNAME="${APPROVER_USERNAME:-phone-approver}"

read -r -p "Operator governance identity [phone-operator]: " OPERATOR_ID
OPERATOR_ID="${OPERATOR_ID:-phone-operator}"
read -r -p "Operator display name [Phone Operator]: " OPERATOR_DISPLAY
OPERATOR_DISPLAY="${OPERATOR_DISPLAY:-Phone Operator}"
read -r -p "Operator web username [phone-operator]: " OPERATOR_USERNAME
OPERATOR_USERNAME="${OPERATOR_USERNAME:-phone-operator}"

if [[ "${APPROVER_ID,,}" == "${OPERATOR_ID,,}" \
  || "${APPROVER_USERNAME,,}" == "${OPERATOR_USERNAME,,}" ]]; then
  printf 'The operator and approver must use different governance identities and web accounts.\n' >&2
  exit 2
fi

identity_listing() {
  python -m vulnhunter.governance identity list \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
}

IDENTITIES="$(identity_listing)"
APPROVER_LINE="$(awk -v id="$APPROVER_ID" '$1 == id {print; exit}' <<<"$IDENTITIES")"
if [[ -n "$APPROVER_LINE" ]]; then
  if [[ "$APPROVER_LINE" != *"campaign_admin"* ]]; then
    printf 'Existing approver identity %s is not a campaign administrator.\n' \
      "$APPROVER_ID" >&2
    exit 2
  fi
  printf 'Approver governance identity already exists: %s\n' "$APPROVER_ID"
elif grep -Fq "No governance identities found." <<<"$IDENTITIES"; then
  python -m vulnhunter.governance identity bootstrap \
    --reviewer "$APPROVER_ID" \
    --display-name "$APPROVER_DISPLAY" \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
else
  EXISTING_ADMIN="$(awk '/roles=.*campaign_admin/ {print $1; exit}' <<<"$IDENTITIES")"
  if [[ -z "$EXISTING_ADMIN" ]]; then
    printf 'No active campaign administrator is available to create the phone approver.\n' >&2
    exit 2
  fi
  read -r -p "Existing campaign administrator [$EXISTING_ADMIN]: " ADMIN_ID
  ADMIN_ID="${ADMIN_ID:-$EXISTING_ADMIN}"
  printf '\nAuthenticate %s, then choose a separate secret for %s.\n' \
    "$ADMIN_ID" "$APPROVER_ID"
  python -m vulnhunter.governance identity create \
    --actor "$ADMIN_ID" \
    --reviewer "$APPROVER_ID" \
    --display-name "$APPROVER_DISPLAY" \
    --role campaign_admin \
    --governance-database "$VULNHUNTER_GOVERNANCE_DATABASE"
fi

IDENTITIES="$(identity_listing)"
OPERATOR_LINE="$(awk -v id="$OPERATOR_ID" '$1 == id {print; exit}' <<<"$IDENTITIES")"
if [[ -n "$OPERATOR_LINE" ]]; then
  if [[ "$OPERATOR_LINE" != *"reviewer"* ]]; then
    printf 'Existing operator identity %s does not have the reviewer role.\n' \
      "$OPERATOR_ID" >&2
    exit 2
  fi
  printf 'Operator governance identity already exists: %s\n' "$OPERATOR_ID"
else
  printf '\nAuthenticate the approver, then choose a separate secret for the operator.\n'
  python -m vulnhunter.governance identity create \
    --actor "$APPROVER_ID" \
    --reviewer "$OPERATOR_ID" \
    --display-name "$OPERATOR_DISPLAY" \
    --role reviewer \
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
    'import os; from django.contrib.auth import get_user_model; from vulnhunter.web.models import WebUserMapping; user=get_user_model().objects.get(username=os.environ["WEB_USERNAME"]); mapping=WebUserMapping.objects.get(user=user); mapping.governance_identity_id=os.environ["GOVERNANCE_ID"]; roles=list(mapping.product_roles); role=os.environ["PRODUCT_ROLE"]; mapping.product_roles=roles if role in roles else [*roles, role]; mapping.full_clean(); mapping.save(); user.is_staff=True; user.save(update_fields=["is_staff"]); print("Configured", user.username, "as", role)'
}

ensure_web_user "$APPROVER_USERNAME" "$APPROVER_ID" "system-administrator"
ensure_web_user "$OPERATOR_USERNAME" "$OPERATOR_ID" "campaign-operator"

USERS_FILE="$ROOT/.codespaces/phone-lab-users.env"
cat > "$USERS_FILE" <<EOF2
export VULNHUNTER_PHONE_LAB_APPROVER_ID="$APPROVER_ID"
export VULNHUNTER_PHONE_LAB_APPROVER_USERNAME="$APPROVER_USERNAME"
export VULNHUNTER_PHONE_LAB_OPERATOR_ID="$OPERATOR_ID"
export VULNHUNTER_PHONE_LAB_OPERATOR_USERNAME="$OPERATOR_USERNAME"
EOF2
chmod 600 "$USERS_FILE"

printf '\nPhone-lab setup is complete. Start everything with:\n'
printf '  bash .devcontainer/start-phone-lab.sh\n\n'
printf 'Create assessments as: %s\n' "$OPERATOR_USERNAME"
printf 'Approve exact plans as: %s\n' "$APPROVER_USERNAME"
