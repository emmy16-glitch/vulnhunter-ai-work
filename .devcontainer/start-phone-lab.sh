#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/.codespaces/vulnhunter.env"
[[ -f "$ROOT/.codespaces/phone-lab-users.env" ]] && source "$ROOT/.codespaces/phone-lab-users.env"

: "${VULNHUNTER_PHONE_LAB_OPERATOR_ID:?Run bash .devcontainer/first-run.sh first.}"
: "${VULNHUNTER_PHONE_LAB_APPROVER_ID:?Run bash .devcontainer/first-run.sh first.}"

LAB_PORT="${VULNHUNTER_PHONE_LAB_TARGET_PORT:-8010}"
LAB_ADDRESS="$(python scripts/phone_lab_target.py --print-address)"
LAB_URL="http://${LAB_ADDRESS}:${LAB_PORT}/"
LOG_ROOT="$ROOT/.codespaces/phone-lab"
mkdir -p "$LOG_ROOT"

TARGET_PID=""
WORKER_PID=""
cleanup() {
  set +e
  if [[ -n "$WORKER_PID" ]]; then
    kill "$WORKER_PID" 2>/dev/null
    wait "$WORKER_PID" 2>/dev/null
  fi
  if [[ -n "$TARGET_PID" ]]; then
    kill "$TARGET_PID" 2>/dev/null
    wait "$TARGET_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

python scripts/phone_lab_target.py --host "$LAB_ADDRESS" --port "$LAB_PORT" \
  >"$LOG_ROOT/target.log" 2>&1 &
TARGET_PID=$!
for _ in $(seq 1 40); do
  if curl --fail --silent "$LAB_URL/healthz" >/dev/null; then
    break
  fi
  sleep 0.25
done
curl --fail --silent "$LAB_URL/healthz" >/dev/null || {
  cat "$LOG_ROOT/target.log" >&2
  exit 1
}

python scripts/nuclei_readiness.py \
  --executable "$VULNHUNTER_NUCLEI_EXECUTABLE" \
  --manifest "$VULNHUNTER_NUCLEI_TEMPLATE_MANIFEST" \
  --template-root "$VULNHUNTER_NUCLEI_TEMPLATE_ROOT" \
  --execution-enabled \
  --output "$VULNHUNTER_NUCLEI_READINESS_REPORT" \
  --require-ready

python manage.py migrate --noinput
python manage.py vh_prepare_phone_lab \
  --target-url "$LAB_URL" \
  --owner "$VULNHUNTER_PHONE_LAB_OPERATOR_ID" \
  --approved-by "$VULNHUNTER_PHONE_LAB_APPROVER_ID"

python manage.py vh_run_nuclei_worker --watch --poll-seconds 0.5 \
  >"$LOG_ROOT/worker.log" 2>&1 &
WORKER_PID=$!

cat <<MESSAGE

VulnHunter phone-only private lab is ready.
Target: $LAB_URL
Operator login: ${VULNHUNTER_PHONE_LAB_OPERATOR_USERNAME:-configured operator}
Approver login: ${VULNHUNTER_PHONE_LAB_APPROVER_USERNAME:-configured approver}

1. Open the private port-8002 Codespaces URL in your phone browser.
2. Sign in as the operator and create a passive assessment for the displayed target.
3. Sign out, sign in as the approver, and approve the exact plan digest.
4. The separate worker process will claim the signed job and store real evidence.

MESSAGE

exec python manage.py runserver 0.0.0.0:8002
