#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/.codespaces/vulnhunter.env"
if [[ -f "$ROOT/.codespaces/vulnhunter-user.env" ]]; then
  source "$ROOT/.codespaces/vulnhunter-user.env"
fi

: "${VULNHUNTER_USER_ID:?Run bash .devcontainer/first-run.sh first.}"
: "${VULNHUNTER_USERNAME:?Run bash .devcontainer/first-run.sh first.}"
: "${VULNHUNTER_APPROVER_USERNAME:?Run bash .devcontainer/first-run.sh again to create the independent approver.}"

export VULNHUNTER_GROQ_ENABLED="${VULNHUNTER_GROQ_ENABLED:-true}"
export VULNHUNTER_GROQ_API_KEY_FILE="${VULNHUNTER_GROQ_API_KEY_FILE:-$ROOT/.codespaces/groq-api-key}"
export VULNHUNTER_INTELLIGENCE_ENABLED="${VULNHUNTER_INTELLIGENCE_ENABLED:-true}"

LAB_PORT="${VULNHUNTER_LAB_TARGET_PORT:-${VULNHUNTER_PHONE_LAB_TARGET_PORT:-8010}}"
LAB_ADDRESS="$(python scripts/phone_lab_target.py --print-address)"
LAB_URL="http://${LAB_ADDRESS}:${LAB_PORT}/"
LOG_ROOT="$ROOT/.codespaces/runtime"
mkdir -p "$LOG_ROOT"

TARGET_PID=""
WORKER_PID=""
INTELLIGENCE_PID=""
cleanup() {
  set +e
  if [[ -n "$INTELLIGENCE_PID" ]]; then
    kill "$INTELLIGENCE_PID" 2>/dev/null
    wait "$INTELLIGENCE_PID" 2>/dev/null
  fi
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
python manage.py vh_prepare_private_lab \
  --target-url "$LAB_URL" \
  --account-id "$VULNHUNTER_USER_ID"

python manage.py vh_run_nuclei_worker --watch --poll-seconds 0.5 \
  >"$LOG_ROOT/worker.log" 2>&1 &
WORKER_PID=$!

GROQ_STATE="deterministic fallback"
INTELLIGENCE_STATE="disabled"
if [[ "$VULNHUNTER_GROQ_ENABLED" == "true" && -s "$VULNHUNTER_GROQ_API_KEY_FILE" ]]; then
  GROQ_STATE="configured advisory"
  if [[ "$VULNHUNTER_INTELLIGENCE_ENABLED" == "true" ]]; then
    python manage.py vh_run_intelligence_worker --watch --poll-seconds 0.5 \
      >"$LOG_ROOT/intelligence.log" 2>&1 &
    INTELLIGENCE_PID=$!
    INTELLIGENCE_STATE="analyst → critic → synthesizer ready"
  fi
fi

cat <<MESSAGE

VulnHunter is ready.
Controlled target: $LAB_URL
Operator username: $VULNHUNTER_USERNAME
Independent approver username: $VULNHUNTER_APPROVER_USERNAME
Groq: $GROQ_STATE
Reasoning: $INTELLIGENCE_STATE
Nuclei: pinned passive worker ready

Open the private port-8002 Codespaces URL and sign in as the operator to create
and monitor an assessment. When the plan pauses, sign in separately as the
approver and use the Approval Centre. The requester cannot approve its own plan.

MESSAGE

exec python manage.py runserver 0.0.0.0:8002
