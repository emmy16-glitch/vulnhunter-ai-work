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

export VULNHUNTER_GROQ_ENABLED="${VULNHUNTER_GROQ_ENABLED:-true}"
export VULNHUNTER_GROQ_API_KEY_FILE="${VULNHUNTER_GROQ_API_KEY_FILE:-$ROOT/.codespaces/groq-api-key}"
export VULNHUNTER_INTELLIGENCE_ENABLED="${VULNHUNTER_INTELLIGENCE_ENABLED:-true}"
export VULNHUNTER_SOURCE_HUNT_ROOTS="${VULNHUNTER_SOURCE_HUNT_ROOTS:-/workspaces}"
export VULNHUNTER_SOURCE_HUNT_JOB_ROOT="${VULNHUNTER_SOURCE_HUNT_JOB_ROOT:-$ROOT/.local/source-hunt-jobs}"
export VULNHUNTER_SOURCE_HUNT_REPORT_ROOT="${VULNHUNTER_SOURCE_HUNT_REPORT_ROOT:-$ROOT/.local/source-hunt-reports}"
export VULNHUNTER_MOBILE_MAX_APK_BYTES="${VULNHUNTER_MOBILE_MAX_APK_BYTES:-1000000000}"
export VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES="${VULNHUNTER_MOBILE_UPLOAD_CHUNK_BYTES:-8388608}"

LAB_PORT="${VULNHUNTER_LAB_TARGET_PORT:-${VULNHUNTER_PHONE_LAB_TARGET_PORT:-8010}}"
LAB_ADDRESS="$(python scripts/phone_lab_target.py --print-address)"
LAB_URL="http://${LAB_ADDRESS}:${LAB_PORT}/"
LOG_ROOT="$ROOT/.codespaces/runtime"
MOBILE_WORKSPACE="${VULNHUNTER_MOBILE_STATIC_WORKSPACE:-$ROOT/.local/mobile-static-workspace}"
mkdir -p "$LOG_ROOT"

TARGET_PID=""
WORKER_PID=""
MOBILE_WORKER_PID=""
EXTENSION_WORKER_PID=""
INTELLIGENCE_PID=""
SOURCE_HUNT_PID=""
cleanup() {
  set +e
  if [[ -n "$SOURCE_HUNT_PID" ]]; then
    kill "$SOURCE_HUNT_PID" 2>/dev/null
    wait "$SOURCE_HUNT_PID" 2>/dev/null
  fi
  if [[ -n "$INTELLIGENCE_PID" ]]; then
    kill "$INTELLIGENCE_PID" 2>/dev/null
    wait "$INTELLIGENCE_PID" 2>/dev/null
  fi
  if [[ -n "$EXTENSION_WORKER_PID" ]]; then
    kill "$EXTENSION_WORKER_PID" 2>/dev/null
    wait "$EXTENSION_WORKER_PID" 2>/dev/null
  fi
  if [[ -n "$MOBILE_WORKER_PID" ]]; then
    kill "$MOBILE_WORKER_PID" 2>/dev/null
    wait "$MOBILE_WORKER_PID" 2>/dev/null
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

python scripts/prepare_mobile_static_worker.py \
  --policy "$VULNHUNTER_MOBILE_STATIC_WORKER_POLICY" \
  --workspace "$MOBILE_WORKSPACE" \
  --worker-id codespaces-mobile-static-worker \
  >"$LOG_ROOT/mobile-policy.log" 2>&1
VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED="$(python - <<'PY'
import json
import os
from pathlib import Path

payload = json.loads(
    Path(os.environ["VULNHUNTER_MOBILE_STATIC_WORKER_POLICY"]).read_text(encoding="utf-8")
)
print("true" if payload.get("enabled") is True else "false")
PY
)"
export VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED

MOBILE_STATE="gated; no verified static APK tools were discovered"
if [[ "$VULNHUNTER_MOBILE_STATIC_ENQUEUE_ENABLED" == "true" ]]; then
  python manage.py vh_run_mobile_static_worker --watch --poll-seconds 0.5 \
    >"$LOG_ROOT/mobile-static-worker.log" 2>&1 &
  MOBILE_WORKER_PID=$!
  sleep 0.2
  if kill -0 "$MOBILE_WORKER_PID" 2>/dev/null; then
    MOBILE_STATE="automatic isolated static/native worker ready"
  else
    MOBILE_STATE="failed closed; see .codespaces/runtime/mobile-static-worker.log"
    MOBILE_WORKER_PID=""
  fi
fi

MOBSF_STATE="gated"
if [[ -s "${VULNHUNTER_MOBSF_POLICY:-}" && -s "${VULNHUNTER_MOBSF_API_KEY_FILE:-}" ]]; then
  if bash scripts/start-mobsf-private.sh >"$LOG_ROOT/mobsf.log" 2>&1; then
    MOBSF_STATE="private loopback service ready"
  else
    MOBSF_STATE="failed closed; see .codespaces/runtime/mobsf.log"
  fi
fi

RUNTIME_STATE="gated; no disposable emulator registered"
if [[ -s "${VULNHUNTER_MOBILE_RUNTIME_POLICY:-}" ]]; then
  RUNTIME_STATE="$(python - <<'PY'
import json
import os
from datetime import UTC, datetime
from pathlib import Path

try:
    payload = json.loads(
        Path(os.environ["VULNHUNTER_MOBILE_RUNTIME_POLICY"]).read_text(encoding="utf-8")
    )
    expires_at = datetime.fromisoformat(str(payload["expires_at"])).astimezone(UTC)
    if payload.get("enabled") is True and expires_at > datetime.now(UTC):
        print(f"registered as {payload.get('runtime_id', 'unknown')}; exact approval required")
    else:
        print("gated; runtime registration is disabled or expired")
except (OSError, KeyError, TypeError, ValueError):
    print("gated; runtime registration failed closed")
PY
)"
fi

EXTENSION_STATE="gated"
if [[ -s "${VULNHUNTER_MOBILE_EXTENSION_SIGNING_KEY_FILE:-}" && \
      -s "${VULNHUNTER_MOBILE_RUNTIME_APPROVAL_KEY_FILE:-}" ]]; then
  python manage.py vh_run_mobile_extension_worker --watch --poll-seconds 0.5 \
    >"$LOG_ROOT/mobile-extension-worker.log" 2>&1 &
  EXTENSION_WORKER_PID=$!
  EXTENSION_STATE="signed approval queue ready"
fi

GROQ_STATE="deterministic fallback"
INTELLIGENCE_STATE="disabled"
SOURCE_HUNT_STATE="disabled"
if [[ "$VULNHUNTER_GROQ_ENABLED" == "true" && -s "$VULNHUNTER_GROQ_API_KEY_FILE" ]]; then
  GROQ_STATE="configured advisory"
  python manage.py vh_run_source_hunt_worker --poll-seconds 0.5 \
    >"$LOG_ROOT/source-hunt-worker.log" 2>&1 &
  SOURCE_HUNT_PID=$!
  SOURCE_HUNT_STATE="exact-approval queue ready"
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
Login username: $VULNHUNTER_USERNAME
Groq: $GROQ_STATE
Reasoning: $INTELLIGENCE_STATE
Source Hunt: $SOURCE_HUNT_STATE
Nuclei: pinned passive worker ready
APK upload limit: $VULNHUNTER_MOBILE_MAX_APK_BYTES bytes via bounded chunks
Mobile APK: $MOBILE_STATE
MobSF: $MOBSF_STATE
ADB/Frida: $RUNTIME_STATE
Extension worker: $EXTENSION_STATE

Open the private port-8002 Codespaces URL and sign in once. Use the plus button to
attach an APK or request an authorised web scan. Source repositories enter the exact
Source Hunt queue; dynamic APK execution remains separately approved.

MESSAGE

exec python manage.py runserver 0.0.0.0:8002
