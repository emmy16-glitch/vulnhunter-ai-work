#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="opensecurity/mobile-security-framework-mobsf:v4.4.6"
CONTAINER="vulnhunter-mobsf"
VOLUME="vulnhunter-mobsf-data"
PORT="${VULNHUNTER_MOBSF_PORT:-8008}"
STATE_DIR="$ROOT/.codespaces/runtime"
IMAGE_RECEIPT="$STATE_DIR/mobsf-image.json"

log() {
  printf '[mobsf] %s\n' "$*"
}

if ! command -v docker >/dev/null 2>&1; then
  log 'Docker is unavailable. Rebuild the Codespace with the Docker feature.' >&2
  exit 2
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1024 || PORT > 65535 )); then
  log 'VULNHUNTER_MOBSF_PORT must be an unprivileged TCP port.' >&2
  exit 2
fi

mkdir -p "$STATE_DIR"
chmod 700 "$ROOT/.codespaces" "$STATE_DIR" 2>/dev/null || true

log "Pulling reviewed MobSF image $IMAGE."
docker pull "$IMAGE" >/dev/null
IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
REPO_DIGEST="$(docker image inspect --format '{{join .RepoDigests "\n"}}' "$IMAGE" | head -n 1)"
if [[ -z "$IMAGE_ID" || -z "$REPO_DIGEST" || "$REPO_DIGEST" != *@sha256:* ]]; then
  log 'MobSF image did not produce a repository digest.' >&2
  exit 2
fi

if docker container inspect "$CONTAINER" >/dev/null 2>&1; then
  CURRENT_IMAGE="$(docker container inspect --format '{{.Config.Image}}' "$CONTAINER")"
  if [[ "$CURRENT_IMAGE" != "$IMAGE" ]]; then
    log 'Existing MobSF container uses a different image; refusing to reuse it.' >&2
    exit 2
  fi
  docker start "$CONTAINER" >/dev/null
else
  docker volume create "$VOLUME" >/dev/null
  docker run -d \
    --name "$CONTAINER" \
    --restart unless-stopped \
    --publish "127.0.0.1:${PORT}:8000" \
    --volume "$VOLUME:/home/mobsf/.MobSF" \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=2g \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 1024 \
    "$IMAGE" >/dev/null
fi

IMAGE_ID="$IMAGE_ID" REPO_DIGEST="$REPO_DIGEST" IMAGE_RECEIPT="$IMAGE_RECEIPT" python - <<'PY'
import json
import os
from datetime import UTC, datetime
from pathlib import Path

path = Path(os.environ["IMAGE_RECEIPT"])
payload = {
    "schema_version": "1.0",
    "image_id": os.environ["IMAGE_ID"],
    "repo_digest": os.environ["REPO_DIGEST"],
    "verified_at": datetime.now(UTC).isoformat(),
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

log 'Waiting for the loopback-only service to answer.'
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error --max-time 3 "http://127.0.0.1:${PORT}/" >/dev/null 2>&1; then
    log "MobSF is ready on loopback port ${PORT}."
    log "Image digest: ${REPO_DIGEST}"
    exit 0
  fi
  sleep 2
done

log 'MobSF did not become ready before the timeout.' >&2
docker logs --tail 80 "$CONTAINER" >&2 || true
exit 2
