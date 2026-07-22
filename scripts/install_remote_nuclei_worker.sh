#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  bash scripts/install_remote_nuclei_worker.sh \
    --host-policy /absolute/path/remote_nuclei_host.json \
    --public-key /absolute/path/vulnhunter_guest_to_host_ed25519.pub \
    [--authorized-keys ~/.ssh/authorized_keys] [--dry-run]

Installs the restricted host-side forced command without sudo and appends one
owner-restricted SSH key entry. Existing authorized_keys content is preserved
and backed up before modification.
EOF
}

HOST_POLICY=""
PUBLIC_KEY=""
AUTHORIZED_KEYS="${HOME}/.ssh/authorized_keys"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-policy)
      HOST_POLICY="${2:-}"
      shift 2
      ;;
    --public-key)
      PUBLIC_KEY="${2:-}"
      shift 2
      ;;
    --authorized-keys)
      AUTHORIZED_KEYS="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "$HOST_POLICY" && -n "$PUBLIC_KEY" ]] || {
  usage >&2
  exit 2
}

for value in "$HOST_POLICY" "$PUBLIC_KEY" "$AUTHORIZED_KEYS" "$HOME"; do
  [[ "$value" != *$'\n'* && "$value" != *'"'* ]] || {
    echo "Paths must not contain quotes or newlines." >&2
    exit 2
  }
done

HOST_POLICY="$(realpath -e "$HOST_POLICY")"
PUBLIC_KEY="$(realpath -e "$PUBLIC_KEY")"
SCRIPT_SOURCE="$(realpath -e "$(dirname "$0")/remote_nuclei_forced_command.py")"
INSTALL_ROOT="${HOME}/.local/libexec"
CONFIG_ROOT="${HOME}/.config/vulnhunter"
SCRIPT_DEST="${INSTALL_ROOT}/vulnhunter-remote-nuclei-worker"
POLICY_DEST="${CONFIG_ROOT}/remote_nuclei_host.json"
MARKER="vulnhunter-remote-nuclei-worker"

python3 - "$HOST_POLICY" <<'PY'
import json
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
metadata = path.stat()
if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
    raise SystemExit("host policy must be a regular non-symlink file")
if stat.S_IMODE(metadata.st_mode) & 0o022:
    raise SystemExit("host policy must not be group or world writable")
payload = json.loads(path.read_text(encoding="utf-8"))
if payload.get("schema_version") != "1.0" or payload.get("enabled") is not True:
    raise SystemExit("host policy must use schema 1.0 and enabled=true")
for key in ("nuclei_executable", "template_path", "replay_root"):
    value = Path(str(payload.get(key, ""))).expanduser()
    if not value.is_absolute():
        raise SystemExit(f"{key} must be absolute")
print(payload.get("worker_id", "remote-worker"))
PY

PUBLIC_KEY_LINE="$(tr -d '\r\n' < "$PUBLIC_KEY")"
[[ "$PUBLIC_KEY_LINE" == ssh-ed25519\ * ]] || {
  echo "A dedicated ssh-ed25519 public key is required." >&2
  exit 2
}

FORCED_COMMAND="${SCRIPT_DEST} --policy ${POLICY_DEST}"
RESTRICTED_ENTRY="command=\"${FORCED_COMMAND}\",no-agent-forwarding,no-port-forwarding,no-pty,no-user-rc,no-X11-forwarding ${PUBLIC_KEY_LINE} ${MARKER}"

if [[ "$DRY_RUN" -eq 1 ]]; then
  printf 'Would install script: %s\n' "$SCRIPT_DEST"
  printf 'Would install policy: %s\n' "$POLICY_DEST"
  printf 'Would update: %s\n' "$AUTHORIZED_KEYS"
  printf 'Forced command: %s\n' "$FORCED_COMMAND"
  exit 0
fi

umask 077
mkdir -p "$INSTALL_ROOT" "$CONFIG_ROOT" "$(dirname "$AUTHORIZED_KEYS")"
install -m 0700 "$SCRIPT_SOURCE" "$SCRIPT_DEST"
install -m 0600 "$HOST_POLICY" "$POLICY_DEST"
touch "$AUTHORIZED_KEYS"
chmod 0600 "$AUTHORIZED_KEYS"
BACKUP="${AUTHORIZED_KEYS}.vulnhunter-backup-$(date -u +%Y%m%dT%H%M%SZ)"
cp -p "$AUTHORIZED_KEYS" "$BACKUP"

TEMP_FILE="$(mktemp "${AUTHORIZED_KEYS}.tmp.XXXXXX")"
trap 'rm -f "$TEMP_FILE"' EXIT
awk -v marker="$MARKER" 'index($0, marker) == 0 { print }' "$AUTHORIZED_KEYS" > "$TEMP_FILE"
printf '%s\n' "$RESTRICTED_ENTRY" >> "$TEMP_FILE"
chmod 0600 "$TEMP_FILE"
mv "$TEMP_FILE" "$AUTHORIZED_KEYS"
trap - EXIT

printf 'Installed restricted worker: %s\n' "$SCRIPT_DEST"
printf 'Installed owner-private policy: %s\n' "$POLICY_DEST"
printf 'Updated authorized_keys with backup: %s\n' "$BACKUP"
printf 'No sudo command was used.\n'
