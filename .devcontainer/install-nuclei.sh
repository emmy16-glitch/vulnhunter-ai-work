#!/usr/bin/env bash
set -euo pipefail

NUCLEI_VERSION="3.8.0"
INSTALL_ROOT="${VULNHUNTER_NUCLEI_INSTALL_ROOT:-$PWD/.codespaces/tools/nuclei-v${NUCLEI_VERSION}}"
BIN_DIR="$INSTALL_ROOT/bin"
BIN_PATH="$BIN_DIR/nuclei"
PROVENANCE_PATH="$INSTALL_ROOT/provenance.json"

case "$(uname -m)" in
  x86_64|amd64) RELEASE_ARCH="amd64" ;;
  aarch64|arm64) RELEASE_ARCH="arm64" ;;
  *)
    printf 'Unsupported Codespaces architecture for the reviewed Nuclei binary: %s\n' \
      "$(uname -m)" >&2
    exit 2
    ;;
esac

verify_exact_version() {
  local output="$1"
  VERSION_OUTPUT="$output" python - <<'PY'
import os
import re

expected = "3.8.0"
pattern = re.compile(r"(?<![0-9A-Za-z.+-])v?(\d+\.\d+\.\d+)(?![0-9A-Za-z.+-])")
raise SystemExit(0 if expected in pattern.findall(os.environ["VERSION_OUTPUT"]) else 1)
PY
}

if [[ -x "$BIN_PATH" ]]; then
  VERSION_OUTPUT="$($BIN_PATH -version 2>&1 || true)"
  if verify_exact_version "$VERSION_OUTPUT"; then
    printf 'Pinned Nuclei is already installed: %s\n' "$BIN_PATH"
    exit 0
  fi
fi

for command in curl unzip sha256sum python; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'Required installer command is missing: %s\n' "$command" >&2
    exit 2
  }
done

ARCHIVE="nuclei_${NUCLEI_VERSION}_linux_${RELEASE_ARCH}.zip"
BASE_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl --fail --location --retry 4 --retry-delay 2 \
  --output "$TMP_DIR/$ARCHIVE" "$BASE_URL/$ARCHIVE"
curl --fail --location --retry 4 --retry-delay 2 \
  --output "$TMP_DIR/nuclei_checksums.txt" \
  "$BASE_URL/nuclei_${NUCLEI_VERSION}_checksums.txt"

(
  cd "$TMP_DIR"
  grep -E "[[:space:]]${ARCHIVE}$" nuclei_checksums.txt > selected-checksum.txt
  [[ -s selected-checksum.txt ]] || {
    printf 'Official checksum list does not contain %s\n' "$ARCHIVE" >&2
    exit 2
  }
  sha256sum --check selected-checksum.txt
)

rm -rf "$INSTALL_ROOT"
mkdir -p "$BIN_DIR"
unzip -q "$TMP_DIR/$ARCHIVE" nuclei -d "$BIN_DIR"
chmod 0555 "$BIN_PATH"

VERSION_OUTPUT="$($BIN_PATH -version 2>&1)"
if ! verify_exact_version "$VERSION_OUTPUT"; then
  printf 'Installed Nuclei did not report the exact reviewed version v3.8.0.\n%s\n' \
    "$VERSION_OUTPUT" >&2
  exit 2
fi

ARCHIVE_SHA256="$(sha256sum "$TMP_DIR/$ARCHIVE" | awk '{print $1}')"
NUCLEI_BINARY="$BIN_PATH" ARCHIVE_NAME="$ARCHIVE" ARCHIVE_SHA256="$ARCHIVE_SHA256" \
  VERSION_OUTPUT="$VERSION_OUTPUT" python - <<'PY' > "$PROVENANCE_PATH"
import json
import os
from datetime import UTC, datetime

print(
    json.dumps(
        {
            "schema_version": "1.0",
            "installed_at": datetime.now(UTC).isoformat(),
            "source": "official-projectdiscovery-github-release",
            "release": "v3.8.0",
            "archive": os.environ["ARCHIVE_NAME"],
            "archive_sha256": os.environ["ARCHIVE_SHA256"],
            "binary": os.environ["NUCLEI_BINARY"],
            "version_output": os.environ["VERSION_OUTPUT"][:1000],
        },
        indent=2,
        sort_keys=True,
    )
)
PY
chmod 0444 "$PROVENANCE_PATH"
printf 'Installed and verified Nuclei v3.8.0 at %s\n' "$BIN_PATH"
