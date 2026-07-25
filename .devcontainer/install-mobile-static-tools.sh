#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_ROOT="$ROOT/.codespaces/tools/mobile-releases"
PYTHON_TOOLS_ROOT="$ROOT/.codespaces/tools/mobile-python"

log() {
  printf '[mobile-tools] %s\n' "$*"
}

install_apt_package() {
  local package="$1"
  if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
    log "$package is already installed."
    return 0
  fi
  if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package"; then
    log "installed $package."
  else
    log "$package is unavailable for this image; its adapter will remain gated."
  fi
}

log 'Refreshing Debian metadata for Android tooling and release extraction.'
if ! sudo apt-get update; then
  log 'APT metadata refresh failed; continuing with tools already present.'
fi

for package in apksigner apktool aapt adb yara file unzip dpkg-dev python3-venv; do
  install_apt_package "$package"
done

mkdir -p "$HOME/.local/bin" "$TOOLS_ROOT" "$(dirname "$PYTHON_TOOLS_ROOT")"
chmod 700 "$HOME/.local" "$HOME/.local/bin" "$TOOLS_ROOT" 2>/dev/null || true

log 'Installing pinned Python APK analyzers in a dedicated worker environment.'
if [[ ! -x "$PYTHON_TOOLS_ROOT/bin/python" ]]; then
  rm -rf "$PYTHON_TOOLS_ROOT"
  if ! python -m venv --copies "$PYTHON_TOOLS_ROOT"; then
    log 'The dedicated Python worker environment could not be created; Python adapters remain gated.'
  fi
fi

if [[ -x "$PYTHON_TOOLS_ROOT/bin/python" ]]; then
  chmod 700 "$PYTHON_TOOLS_ROOT" 2>/dev/null || true
  if ! "$PYTHON_TOOLS_ROOT/bin/python" -m pip install --upgrade pip setuptools wheel; then
    log 'The dedicated mobile worker pip bootstrap failed; existing packages will be checked.'
  fi
  if ! "$PYTHON_TOOLS_ROOT/bin/python" -m pip install \
    'apkid>=2,<4' \
    'androguard==4.1.4' \
    'yara-python==4.5.4' \
    'frida==17.10.1' \
    'frida-tools==14.10.4'; then
    log 'One or more Python mobile tools failed to install; affected adapters remain gated.'
  fi
fi

log 'Installing digest-verified JADX, Radare2 and Ghidra release assets.'
if ! python "$ROOT/scripts/install_mobile_release_tools.py" --root "$TOOLS_ROOT"; then
  log 'One or more release tools failed verification or installation; discovery keeps them gated.'
fi

log 'Mobile tool installation attempt complete. Worker policy discovery decides what is usable.'
