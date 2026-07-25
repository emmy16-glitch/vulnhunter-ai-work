#!/usr/bin/env bash
set -u

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

log 'Refreshing Debian package metadata for read-only Android tooling.'
if ! sudo apt-get update; then
  log 'APT metadata refresh failed; continuing with tools already present.'
fi

for package in default-jre-headless apksigner apktool aapt yara radare2 adb; do
  install_apt_package "$package"
done

log 'Installing Python-only APK metadata analyzers into the Codespace environment.'
if ! python -m pip install 'apkid>=2,<4' 'androguard>=4,<5'; then
  log 'Python mobile analyzers could not be installed; their adapters will remain gated.'
fi

log 'Mobile tool installation attempt complete. Worker policy discovery decides what is usable.'
