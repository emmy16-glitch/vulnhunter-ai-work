#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '[codex] %s\n' "$*"
}

if ! command -v node >/dev/null 2>&1; then
  log 'Node.js is unavailable. Rebuild the Codespace so the devcontainer Node feature is applied.'
  exit 2
fi

if ! command -v npm >/dev/null 2>&1; then
  log 'npm is unavailable even though Node.js is installed.'
  exit 2
fi

if command -v codex >/dev/null 2>&1; then
  if codex --version >/dev/null 2>&1; then
    log "Codex is already installed: $(codex --version)"
    exit 0
  fi
  log 'An existing Codex executable is unhealthy; reinstalling it.'
fi

log 'Installing the official OpenAI Codex CLI from npm.'
npm install --global @openai/codex@latest

if ! command -v codex >/dev/null 2>&1; then
  log 'Codex installed, but its executable is not available on PATH.'
  exit 2
fi

log "Installed $(codex --version)"
log "Run 'codex' and choose Continue with ChatGPT to authenticate."
