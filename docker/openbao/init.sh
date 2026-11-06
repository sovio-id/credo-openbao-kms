#!/bin/sh
# Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Initialize a non-dev OpenBao server, unseal it, enable the mounts this
# project needs, and keep it unsealed across restarts.
#
# This is a LOCAL DEVELOPMENT helper. It uses a single unseal share and writes
# the unseal key and root token to the openbao-init volume so the agent can read
# the token. Never use this in production.

set -eu

BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
export BAO_ADDR

INIT_DIR="${INIT_DIR:-/openbao-init}"
UNSEAL_KEY_FILE="$INIT_DIR/unseal.key"
ROOT_TOKEN_FILE="$INIT_DIR/root-token"
CONFIGURED_FILE="$INIT_DIR/configured"

log() {
  echo "[openbao-init] $*"
}

# `bao status` exits non-zero while the server is uninitialized or sealed, but
# still prints the status table, so test the output rather than the exit code.
wait_for_server() {
  until bao status 2>/dev/null | grep -q '^Initialized'; do
    sleep 1
  done
}

is_initialized() {
  bao status 2>/dev/null | awk '/^Initialized/ { print $2 }' | grep -q '^true$'
}

is_sealed() {
  bao status 2>/dev/null | awk '/^Sealed/ { print $2 }' | grep -q '^true$'
}

unseal() {
  log "Unsealing OpenBao"
  bao operator unseal "$1" >/dev/null
}

configure() {
  token="$1"

  log "Enabling transit and KV v2 mounts"
  BAO_TOKEN="$token" bao secrets enable -path=transit transit 2>/dev/null || true
  BAO_TOKEN="$token" bao secrets enable -path=secret kv-v2 2>/dev/null || true

  touch "$CONFIGURED_FILE"
  log "OpenBao is ready at $BAO_ADDR"
}

mkdir -p "$INIT_DIR"
# The agent container runs as an unprivileged user and must be able to traverse
# this directory to read the root token. The unseal key stays mode 0600.
chmod 755 "$INIT_DIR" 2>/dev/null || true

wait_for_server

if [ -s "$UNSEAL_KEY_FILE" ]; then
  UNSEAL_KEY="$(cat "$UNSEAL_KEY_FILE")"
  ROOT_TOKEN="$(cat "$ROOT_TOKEN_FILE")"
else
  if is_initialized; then
    log "OpenBao is already initialized but no unseal key was saved."
    log "Remove the openbao-data volume to start over."
    exit 1
  fi

  log "Initializing OpenBao"
  INIT_OUTPUT="$(bao operator init -key-shares=1 -key-threshold=1)"
  UNSEAL_KEY="$(printf '%s\n' "$INIT_OUTPUT" | awk -F': ' '/Unseal Key 1:/ { print $2 }')"
  ROOT_TOKEN="$(printf '%s\n' "$INIT_OUTPUT" | awk -F': ' '/Initial Root Token:/ { print $2 }')"

  if [ -z "$UNSEAL_KEY" ] || [ -z "$ROOT_TOKEN" ]; then
    log "Could not parse the output of 'bao operator init'."
    exit 1
  fi

  printf '%s' "$UNSEAL_KEY" >"$UNSEAL_KEY_FILE"
  printf '%s' "$ROOT_TOKEN" >"$ROOT_TOKEN_FILE"
  chmod 600 "$UNSEAL_KEY_FILE" "$ROOT_TOKEN_FILE"
fi

if is_sealed; then
  unseal "$UNSEAL_KEY"
fi

if [ ! -f "$CONFIGURED_FILE" ]; then
  configure "$ROOT_TOKEN"
fi

# The agent waits for the token file, so only publish it once the mounts exist.
printf '%s' "$ROOT_TOKEN" >"$ROOT_TOKEN_FILE"
# The dev agent container reads this file as an unprivileged user.
chmod 644 "$ROOT_TOKEN_FILE"

while true; do
  if bao status 2>/dev/null | grep -q '^Initialized' && is_sealed; then
    unseal "$UNSEAL_KEY" || true
  fi
  sleep 5
done
