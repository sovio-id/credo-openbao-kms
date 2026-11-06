#!/bin/sh
# Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Wait for OpenBao to be initialized and unsealed, then start the Credo agent.

set -eu

if [ -z "${OPENBAO_TOKEN:-}" ] && [ -n "${OPENBAO_TOKEN_FILE:-}" ]; then
  echo "Waiting for OpenBao token at $OPENBAO_TOKEN_FILE"

  i=0
  until [ -s "$OPENBAO_TOKEN_FILE" ]; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      echo "Timed out waiting for $OPENBAO_TOKEN_FILE" >&2
      exit 1
    fi
    sleep 1
  done

  OPENBAO_TOKEN="$(cat "$OPENBAO_TOKEN_FILE")"
  export OPENBAO_TOKEN
fi

# Wait until the server is initialized and unsealed. The health endpoint returns
# 503 while sealed and 200 when active.
if [ -n "${OPENBAO_ADDR:-}" ]; then
  echo "Waiting for OpenBao at $OPENBAO_ADDR"

  i=0
  until node -e "fetch(process.env.OPENBAO_ADDR + '/v1/sys/health').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      echo "Timed out waiting for OpenBao at $OPENBAO_ADDR" >&2
      exit 1
    fi
    sleep 1
  done
fi

exec node_modules/.bin/tsx scripts/dev-agent.ts
