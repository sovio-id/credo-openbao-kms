# Copyright 2026 AyanWorks Technology Solutions Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Local development image for scripts/dev-agent.ts.
#
# Credo, Drizzle and the SQLite driver are devDependencies in this repository,
# so the runtime image keeps the full dependency tree and runs the TypeScript
# entry point with tsx. That is intentional for a development compose stack.

FROM node:22-bookworm-slim AS build

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts

RUN npx tsc -p tsconfig.build.json

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=development
WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/build ./build
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY scripts ./scripts
COPY docker/agent/entrypoint.sh /usr/local/bin/agent-entrypoint.sh

RUN chmod +x /usr/local/bin/agent-entrypoint.sh \
  && mkdir -p /app/data \
  && chown -R node:node /app

USER node

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/agent-entrypoint.sh"]
