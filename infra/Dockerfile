# One image for api, portal, worker and migrations. Build from the repo root:
#   docker build -f infra/Dockerfile -t community-cti .
FROM node:22.11.0-bookworm-slim AS build
WORKDIR /app
RUN npm install -g pnpm@9.12.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps ./apps
COPY packages ./packages
RUN pnpm install --frozen-lockfile
RUN pnpm build && pnpm prune --prod --ignore-scripts

FROM node:22.11.0-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /app /app
COPY --chown=node:node db ./db
COPY --chown=node:node docs/SOURCES.md ./docs/SOURCES.md
RUN mkdir -p /data/raw && chown -R node:node /data
USER node
CMD ["node", "apps/api/dist/index.js"]
