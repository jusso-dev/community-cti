#!/usr/bin/env bash
# Deploy the homelab test stack. Run from the repo root on the workstation:
#   bash infra/homelab/deploy.sh
# Copies the source to homelab, creates .env once (mode 600, random secrets,
# never printed), builds the image on the host and starts the stack.
set -euo pipefail

HOST="${HOMELAB_HOST:-homelab}"
DIR="${HOMELAB_DIR:-apps/community-cti}"
PORTAL_URL="${PORTAL_BASE_URL:-http://192.168.1.19:3330}"
# Optional: limit which services start, e.g. SERVICES="api portal".
SERVICES="${SERVICES:-}"

ssh "$HOST" "mkdir -p $DIR/src"
rsync -az --delete \
  --exclude node_modules --exclude dist --exclude .git --exclude '.env*' --exclude data \
  ./ "$HOST:$DIR/src/"

ssh "$HOST" DIR="$DIR" PORTAL_URL="$PORTAL_URL" SERVICES="'$SERVICES'" 'bash -s' <<'REMOTE'
set -euo pipefail
cd "$HOME/$DIR"
cp src/infra/homelab/docker-compose.yml docker-compose.yml
if [ ! -f .env ]; then
  umask 077
  {
    echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
    echo "CTI_APP_PASSWORD=$(openssl rand -hex 24)"
    echo "FIELD_ENCRYPTION_KEY=$(openssl rand -hex 32)"
    echo "PORTAL_BASE_URL=$PORTAL_URL"
    echo "CTI_ENV=test"
    echo "TEST_APPROVED_SOURCES="
    echo "PAPERBOY_URL=http://192.168.1.19:3238"
    echo "PAPERBOY_API_KEY="
  } > .env
  echo "created .env"
fi
chmod 600 .env
docker build -q -f src/infra/Dockerfile -t community-cti:homelab src
docker compose up -d --remove-orphans $SERVICES
docker compose ps --format 'table {{.Service}}\t{{.Status}}'
REMOTE
