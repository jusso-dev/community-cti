#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
docker compose -f "$root/infra/docker-compose.yml" up -d --wait
