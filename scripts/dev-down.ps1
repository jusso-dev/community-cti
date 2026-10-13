$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
docker compose -f (Join-Path $root "infra\docker-compose.yml") down
