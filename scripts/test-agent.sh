#!/usr/bin/env bash
set -euo pipefail
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
docker compose --project-directory "$project_directory" run --rm --no-deps agent-tools sh -c 'go mod verify && go test -race -count=1 ./internal/agent && go vet ./internal/agent'
