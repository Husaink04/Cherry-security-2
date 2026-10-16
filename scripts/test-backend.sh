#!/usr/bin/env bash
set -euo pipefail
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
docker compose --project-directory "$project_directory" run --rm tools sh -c 'go mod verify && go test -race -count=1 -v ./... && go vet ./...'
