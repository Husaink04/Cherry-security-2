#!/usr/bin/env bash
set -euo pipefail
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Only project-owned Go cache volumes are adjusted. Runtime app containers remain unprivileged.
docker compose --project-directory "$project_directory" run --rm --no-deps --user 0:0 tools sh -c 'mkdir -p /cache/gopath && chown -R 1000:1000 /cache /go/pkg/mod'
