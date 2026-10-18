#!/usr/bin/env bash
set -euo pipefail
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
docker compose --project-directory "$project_directory" run --rm --no-deps agent-tools sh -eu -c '
  go mod verify
  mkdir -p /artifacts/agent
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -H=windowsgui" -o /artifacts/agent/CherrySecurityAgent-m1.exe ./cmd/service
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -H=windowsgui" -o /artifacts/agent/CherrySecurityHelper-m1.exe ./cmd/helper
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /artifacts/agent/CherrySecurityControl-m1.exe ./cmd/control
  cd /artifacts/agent
  sha256sum CherrySecurityAgent-m1.exe CherrySecurityHelper-m1.exe CherrySecurityControl-m1.exe > SHA256SUMS
'
