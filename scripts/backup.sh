#!/usr/bin/env bash
set -euo pipefail
umask 077
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
backup_directory="$project_directory/backups"
source_database="${1:-cherrysecurity}"
if [[ "$source_database" != cherrysecurity && "$source_database" != cherrysecurity_test ]]; then
  printf 'Backup source must be cherrysecurity or the dedicated cherrysecurity_test database.\n' >&2
  exit 2
fi
mkdir -p -- "$backup_directory"
backup_file="$(mktemp "$backup_directory/cherrysecurity-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXXXX.dump")"
if docker compose --project-directory "$project_directory" exec -T db pg_dump --username cherryowner --dbname "$source_database" --format=custom > "$backup_file"; then
  printf 'Backup created: %s\n' "$backup_file"
else
  printf 'Backup failed; incomplete file retained for inspection: %s\n' "$backup_file" >&2
  exit 1
fi
