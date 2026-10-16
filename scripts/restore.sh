#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  printf 'Usage: bash /absolute/project/scripts/restore.sh /absolute/backup.dump cherrysecurity_restore_NAME_test\n' >&2
  exit 2
fi
backup_file="$1"
target_database="$2"
if [[ "$backup_file" != /* || ! -f "$backup_file" ]]; then
  printf 'An existing absolute backup path is required.\n' >&2; exit 2
fi
if [[ ! "$target_database" =~ ^cherrysecurity_restore_[a-z0-9_]+_test$ ]]; then
  printf 'Restore target must be a new cherrysecurity_restore_NAME_test database.\n' >&2; exit 2
fi
project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# createdb fails if this target already exists; never drop or overwrite a database.
docker compose --project-directory "$project_directory" exec -T db createdb --username cherryowner --template template0 "$target_database"
docker compose --project-directory "$project_directory" exec -T db pg_restore --username cherryowner --dbname "$target_database" --no-owner --exit-on-error < "$backup_file"
printf 'Restore complete into isolated database: %s\n' "$target_database"
