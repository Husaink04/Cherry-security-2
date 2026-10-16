"""Verify a non-empty synthetic database backup in a new isolated restore target."""
import json
from pathlib import Path
import re
import subprocess
import uuid

root = Path(__file__).resolve().parent.parent
compose = ['docker', 'compose', '--project-directory', str(root)]
tables = ['accounts', 'audit_events', 'daily_summaries', 'devices', 'enrollment_keys', 'events', 'organizations', 'schema_migrations', 'sessions']

def query(database, sql):
    result = subprocess.run(compose + ['exec', '-T', 'db', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-U', 'cherryowner', '-d', database, '-Atc', sql], check=True, capture_output=True, text=True)
    return result.stdout.strip()

def snapshot(database):
    fingerprints = {}
    for table in tables:
        # Fixed allowlisted identifiers, no caller-supplied SQL identifiers.
        fingerprints[table] = query(database, f"SELECT count(*) || ':' || md5(coalesce(string_agg(to_jsonb(t)::text,E'\\n' ORDER BY to_jsonb(t)::text),'')) FROM public.{table} t")
    fingerprints['indexes'] = query(database, "SELECT md5(coalesce(string_agg(indexdef,E'\\n' ORDER BY indexname),'')) FROM pg_indexes WHERE schemaname='public'")
    return fingerprints

before = snapshot('cherrysecurity_test')
if int(before['events'].split(':')[0]) < 1 or int(before['organizations'].split(':')[0]) < 1:
    raise SystemExit('A non-empty browser fixture database is required before backup verification.')
backup = subprocess.run(['bash', str(root / 'scripts' / 'backup.sh'), 'cherrysecurity_test'], check=True, capture_output=True, text=True)
match = re.search(r'^Backup created: (.+)$', backup.stdout, re.MULTILINE)
if not match:
    raise SystemExit('Backup script did not return a file path.')
backup_path = Path(match.group(1))
target = f'cherrysecurity_restore_{uuid.uuid4().hex[:12]}_test'
subprocess.run(['bash', str(root / 'scripts' / 'restore.sh'), str(backup_path), target], check=True)
after = snapshot(target)
if before != after:
    raise SystemExit('Restored table/index fingerprints differ; target retained for investigation.')
source_state = json.loads(query(target, "SELECT json_build_object('revoked_devices',(SELECT count(*) FROM devices WHERE revoked_at IS NOT NULL),'used_keys',(SELECT count(*) FROM enrollment_keys WHERE used_at IS NOT NULL),'events',(SELECT count(*) FROM events),'summary_seconds',(SELECT coalesce(sum(seconds),0) FROM daily_summaries))"))
if source_state['revoked_devices'] < 1 or source_state['used_keys'] < 1:
    raise SystemExit('Revocation and used-key fixtures are required for a meaningful restore check.')
print(f'PASS: all {len(tables)} table fingerprints and index definitions match the source.')
print(json.dumps({'restore_database': target, 'verified_state': source_state}, indent=2))
print('Source and restored databases retained. No active database or volume was dropped.')
