"""Create local-only database secrets once. Prints no secret material."""
from pathlib import Path
import os
import secrets

root = Path(__file__).resolve().parent.parent
path = root / '.env'
if path.exists():
    print('Existing .env retained.')
else:
    content = (
        f'DB_OWNER_PASSWORD={secrets.token_hex(32)}\n'
        f'DB_APP_PASSWORD={secrets.token_hex(32)}\n'
        'APP_ORIGIN=http://127.0.0.1:8080\n'
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        output.write(content)
    print('Created restricted .env with independent random database passwords.')
