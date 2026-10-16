"""Start an isolated empty-volume deployment, verify it, then stop only that test project."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from urllib.request import urlopen

root=Path(__file__).resolve().parent.parent
artifacts=root/'artifacts'
artifacts.mkdir(exist_ok=True)
project='cherrysecurity-m0-fresh-'+secrets.token_hex(4)
environment_path=artifacts/(project+'.env')
descriptor=os.open(environment_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(descriptor,'w') as output:
    output.write(f'DB_OWNER_PASSWORD={secrets.token_hex(32)}\nDB_APP_PASSWORD={secrets.token_hex(32)}\nAPP_ORIGIN=http://127.0.0.1:8084\nWEB_PORT=8084\n')
compose=['docker','compose','--project-directory',str(root),'--env-file',str(environment_path),'-p',project]
subprocess.run(compose+['up','-d','--build','db','migrate','api','web'],check=True)
try:
    for attempt in range(30):
        try:
            with urlopen('http://127.0.0.1:8084/api/readyz',timeout=2) as response:
                if json.load(response).get('status')=='ready':
                    break
        except (OSError,ValueError):
            time.sleep(1)
    else:
        raise SystemExit('Fresh stack failed readiness.')
    result=subprocess.run(compose+['exec','-T','db','psql','-X','-v','ON_ERROR_STOP=1','-U','cherryowner','-d','cherrysecurity','-Atc',"SELECT (SELECT max(version) FROM schema_migrations)||':'||(SELECT count(*) FROM accounts)||':'||(SELECT rolsuper::text FROM pg_roles WHERE rolname='cherryapp');"],check=True,capture_output=True,text=True)
    if result.stdout.strip()!='2:0:false':
        raise SystemExit('Fresh schema, empty account state, or least-privilege role validation failed.')
    print(json.dumps({'fresh_setup':'PASS','project':project,'schema_version':2,'initial_accounts':0,'runtime_superuser':False}))
finally:
    subprocess.run(compose+['stop'],check=True)
    print('Only the fresh test project was stopped; its volume and restricted environment remain for inspection.')
