"""Exercise the real interactive bootstrap binary against a new disposable database."""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import time
import uuid

root=Path(__file__).resolve().parent.parent
compose=['docker','compose','--project-directory',str(root)]
values=dict(line.split('=',1) for line in (root/'.env').read_text().splitlines() if line and not line.startswith('#'))
database='cherrysecurity_cli_'+uuid.uuid4().hex[:10]+'_test'
subprocess.run(compose+['exec','-T','db','createdb','-U','cherryowner',database],check=True)
environment=os.environ.copy()
environment['DATABASE_URL']=f"postgres://cherryowner:{values['DB_OWNER_PASSWORD']}@db:5432/{database}?sslmode=disable"
subprocess.run(compose+['run','--rm','-T','--no-deps','-e','DATABASE_URL','-e','GRANT_APP_ROLE=true','--entrypoint','/app/migrate','api'],env=environment,check=True)
environment['DATABASE_URL']=f"postgres://cherryapp:{values['DB_APP_PASSWORD']}@db:5432/{database}?sslmode=disable"
primary,terminal=pty.openpty()
process=subprocess.Popen(compose+['run','--rm','--no-deps','-e','DATABASE_URL','--entrypoint','/app/admin','api'],env=environment,stdin=terminal,stdout=terminal,stderr=terminal)
os.close(terminal)
dummy_password='Synthetic-only-bootstrap-password-2026!'
stages=[('Product Owner email: ',b'bootstrap-fixture@example.test\n'),('Product Owner password (14', (dummy_password+'\n').encode()),('Confirm password: ',(dummy_password+'\n').encode())]
output='';step=0;deadline=time.monotonic()+45
try:
    while time.monotonic()<deadline:
        readable,_,_=select.select([primary],[],[],0.2)
        if readable:
            try:
                chunk=os.read(primary,65536)
            except OSError:
                break
            if not chunk:
                break
            output+=chunk.decode(errors='replace')
            if step<len(stages) and stages[step][0] in output:
                os.write(primary,stages[step][1]);step+=1
        if process.poll() is not None:
            break
    # PTY EOF may arrive just before Docker Compose reaps the successful child.
    if process.poll() is None and 'Product Owner created.' in output:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is None:
        process.terminate()
        print(output.replace(dummy_password,'[REDACTED TEST PASSWORD]'))
        raise SystemExit(f'Bootstrap did not complete before the test timeout (input stages completed: {step}).')
    print(output.replace(dummy_password,'[REDACTED TEST PASSWORD]'))
    if process.wait()!=0 or 'Product Owner created.' not in output:
        raise SystemExit('Interactive bootstrap failed in the isolated test database.')
    count=subprocess.run(compose+['exec','-T','db','psql','-U','cherryowner','-d',database,'-Atc','SELECT count(*) FROM accounts;'],capture_output=True,text=True,check=True).stdout.strip()
    if count!='1':
        raise SystemExit('Bootstrap did not persist exactly one owner.')
    print(json.dumps({'bootstrap':'PASS','database':database,'owner_count':1}))
finally:
    os.close(primary)
