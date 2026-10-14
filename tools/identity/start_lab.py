#!/usr/bin/env python3
"""Local standalone identity lab. No app migration or tenant grants."""
from pathlib import Path
import os
import secrets
import shutil
import subprocess
ROOT=Path(__file__).resolve().parents[2]
base=ROOT/'work/identity';kc=base/'keycloak-26.8.1'
if not (kc/'bin/kc.sh').is_file():raise SystemExit('Run scripts/bootstrap-identity.py first')
private=ROOT/'work/private';private.mkdir(mode=0o700,exist_ok=True);private.chmod(0o700)
password=private/'identity-lab-admin.txt'
if not password.exists():
    fd=os.open(password,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:f.write(secrets.token_urlsafe(32)+'\n')
password.chmod(0o600)
imports=kc/'data/import';imports.mkdir(parents=True,exist_ok=True)
shutil.copyfile(ROOT/'tools/identity/forensics-lab-realm.json',imports/'forensics-lab-realm.json')
userhome=base/'home';userhome.mkdir(mode=0o700,exist_ok=True)
env=dict(os.environ,JAVA_HOME=str(base/'jdk/usr/lib/jvm/java-25-openjdk-amd64'),
    KC_BOOTSTRAP_ADMIN_USERNAME='lab-admin',KC_BOOTSTRAP_ADMIN_PASSWORD=password.read_text().strip(),
    JAVA_OPTS_APPEND='-Duser.home="'+str(userhome)+'" -Xms128m -Xmx768m')
# exec preserves signal handling; bootstrap secret appears only in child environment.
args=[str(kc/'bin/kc.sh'),'start-dev','--http-host=127.0.0.1','--http-port=9080','--hostname=http://127.0.0.1:9080','--import-realm','--health-enabled=false','--metrics-enabled=false']
os.execve(args[0],args,env)
