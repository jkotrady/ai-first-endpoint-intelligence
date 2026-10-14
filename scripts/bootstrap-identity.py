#!/usr/bin/env python3
"""Project-local pinned Keycloak/JDK lab bootstrap; never installs host packages."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request
ROOT=Path(__file__).resolve().parents[1]
PIN=json.loads((ROOT/'outputs/identity-toolchain-2026-10-14.json').read_text())

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
    return h.hexdigest()

def main():
    root=ROOT/'work/identity';downloads=root/'downloads';downloads.mkdir(parents=True,exist_ok=True)
    for p in PIN['jdk_packages']:
        file=downloads/Path(p['Filename']).name
        if not file.exists():subprocess.run(['apt-get','download',p['Package']+'='+p['Version']],cwd=downloads,check=True)
        if file.stat().st_size!=int(p['Size']) or digest(file)!=p['SHA256']:raise ValueError('JDK package integrity mismatch')
        subprocess.run(['dpkg-deb','-x',str(file),str(root/'jdk')],check=True)
    # Debian conf symlinks normally point to host /etc; keep this standalone JDK private.
    home=root/'jdk/usr/lib/jvm/java-25-openjdk-amd64'
    for file in (home/'conf').rglob('*'):
        if file.is_symlink():
            target=file.readlink()
            if str(target).startswith('/etc/java-25-openjdk/'):
                source=root/'jdk'/str(target).lstrip('/')
                if not source.is_file():raise ValueError('Missing standalone Java configuration')
                file.unlink();shutil.copyfile(source,file)
    k=PIN['keycloak'];archive=downloads/'keycloak-26.8.1.tar.gz'
    if not archive.exists():
        part=archive.with_suffix('.part')
        with urllib.request.urlopen(k['url'],timeout=60) as response,part.open('wb') as output:
            for chunk in iter(lambda:response.read(1024*1024),b''):output.write(chunk)
        if part.stat().st_size!=k['size'] or digest(part)!=k['sha256']:raise ValueError('Keycloak integrity mismatch')
        part.rename(archive)
    if archive.stat().st_size!=k['size'] or digest(archive)!=k['sha256']:raise ValueError('Keycloak integrity mismatch')
    if not (root/'keycloak-26.8.1').exists():
        with tarfile.open(archive) as t:t.extractall(root,filter='data')
    subprocess.run([str(home/'bin/java'),'-version'],check=True)
    print('Pinned identity lab dependencies ready; no host installation.')
if __name__=='__main__':main()
