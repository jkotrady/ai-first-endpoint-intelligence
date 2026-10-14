#!/usr/bin/env python3
"""Project-local Ubuntu/amd64 MinGW + Mbed TLS bootstrap; no apt install or sudo."""
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'work/toolchains'
PIN = json.loads((ROOT/'outputs/pilot-toolchain-2026-10-13.json').read_text())

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def main():
    debs=TOOLS/'mingw-debs';debs.mkdir(parents=True,exist_ok=True)
    for p in PIN['compiler_packages']:
        matches=list(debs.glob(p['package']+'_'+p['version']+'_*.deb'))
        if not matches:
            subprocess.run(['apt-get','download',p['package']+'='+p['version']],cwd=debs,check=True)
            matches=list(debs.glob(p['package']+'_'+p['version']+'_*.deb'))
        if len(matches)!=1 or digest(matches[0])!=p['sha256']:
            raise SystemExit('Pinned package hash mismatch: '+p['package'])
        subprocess.run(['dpkg-deb','-x',str(matches[0]),str(TOOLS/'mingw')],check=True)
    tls=PIN['tls'];archive=TOOLS/('mbedtls-'+tls['version']+'.tar.bz2')
    if not archive.exists():
        partial=archive.with_suffix('.part')
        with urllib.request.urlopen(tls['source'],timeout=60) as src,partial.open('xb') as dst:
            for b in iter(lambda:src.read(1024*1024),b''):dst.write(b)
        if digest(partial)!=tls['sha256']:raise SystemExit('TLS archive hash mismatch')
        partial.rename(archive)
    if digest(archive)!=tls['sha256']:raise SystemExit('TLS archive hash mismatch')
    if not (TOOLS/('mbedtls-'+tls['version'])).exists():
        with tarfile.open(archive) as t:t.extractall(TOOLS,filter='data')
    print('Pinned native toolchain archives verified and extracted locally. Run scripts/build-agent.sh.')

if __name__=='__main__':main()
