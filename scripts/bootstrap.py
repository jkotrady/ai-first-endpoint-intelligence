#!/usr/bin/env python3
"""Install pinned developer tools inside work/, after SHA-256 verification."""
import hashlib
import os
import subprocess
from pathlib import Path
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
TOOLS=ROOT/'work/toolchains'
PINS=[('go1.27.1.linux-amd64.tar.gz','https://go.dev/dl/go1.27.1.linux-amd64.tar.gz','63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445','go')]

def main():
    TOOLS.mkdir(parents=True,exist_ok=True)
    # Keep experimental/toolchain Go sources outside the product module walk.
    boundary=ROOT/'work/go.mod'
    if not boundary.exists(): boundary.write_text('module aiforensics.local/experiments\n\ngo 1.27.1\n')
    for name,url,digest,directory in PINS:
        archive=TOOLS/name
        if not archive.exists():
            partial=TOOLS/(name+'.part')
            with urllib.request.urlopen(url,timeout=60) as source,partial.open('xb') as target:
                for data in iter(lambda:source.read(1024*1024),b''): target.write(data)
            partial.rename(archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=digest:raise SystemExit('Toolchain hash mismatch')
        if not (TOOLS/directory).exists():
            with tarfile.open(archive) as bundle:bundle.extractall(TOOLS,filter='data')
        print('Verified archive; tool directory:',TOOLS/directory)
    env=dict(os.environ, GOPATH=str(ROOT/'work/go-path'), GOCACHE=str(ROOT/'work/go-cache'),
             GOTOOLCHAIN='local', GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org')
    subprocess.run([str(TOOLS/'go/bin/go'),'mod','download'],cwd=ROOT,env=env,check=True)
    subprocess.run([str(TOOLS/'go/bin/go'),'mod','verify'],cwd=ROOT,env=env,check=True)

if __name__=='__main__':main()
