#!/usr/bin/env python3
"""Freeze a locally verified source/binary snapshot; no upload or endpoint update."""
import hashlib
import json
from pathlib import Path
import re
import sys
import shutil
ROOT=Path(__file__).resolve().parents[1]

def stage(root,name):
    if not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',name):raise ValueError('Invalid release name')
    src=root/'work/bin';manifest=(src/'agent-build.json').read_bytes();m=json.loads(manifest)
    data={'agent-build.json':manifest}
    for file,field in [('forensics-agent-x86.exe','binary'),('forensics-agent-source.zip','source_zip')]:
        data[file]=(src/file).read_bytes()
        if len(data[file])!=m[field+'_size'] or hashlib.sha256(data[file]).hexdigest()!=m[field+'_sha256']:
            raise ValueError('Artifact mismatch: '+file)
    if m['collectors']!=json.loads((root/'collectors/catalog.json').read_text()):raise ValueError('Catalog drift')
    parent=root/'work/releases';parent.mkdir(parents=True,exist_ok=True)
    dest=parent/name
    # mkdir refuses replacement; never overwrite an earlier release.
    dest.mkdir(mode=0o700)
    try:
        for file,body in data.items():
            path=dest/file;path.write_bytes(body);path.chmod(0o444)
        dest.chmod(0o555)
    except Exception:
        dest.chmod(0o700);shutil.rmtree(dest);raise
    return dest
if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: stage-agent-release.py release-name')
    print(stage(ROOT,sys.argv[1]).relative_to(ROOT))
