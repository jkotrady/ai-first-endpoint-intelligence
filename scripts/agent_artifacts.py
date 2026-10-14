#!/usr/bin/env python3
"""Explicit, deterministic source bundle; never traverse work/ or private state."""
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXED = [
    'agent/windows/agent.c', 'agent/windows/pilot_config.h',
    'agent/windows/collector_main.c', 'scripts/build-collectors.py',
    'collectors/README.md', 'collectors/catalog.json',
    'collectors/windows/collector.h', 'collectors/windows/runtime.c',
    'collectors/windows/registry.c', 'docs/AGENT-AUDIT.md',
    'scripts/agent_artifacts.py', 'scripts/bootstrap-agent.py', 'scripts/build-agent.sh',
    'outputs/pilot-toolchain-2026-10-13.json',
    'agent/windows/licenses/MBEDTLS.txt', 'agent/windows/licenses/MINGW.txt',
    'agent/windows/licenses/GCC-RUNTIME.txt',
]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def inputs(root=ROOT):
    catalog = json.loads((root/'collectors/catalog.json').read_text())
    seen = set()
    for entry in catalog:
        if set(entry) != {'id', 'name', 'source', 'entrypoint', 'limitations'}:
            raise ValueError('Unexpected catalog fields')
        ident = entry['id']
        if not re.fullmatch(r'F[0-9]{2}', ident) or ident in seen:
            raise ValueError('Invalid or duplicate collector ID')
        if not re.fullmatch(r'collectors/windows/'+ident+r'_[a-z]+\.c', entry['source']):
            raise ValueError('Collector source outside allowlisted directory')
        if entry['entrypoint'] != 'collect_'+ident:
            raise ValueError('Invalid entrypoint')
        seen.add(ident)
    if not catalog or len(catalog)>50:
        raise ValueError('Invalid catalog length')
    paths = sorted(FIXED+[entry['source'] for entry in catalog])
    data = {}
    for name in paths:
        p = root/name
        if p.is_symlink() or not p.resolve().is_relative_to(root.resolve()):
            raise ValueError('Source symlink refused')
        data[name] = p.read_bytes()
    hashes = {name: digest(body) for name, body in data.items()}
    build_inputs = {name: value for name, value in hashes.items() if name.endswith(('.c', '.h', '.py', '.sh', '.json'))}
    fingerprint = digest(json.dumps(build_inputs, sort_keys=True, separators=(',', ':')).encode())
    return catalog, data, hashes, fingerprint

def bundle(data):
    result = io.BytesIO()
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(data):
            info = zipfile.ZipInfo(name, date_time=(1980,1,1,0,0,0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data[name])
    return result.getvalue()

def main(mode):
    catalog, data, hashes, fingerprint = inputs()
    out = ROOT/'work/bin'
    out.mkdir(parents=True, exist_ok=True)
    if mode == 'prepare':
        quoted = lambda s: json.dumps(s, ensure_ascii=True)
        macro = ' '.join('X('+quoted(e['id'])+','+e['entrypoint']+')' for e in catalog)
        header = '#define COLLECTOR_REGISTRY(X) '+macro+'\n'
        header += '#define COLLECTOR_IDS '+quoted(','.join(e['id'] for e in catalog))+'\n'
        header += '#define AGENT_SOURCE_SHA256 '+quoted(fingerprint)+'\n'
        header += '#define COLLECTOR_CATALOG_JSON '+quoted(json.dumps(catalog,ensure_ascii=True,separators=(',', ':'))) +'\n'
        (out/'catalog_generated.h').write_text(header)
        (out/'agent-build-input.sha256').write_text(fingerprint+'\n')
    elif mode == 'package':
        if (out/'agent-build-input.sha256').read_text().strip() != fingerprint:
            raise ValueError('Source changed during build; rebuild required')
        source = bundle(data)
        binary = (out/'forensics-agent-x86.exe').read_bytes()
        manifest = dict(schema_version=1, source_fingerprint=fingerprint,
            source_files=hashes, source_fingerprint_scope='source_files with .c .h .py .sh .json suffix; docs and notices excluded', binary_sha256=digest(binary), binary_size=len(binary),
            source_zip_sha256=digest(source), source_zip_size=len(source),
            collectors=catalog, target='windows-x86-subsystem-5.1',
            assurance='Unsigned local build record; runtime support requires separate OS tests')
        (out/'forensics-agent-source.zip').write_bytes(source)
        (out/'agent-build.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
        print('Agent binary SHA-256:', manifest['binary_sha256'])
        print('Source fingerprint:', fingerprint)
    else:
        raise ValueError('Expected prepare or package')

if __name__ == '__main__':
    main(sys.argv[1])
