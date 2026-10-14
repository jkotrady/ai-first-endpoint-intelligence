#!/usr/bin/env python3
"""Read-only W04-W12 intake; exports a Win10 launch profile only after hash checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]

def inside(root,relative):
    p=(root/relative).resolve()
    if not p.is_relative_to(root.resolve()): raise ValueError('Path outside project')
    return p

def verify_media(root,profile):
    path=inside(root,profile['image_manifest'])
    if not path.is_file(): return None,['media_manifest_missing']
    try:
        m=json.loads(path.read_text())
        for key in ('product_edition','version','build_family','architecture'):
            if m[key]!=profile[key]: raise ValueError('Media target mismatch: '+key)
        if not re.fullmatch('[a-f0-9]{64}',m['sha256']) or type(m['size']) is not int or m['size']<=0:
            raise ValueError('Invalid expected hash/size')
        if not isinstance(m['source_reference'],str) or not m['source_reference'].strip():raise ValueError('Source reference missing')
        image=inside(root,m['image'])
        if not image.is_file():return None,['media_file_missing']
        if image.stat().st_size!=m['size']:return None,['media_size_mismatch']
        h=hashlib.sha256()
        with image.open('rb') as f:
            for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
        if h.hexdigest()!=m['sha256']:return None,['media_hash_mismatch']
        return m,[]
    except (KeyError,TypeError,ValueError,OSError) as e:
        return None,['invalid_media_manifest: '+str(e)]

def check(root=ROOT):
    profiles=json.loads((root/'tools/lab/modern-windows.json').read_text())
    selected={p['id']:p for p in json.loads((root/'outputs/windows-matrix.json').read_text())['profiles']}
    host={'qemu':shutil.which('qemu-system-x86_64'),'qemu_img':shutil.which('qemu-img'),
        'kvm_access':os.access('/dev/kvm',os.R_OK|os.W_OK),'swtpm':shutil.which('swtpm'),
        'secure_boot_code':Path('/usr/share/OVMF/OVMF_CODE_4M.ms.fd').is_file(),
        'enrolled_vars_template':Path('/usr/share/OVMF/OVMF_VARS_4M.ms.fd').is_file(),
        'free_disk_gib':shutil.disk_usage(root).free//(1024**3)}
    results=[]
    for p in profiles:
        for key in ('product_edition','version','build_family','architecture'):
            if p[key]!=selected[p['id']][key]:raise ValueError('Profile drift from selected matrix')
        media,blockers=verify_media(root,p)
        if not host['qemu'] or not host['qemu_img']:blockers.append('qemu_missing')
        if host['free_disk_gib']<p['disk_gib']+16:blockers.append('disk_reserve_insufficient')
        if p['tpm']:
            for key in ('kvm_access','swtpm','secure_boot_code','enrolled_vars_template'):
                if not host[key]:blockers.append(key+'_missing')
            blockers+=['win11_secure_boot_tpm_launcher_pending','supported_cpu_and_guest_secure_boot_require_runtime_verification']
        launch=None
        if not blockers:
            launch={key:p[key] for key in ('machine','accelerator','cpu','cpus','ram_mib','disk_gib')}
            launch.update(id=p['lab_id'],role=p['id']+' selected matrix; install target must be verified in guest',display_device='VGA',image=media['image'],sha256=media['sha256'],size=media['size'])
        results.append({'id':p['id'],'target':p['product_edition']+' '+p['version']+' '+p['architecture'],
            'blockers':blockers,'media_bytes_match_manifest':media is not None,
            'edition_claim':'manifest assertion; must verify actual installed edition/build/architecture',
            'runtime_verified':False,'launch_profile':launch})
    return {'checked_at':datetime.now(timezone.utc).isoformat(),'host':host,'profiles':results,'network':'offline only','activation':'not_attempted'}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='outputs/modern-lab-preflight-2026-10-14.json')
    parser.add_argument('--export-profile',choices=['W04','W05','W06','W07','W08','W09'])
    args=parser.parse_args();report=check()
    out=inside(ROOT,args.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n')
    if args.export_profile:
        entry=next(p for p in report['profiles'] if p['id']==args.export_profile)
        if entry['blockers']:raise SystemExit('Installation blocked: '+', '.join(entry['blockers']))
        dest=ROOT/'work/lab'/('verified-'+args.export_profile.lower()+'.json')
        dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(entry['launch_profile'],indent=2)+'\n')
        print('Verified launch profile:',dest.relative_to(ROOT))
    for p in report['profiles']:print(p['id']+': '+(', '.join(p['blockers']) or 'ready for offline installation; no runtime evidence yet'))

if __name__=='__main__':main()
