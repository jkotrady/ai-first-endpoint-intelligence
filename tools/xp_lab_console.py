#!/usr/bin/env python3
"""Local-only interactive QMP controller for the explicitly authorized XP lab.
Commands on stdin: screen, status, key <qcode>..., text <US ASCII>, quit.
Default is offline. Pilot mode adds only an explicitly restricted local TLS route.
"""
import argparse
import hashlib
import json
from pathlib import Path
import select
import subprocess
import sys
import time
from xp_vm_smoke import QMP, ROOT, PROFILE, qemu_command, pci_network_devices, inside

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--intake', action='store_true', help='Boot installed disk with read-only intake CD and COM1 output file')
parser.add_argument('--cirrus', action='store_true', help='Test Cirrus VGA for XP OOBE')
parser.add_argument('--pilot-cd', action='store_true', help='Use private pilot CD, still offline')
parser.add_argument('--pilot-network', action='store_true', help='Restrict NIC to explicit localhost TLS gateway; requires provision marker')
args = parser.parse_args()
if args.pilot_network and not args.pilot_cd: parser.error('--pilot-network requires --pilot-cd')

folder = inside(ROOT / 'work/lab/vm/w01-install-01')
iso = inside(ROOT / 'work/lab/media/xp-pro-sp3-x86-retail.iso')
if not iso.is_file():
    raise SystemExit('Verified ISO missing')
h = hashlib.sha1()
with iso.open('rb') as f:
    for data in iter(lambda: f.read(1024*1024), b''): h.update(data)
if h.hexdigest() != '1c735b38931bf57fb14ebd9a9ba253ceb443d459' or iso.stat().st_size != 617756672:
    raise SystemExit('ISO integrity mismatch')
folder.mkdir(parents=True, exist_ok=True, mode=0o700)
if folder.resolve().parent != (ROOT / 'work/lab/vm').resolve() or (folder/'boot.qcow2').is_symlink():
    raise SystemExit('Unexpected path')
if (args.intake or args.pilot_cd) and not (folder / 'boot.qcow2').exists():
    raise SystemExit('Installed disk missing; intake mode cannot create a blank disk')
if not (folder / 'boot.qcow2').exists():
    subprocess.run(['qemu-img','create','-f','qcow2','boot.qcow2','24G'],cwd=folder,check=True)
command = qemu_command('qemu-system-i386',json.loads(PROFILE.read_text()))
if args.cirrus: command[command.index('-device')+1] = 'cirrus-vga'
command.remove('-no-reboot')
command[command.index('order=c,strict=on')] = 'order=c,once=d,strict=on'
if args.pilot_cd:
    pilot = inside(ROOT / 'work/lab/media/pilot.iso')
    if not pilot.is_file(): raise SystemExit('Pilot CD missing')
    command[command.index('order=c,once=d,strict=on')] = 'order=c,strict=on'
    command[command.index('-serial')+1] = 'file:pilot-serial-'+str(time.time_ns())+'.bin'
    command += ['-drive','file=../../media/pilot.iso,format=raw,media=cdrom,if=ide,index=2,readonly=on']
elif args.intake:
    intake = inside(ROOT / 'work/lab/media/intake-20261013.iso')
    if not intake.is_file(): raise SystemExit('Intake CD missing')
    command[command.index('order=c,once=d,strict=on')] = 'order=c,strict=on'
    command[command.index('-serial')+1] = 'file:intake-serial-'+str(time.time_ns())+'.bin'
    command += ['-drive','file=../../media/intake-20261013.iso,format=raw,media=cdrom,if=ide,index=2,readonly=on']
else:
    command += ['-drive','file=../../media/xp-pro-sp3-x86-retail.iso,format=raw,media=cdrom,if=ide,index=2,readonly=on']
if args.pilot_network:
    marker=folder/'pilot-credentials-set.json'
    if not marker.is_file() or json.loads(marker.read_text()).get('boot_inode')!=(folder/'boot.qcow2').stat().st_ino: raise SystemExit('Configure Windows credentials offline for this disk first')
    i=command.index('-nic');del command[i:i+2]
    # No hostfwd, DNS, SMB or arbitrary egress. One fixed guest route only.
    command += ['-netdev','user,id=pilot,restrict=on,ipv6=off,guestfwd=tcp:10.0.2.100:8443-tcp:127.0.0.1:8443,,reconnect=1','-device','rtl8139,netdev=pilot']
    # Direct socket backend avoids spawning children; full QEMU sandbox retained.
with (folder/'console-command.json').open('w') as f: json.dump(command,f,indent=2)
with (folder/'qemu-install.stderr.log').open('ab') as err:
    process = subprocess.Popen(command,cwd=folder,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err)
    try:
        qmp = QMP(process, timeout=45)
        nics=pci_network_devices(qmp.call('query-pci'))
        network=qmp.call('human-monitor-command',{'command-line':'info network'}).strip()
        if args.pilot_network:
            if len(nics)!=1 or not network: raise RuntimeError('Pilot NIC missing or unexpected')
        elif nics or network: raise RuntimeError('Unexpected networking')
        print('XP lab running '+('with restricted pilot TLS route' if args.pilot_network else 'offline')+'. Commands: screen | status | key ret | quit',flush=True)
        deadline = time.monotonic()+3600
        while process.poll() is None and time.monotonic()<deadline:
            if not select.select([sys.stdin],[],[],15)[0]: continue
            line=sys.stdin.readline()
            if not line: break
            parts=line.strip().split()
            if not parts: continue
            if parts==['quit']: break
            if parts==['status']:
                print(json.dumps(qmp.call('query-status')),flush=True)
            elif parts==['screen']:
                name='screen-'+str(time.time_ns())+'.png'
                qmp.call('screendump',{'filename':name,'format':'png'})
                print(str(folder/name),flush=True)
            elif parts[0]=='text' or parts==['password']:
                value=(ROOT/'work/private/xp-pilot-admin.txt').read_text().strip() if parts==['password'] else line.rstrip('\r\n')[5:]
                plain={' ':'spc','-':'minus','=':'equal','[':'bracket_left',']':'bracket_right',';':'semicolon',"'":'apostrophe',',':'comma','.':'dot','/':'slash','\\':'backslash'}
                shifted={'*':'8','%':'5','!':'1',':':'semicolon','_':'minus','>':'dot','<':'comma','"':'apostrophe','?':'slash','(':'9',')':'0','&':'7','|':'backslash'}
                sequence=[]
                for ch in value:
                    if ch.isascii() and ch.isalnum():
                        sequence.append((ch.lower(), ch.isupper()))
                    elif ch in plain: sequence.append((plain[ch],False))
                    elif ch in shifted: sequence.append((shifted[ch],True))
                    else:
                        print('Unsupported US keyboard character; nothing typed',flush=True)
                        sequence=[]
                        break
                if not sequence: continue
                if len(sequence)>256:
                    print('Text too long; nothing typed',flush=True)
                    continue
                for code,shift in sequence:
                    keys=([{'type':'qcode','data':'shift'}] if shift else [])+[{'type':'qcode','data':code}]
                    qmp.call('send-key',{'keys':keys,'hold-time':30})
                    time.sleep(0.05)
                print('text sent',flush=True)
            elif parts[0]=='key' and 1<len(parts)<=5:
                try:
                    qmp.call('send-key',{'keys':[{'type':'qcode','data':k} for k in parts[1:]],'hold-time':100})
                    print('key sent',flush=True)
                except RuntimeError as exc:
                    print(str(exc),flush=True)
            else: print('Unknown command',flush=True)
    finally:
        if process.poll() is None:
            try:
                qmp.call('quit')
                process.wait(timeout=10)
            except Exception:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        print('VM stopped: '+str(process.returncode),flush=True)
