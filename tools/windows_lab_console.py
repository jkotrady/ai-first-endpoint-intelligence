#!/usr/bin/env python3
"""Supplemental Windows lab; offline by default, optional restricted local pilot TLS route."""
import argparse,hashlib,json,os,select,subprocess,sys,time
from xp_vm_smoke import ROOT,inside,qemu_command,QMP,pci_network_devices

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--profile',required=True)
parser.add_argument('--pilot-cd',action='store_true')
parser.add_argument('--pilot-network',action='store_true')
args=parser.parse_args()
if args.pilot_network and not args.pilot_cd:parser.error('--pilot-network requires --pilot-cd')
p=json.loads(inside(ROOT/args.profile).read_text())
import re
if not re.fullmatch('[a-z0-9-]{1,50}',p['id']):raise SystemExit('Invalid profile ID')
iso=inside(ROOT/p['image'])
h=hashlib.sha256()
with iso.open('rb') as f:
 for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
if iso.stat().st_size!=p['size'] or h.hexdigest()!=p['sha256']:raise SystemExit('ISO integrity mismatch')
folder=inside(ROOT/'work/lab/vm'/p['id']);folder.mkdir(parents=True,exist_ok=True,mode=0o700)
if (folder/'boot.qcow2').is_symlink():raise SystemExit('Symlink disk refused')
if args.pilot_cd and not (folder/'boot.qcow2').exists():raise SystemExit('Install the offline Windows disk first')
if not (folder/'boot.qcow2').exists():subprocess.run(['qemu-img','create','-f','qcow2','boot.qcow2',str(p['disk_gib'])+'G'],cwd=folder,check=True)
cmd=qemu_command('qemu-system-x86_64',p);cmd.remove('-no-reboot');cmd[cmd.index('-name')+1]=p['id']
# Verified ISO path is converted to a fixed relative path; reject QEMU delimiters.
if args.pilot_cd:
 iso=inside(ROOT/'work/lab/media'/(p['id']+'-pilot.iso'))
 if not iso.is_file():raise SystemExit('Private pilot CD missing')
 cmd[cmd.index('-serial')+1]='file:pilot-serial-'+str(time.time_ns())+'.bin'
rel=os.path.relpath(iso,folder)
if ',' in rel:raise SystemExit('Unsupported image path')
cmd+=['-drive','file='+rel+',format=raw,media=cdrom,if=ide,index=2,readonly=on']
if not args.pilot_cd:cmd[cmd.index('order=c,strict=on')]='order=c,once=d,strict=on'
if args.pilot_network:
 marker=folder/'pilot-credentials-set.json'
 if not marker.is_file() or json.loads(marker.read_text()).get('boot_inode')!=(folder/'boot.qcow2').stat().st_ino:raise SystemExit('Provision credentials offline on this working disk first')
 i=cmd.index('-nic');del cmd[i:i+2]
 cmd+=['-netdev','user,id=pilot,restrict=on,ipv6=off,guestfwd=tcp:10.0.2.100:8443-tcp:127.0.0.1:8443,,reconnect=1','-device','rtl8139,netdev=pilot']
(folder/'command.json').write_text(json.dumps(cmd,indent=2))
with (folder/'stderr.log').open('ab') as err:
 proc=subprocess.Popen(cmd,cwd=folder,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err)
 try:
  q=QMP(proc,timeout=45)
  nics=pci_network_devices(q.call('query-pci'))
  if len(nics)!=(1 if args.pilot_network else 0):raise RuntimeError('Unexpected NIC inventory')
  print(('Restricted pilot TLS lab' if args.pilot_network else 'Offline lab')+' running. screen | key <qcodes> | text <ASCII> | password | status | quit',flush=True)
  deadline=time.monotonic()+7200
  while proc.poll() is None and time.monotonic()<deadline:
   if not select.select([sys.stdin],[],[],10)[0]:continue
   line=sys.stdin.readline().rstrip('\r\n')
   if not line or line=='quit':break
   try:
    if line=='screen':
     fn='screen-'+str(time.time_ns())+'.png';q.call('screendump',{'filename':fn,'format':'png'});print(folder/fn,flush=True)
    elif line=='status':print(q.call('query-status'),flush=True)
    elif line.startswith('key '):q.call('send-key',{'keys':[{'type':'qcode','data':k} for k in line[4:].split()],'hold-time':100});print('key sent',flush=True)
    elif line.startswith('text ') or line=='password':
     text=inside(ROOT/'work/private'/(p['id']+'-password.txt')).read_text().strip() if line=='password' else line[5:]
     plain={' ':'spc','-':'minus','.':'dot','/':'slash','\\':'backslash'};shifted={':':'semicolon','_':'minus','@':'2','*':'8','%':'5','"':'apostrophe','>':'dot','&':'7'}
     if len(text)>256 or any(not (c.isascii() and c.isalnum() or c in plain or c in shifted) for c in text):print('Unsupported text; nothing sent',flush=True);continue
     for c in text:
      code=plain.get(c,shifted.get(c,c.lower()));keys=([{'type':'qcode','data':'shift'}] if c.isupper() or c in shifted else [])+[{'type':'qcode','data':code}];q.call('send-key',{'keys':keys,'hold-time':30});time.sleep(.05)
     print('text sent',flush=True)
   except (ValueError,RuntimeError) as e:print(str(e),flush=True)
 finally:
  if proc.poll() is None:
   try:q.call('quit');proc.wait(timeout=15)
   except Exception:proc.terminate();proc.wait(timeout=15)
  print('VM stopped:',proc.returncode,flush=True)
