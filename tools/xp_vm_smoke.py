#!/usr/bin/env python3
"""Bounded offline QEMU firmware and disk-overlay test, with no Windows media."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'tools/lab/w01_profile.json'


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inside(path):
    resolved = path.resolve()
    if not resolved.is_relative_to(ROOT):
        raise ValueError('Path must remain inside project')
    return resolved


def reserve_run(run_id):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', run_id):
        raise ValueError('Invalid run ID')
    target = inside(ROOT / 'work/lab/vm' / run_id)
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    return target


def run_command(args, cwd):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stderr.strip()} {result.stdout.strip()}')
    return result.stdout.strip()


def qemu_command(executable, profile):
    # Fixed relative disk names avoid QEMU key/value filename interpretation.
    return [executable, '-name', 'w01-offline-preparation',
            '-machine', profile['machine'] + ',vmport=off,dump-guest-core=off',
            '-accel', profile['accelerator'], '-cpu', profile['cpu'],
            '-smp', str(profile['cpus']), '-m', str(profile['ram_mib']),
            '-nodefaults', '-nic', 'none', '-device', profile['display_device'],
            '-drive', 'file=boot.qcow2,format=qcow2,if=ide,index=0',
            '-boot', 'order=c,strict=on', '-display', 'none',
            '-serial', 'none', '-parallel', 'none', '-monitor', 'none',
            '-qmp', 'stdio', '-no-reboot',
            '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


class QMP:
    def __init__(self, process, timeout=10):
        self.timeout = timeout
        self.process = process
        self.buffer = b''
        self.counter = 0
        greeting = self.receive()
        if 'QMP' not in greeting:
            raise RuntimeError('Missing QMP greeting')
        self.greeting = greeting
        self.call('qmp_capabilities')

    def receive(self):
        deadline = time.monotonic() + self.timeout
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError('QMP response timeout')
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError('QEMU closed QMP')
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def call(self, command, arguments=None):
        self.counter += 1
        message = {'execute': command, 'id': self.counter}
        if arguments is not None:
            message['arguments'] = arguments
        self.process.stdin.write((json.dumps(message) + '\n').encode())
        self.process.stdin.flush()
        while True:
            result = self.receive()
            if result.get('id') != self.counter:
                continue
            if 'error' in result:
                raise RuntimeError(f'QMP {command}: {result["error"]}')
            return result['return']


def pci_network_devices(buses):
    found = []
    for bus in buses:
        for device in bus.get('devices', []):
            if device.get('class_info', {}).get('class', 0) >> 8 == 2:
                found.append(device)
            bridge = device.get('pci_bridge')
            if bridge:
                found.extend(pci_network_devices([bridge['bus']]))
    return found


def smoke(folder, report):
    profile = json.loads(PROFILE.read_text())
    report['profile'] = profile
    report['profile_sha256'] = sha256(PROFILE)
    report['runner_sha256'] = sha256(Path(__file__))
    executables = {name: shutil.which(name) for name in ('qemu-system-i386', 'qemu-img', 'qemu-io')}
    if not all(executables.values()):
        raise RuntimeError('Required QEMU tools missing')
    report['executables'] = executables
    report['qemu_version'] = run_command([executables['qemu-system-i386'], '--version'], folder)
    report['kvm_device_present'] = Path('/dev/kvm').exists()
    img, io = executables['qemu-img'], executables['qemu-io']
    run_command([img, 'create', '-f', 'qcow2', 'blank.qcow2', f'{profile["disk_gib"]}G'], folder)
    initial_hash = sha256(folder / 'blank.qcow2')
    # Independent overlays: retain the dirty specimen, restore by using a fresh branch.
    for name in ('dirty.qcow2', 'restored.qcow2', 'boot.qcow2'):
        run_command([img, 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', 'blank.qcow2', name], folder)
    report['disk_test'] = {
        'write': run_command([io, '-f', 'qcow2', '-c', 'write -P 0x5a 1048576 4096', 'dirty.qcow2'], folder),
        'dirty_read': run_command([io, '-r', '-f', 'qcow2', '-c', 'read -P 0x5a 1048576 4096', 'dirty.qcow2'], folder),
        'restored_read': run_command([io, '-r', '-f', 'qcow2', '-c', 'read -P 0x00 1048576 4096', 'restored.qcow2'], folder),
        'compare_restored_to_base': run_command([img, 'compare', '-f', 'qcow2', '-F', 'qcow2', 'blank.qcow2', 'restored.qcow2'], folder)
    }
    command = qemu_command(executables['qemu-system-i386'], profile)
    report['command'] = command
    process = None
    with (folder / 'qemu.stderr.log').open('xb') as errors:
        try:
            process = subprocess.Popen(command, cwd=folder, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=errors)
            qmp = QMP(process)
            report['qmp_greeting'] = qmp.greeting
            time.sleep(5)
            report['status'] = qmp.call('query-status')
            report['pci'] = qmp.call('query-pci')
            report['blocks'] = qmp.call('query-block')
            report['network_backend_listing'] = qmp.call('human-monitor-command', {'command-line': 'info network'})
            report['host_socket_fds'] = []
            for fd in Path(f'/proc/{process.pid}/fd').iterdir():
                try:
                    link = os.readlink(fd)
                except FileNotFoundError:
                    continue
                if link.startswith('socket:'):
                    report['host_socket_fds'].append(link)
            if not report['status']['running']:
                raise RuntimeError('VM not running')
            if (pci_network_devices(report['pci']) or report['network_backend_listing'].strip()
                    or report['host_socket_fds']):
                raise RuntimeError('Unexpected network device/backend')
            qmp.call('stop')
            report['paused_status'] = qmp.call('query-status')
            qmp.call('screendump', {'filename': 'firmware.png', 'format': 'png'})
            qmp.call('quit')
            report['qemu_exit_code'] = process.wait(timeout=10)
            if report['qemu_exit_code'] != 0:
                raise RuntimeError('QEMU did not exit cleanly')
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                process.stdin.close()
                process.stdout.close()
                report['process_stopped'] = process.poll() is not None
    report['image_checks'] = {name: json.loads(run_command([img, 'check', '--output=json', '-f', 'qcow2', name], folder))
                              for name in ('blank.qcow2', 'dirty.qcow2', 'restored.qcow2', 'boot.qcow2')}
    if sha256(folder / 'blank.qcow2') != initial_hash:
        raise RuntimeError('Base image changed')
    report['base_sha256_before_and_after'] = initial_hash
    report['screenshot_sha256'] = sha256(folder / 'firmware.png')
    report['disk_info'] = json.loads(run_command([img, 'info', '--output=json', 'blank.qcow2'], folder))
    report['result'] = 'firmware_and_synthetic_disk_checks_passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-id', required=True, help='New unique lower-case ID; existing runs are never overwritten')
    args = parser.parse_args()
    try:
        folder = reserve_run(args.run_id)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'{exc}\n')
    report = {'created_utc': datetime.now(timezone.utc).isoformat(), 'run_id': args.run_id,
              'result': 'failed', 'windows_boot': 'not_run', 'agent_tests': 'not_run',
              'windows_snapshot_restore': 'not_run', 'guest_network_tests': 'not_run',
              'performance_validation': 'not_run', 'run_directory': str(folder)}
    try:
        smoke(folder, report)
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as exc:
        report['error'] = str(exc)
    with (folder / 'report.json').open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print(json.dumps({'result': report['result'], 'report': str(folder / 'report.json')}))
    return 0 if report['result'] != 'failed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
