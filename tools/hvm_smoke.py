#!/usr/bin/env python3
"""Headless boot smoke test: exosphere -> Mesosphere reaches Initialized with all cores idle."""
import argparse
import os
import re
import socket
import subprocess
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
HVM = os.environ.get('HORIZONVM_HOME', os.path.expanduser('~/.horizonvm'))
KERNEL_ELF = os.path.join(ROOT, 'third_party/Atmosphere/mesosphere/kernel/out/nintendo_nx_arm64_armv8a/debug/kernel.elf')
BIN = os.path.join(os.environ.get('DEVKITPRO', '/opt/devkitpro'), 'devkitA64/bin/aarch64-none-elf-')
KERNEL_STATE_INITIALIZED = 2   # Kernel::State (kern_kernel.hpp)
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def kernel_offsets():
    nm = subprocess.run([BIN + 'nm', KERNEL_ELF], capture_output=True, text=True, check=True).stdout
    s_state = int(re.search(r'^([0-9a-f]+) \w _ZN3ams4kern6Kernel7s_stateE$', nm, re.M).group(1), 16)
    dis = subprocess.run([BIN + 'objdump', '-d', '--disassemble=_ZN3ams4kern10KScheduler12ScheduleImplEv', KERNEL_ELF],
                         capture_output=True, text=True, check=True).stdout
    wfi = int(re.search(r'^\s*([0-9a-f]+):\s+d503207f\s+wfi', dis, re.M).group(1), 16)
    return s_state, (wfi, wfi + 4)   # a core halted in WFI reports the WFI or the following PC


def wait_for(path, pattern, proc, timeout):
    end = time.time() + timeout
    while time.time() < end and proc.poll() is None:
        with open(path, 'rb') as f:
            m = re.search(pattern, f.read().decode('latin-1'))
        if m:
            return m
        time.sleep(0.5)
    return None


def monitor(sock_path, commands):
    s = socket.socket(socket.AF_UNIX)
    s.connect(sock_path)
    s.settimeout(1.0)
    out = b''
    for c in commands + ['']:
        s.sendall(c.encode() + b'\n')
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            out += chunk
    s.close()
    return ANSI.sub('', out.decode('latin-1')).replace('\r', '')


def smoke(soc, timeout):
    os.makedirs(os.path.join(HVM, 'run'), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(HVM, 'logs'), mode=0o700, exist_ok=True)
    sock = os.path.join(HVM, 'run', 'mon-%s.sock' % soc)
    uart = os.path.join(HVM, 'logs', 'uart-%s.txt' % soc)
    if os.path.exists(sock):
        os.unlink(sock)
    s_state_off, idle = kernel_offsets()

    with open(uart, 'wb') as out:
        proc = subprocess.Popen([os.path.join(ROOT, 'scripts/run.sh'), '--soc', soc, '--',
                                 '-monitor', 'unix:%s,server,nowait' % sock],
                                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
    try:
        m = wait_for(uart, r'KernelRegion[^\n]*\n\s+Code\s+(0x[0-9a-f]+)', proc, timeout)
        base = int(m.group(1), 16) if m else None
        time.sleep(5)   # let init finish and the cores go idle
        mon = ''
        if base is not None and proc.poll() is None:
            cmds = ['x /1bx 0x%x' % (base + s_state_off)] + sum([['cpu %d' % c, 'info registers'] for c in range(4)], [])
            mon = monitor(sock, cmds)
    finally:
        proc.terminate()
        proc.wait()

    with open(uart, 'rb') as f:
        log = f.read().decode('latin-1')
    state = re.search(r'^[0-9a-f]+: (0x[0-9a-f]+)', mon, re.M)
    pcs = [int(p, 16) - base for p in re.findall(r'PC=([0-9a-f]+)', mon)] if base else []
    return [
        ('exosphere OHAYO (single boot)', log.count('OHAYO') == 1),
        ('exosphere KeyGen 15', '[secmon] KeyGen: 15' in log),
        ('kernel banner', 'Horizon Kernel (Mesosphere)' in log),
        ('no kernel panic', 'Kernel Panic' not in log),
        ('Kernel::s_state == Initialized', bool(state) and int(state.group(1), 16) == KERNEL_STATE_INITIALIZED),
        ('4 cores idle in WFI', len(pcs) == 4 and all(idle[0] <= p <= idle[1] for p in pcs)),
    ]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', action='append', choices=['erista', 'mariko'])
    ap.add_argument('--timeout', type=int, default=60)
    args = ap.parse_args()
    os.umask(0o077)

    failed = False
    for soc in args.soc or ['erista', 'mariko']:
        for name, ok in smoke(soc, args.timeout):
            print('%-7s %-6s %s' % (soc, 'PASS' if ok else 'FAIL', name))
            failed |= not ok
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
