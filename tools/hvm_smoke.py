#!/usr/bin/env python3
"""Headless boot smoke test: exosphere -> Mesosphere (-> INI1 processes) reaches its expected state per SoC x INI1 profile."""
import argparse
import os
import re
import socket
import subprocess
import sys
import time

import hvm_log

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
HVM = os.environ.get('HORIZONVM_HOME', os.path.expanduser('~/.horizonvm'))
KERNEL_ELF = os.path.join(ROOT, 'third_party/Atmosphere/mesosphere/kernel/out/nintendo_nx_arm64_armv8a/debug/kernel.elf')
BIN = os.path.join(os.environ.get('DEVKITPRO', '/opt/devkitpro'), 'devkitA64/bin/aarch64-none-elf-')
KERNEL_STATE_INITIALIZED = 2   # Kernel::State (kern_kernel.hpp)
PROFILES = ('empty', 'core', 'ams', 'stock')
SETTLE = {'empty': 5, 'core': 8, 'ams': 20, 'stock': 20}     # seconds after the kernel layout / READY
LONG_SETTLE = 300   # --long: let the late sysmodules (behind nifm, account, btm, ...) reach their frontier
# Line that marks a profile's userland milestone, in the trace (smc lines are flushed as they happen) or on the
# UART: boot2 exiting once it has launched its whole list (Atmosphère's from the SD, Nintendo's ProdBoot).
READY = {'ams': ('uart', r'KProcess::Exit\(\) pid=\d+ name=boot2'),
         'stock': ('uart', r'KProcess::Exit\(\) pid=\d+ name=boot2')}
EXTRA_ALLOWED = {'ams': dict(hvm_log.ALLOWED_BOOT_HW, **hvm_log.ALLOWED_BOOT2),
                 'stock': dict(hvm_log.ALLOWED_BOOT_HW, **hvm_log.ALLOWED_BOOT2)}
# Known frontier: account aborts the first time it builds idgen:/context.bin, which needs the MAC address of a network
# interface, and nifm has none (neither the PCIe WLAN nor a USB Ethernet adapter is emulated). On stock, the fatal it
# throws makes every sysmodule that throws one afterwards (pcv, vi, Bus, hid, FS, ...) Break: "fatal already thrown".
ACCOUNT = '010000000000001e'
ETH_DEFAULT = {'ams': 'ax88772', 'stock': 'ax88772'}          # = run.sh
ADAPTER_MAC = {'erista': '02:48:56:4d:00:01', 'mariko': '02:48:56:4d:00:02'}


def expected_crashes(ini):
    def expected(crashes):          # [(program id, kind)] in UART order
        if not crashes or crashes[0] != (ACCOUNT, 'Break() called'):
            return set()
        if ini == 'stock' and all(kind == 'Break() called' for _, kind in crashes):
            return {prog for prog, _ in crashes}
        return {ACCOUNT}
    return expected
LR_PROGRAM_NOT_FOUND = 8 | (2 << 9)    # lr::ResultProgramNotFound, 2008-0002
IDLE_SAMPLES = 5
# Cores that must reach WFI. With boot2's sysmodules up, core 3 (their only core) stays busy: nvservices polls
# its GPU events in a loop (the GPU is not emulated).
IDLE_CORES = {'ams': {0, 1, 2}, 'stock': {0, 1, 2}}
SPL_SERVICES = {'spl:', 'csrng', 'spl:mig', 'spl:fs', 'spl:ssl', 'spl:es', 'spl:manu'}   # spl_main.cpp, fw >= 5.0.0
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


def smoke(soc, ini, nand, timeout, persist=False, maintenance=False, long=False, eth=None):
    eth = eth or ETH_DEFAULT.get(ini, 'none')
    os.makedirs(os.path.join(HVM, 'run'), mode=0o700, exist_ok=True)
    os.makedirs(os.path.join(HVM, 'logs'), mode=0o700, exist_ok=True)
    sock = os.path.join(HVM, 'run', 'mon-%s.sock' % soc)
    uart = os.path.join(HVM, 'logs', 'uart-%s.txt' % soc)
    if os.path.exists(sock):
        os.unlink(sock)
    s_state_off, idle = kernel_offsets()

    with open(uart, 'wb') as out:
        proc = subprocess.Popen([os.path.join(ROOT, 'scripts/run.sh'), '--soc', soc, '--ini', ini] + (['--nand', nand] if nand else []) + (['--persist'] if persist else []) + (['--maintenance'] if maintenance else []) + ['--eth', eth, '--trace', '--',
                                 '-monitor', 'unix:%s,server,nowait' % sock],
                                stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
    try:
        m = wait_for(uart, r'KernelRegion[^\n]*\n\s+Code\s+(0x[0-9a-f]+)', proc, timeout)
        base = int(m.group(1), 16) if m else None
        if base is not None and ini in READY:
            where, pattern = READY[ini]
            wait_for(os.path.join(HVM, 'logs', 'hvmtrace-%s.log' % soc) if where == 'trace' else uart, pattern, proc, timeout)
        time.sleep(LONG_SETTLE if long and ini in READY else SETTLE[ini])   # let init finish and the cores go idle
        mon, samples = '', []
        if base is not None and proc.poll() is None:
            mon = monitor(sock, ['x /1bx 0x%x' % (base + s_state_off)])
            for _ in range(IDLE_SAMPLES):   # periodic pollers may be awake at any single instant
                regs = monitor(sock, sum([['cpu %d' % c, 'info registers'] for c in range(4)], []))
                samples.append([int(p, 16) - base for p in re.findall(r'PC=([0-9a-f]+)', regs)])
                time.sleep(0.3)
    finally:
        proc.terminate()
        proc.wait()
    locks = [os.path.join(HVM, d, soc, 'overlay', 'lock') for d in ('nand', 'sd')]
    end = time.time() + 120
    while nand == 'dir' and persist and any(map(os.path.exists, locks)) and time.time() < end:
        time.sleep(0.5)                                 # hvm_nbd writes back once QEMU has disconnected

    with open(uart, 'rb') as f:
        log = f.read().decode('latin-1')
    state = re.search(r'^[0-9a-f]+: (0x[0-9a-f]+)', mon, re.M)
    idle_cores = {c for pcs in samples if len(pcs) == 4 for c, p in enumerate(pcs) if idle[0] <= p <= idle[1]}
    trace = hvm_log.analyze(os.path.join(HVM, 'logs', 'hvmtrace-%s.log' % soc),
                            os.path.join(HVM, 'logs', 'qemu-%s.log' % soc),
                            os.path.join(HVM, 'logs', 'uart-%s.log' % soc),
                            dict(hvm_log.ALLOWED, **EXTRA_ALLOWED.get(ini, {})), expected_crashes(ini))
    for v in trace['violations']:
        print('%-7s %-5s %-5s trace: %s' % (soc, ini, nand or '', v))
    return [
        ('exosphere OHAYO (single boot)', log.count('OHAYO') == 1),
        ('exosphere KeyGen 15', '[secmon] KeyGen: 15' in log),
        ('kernel banner', 'Horizon Kernel (Mesosphere)' in log),
        ('no kernel panic', 'Kernel Panic' not in log),
        ('Kernel::s_state == Initialized', bool(state) and int(state.group(1), 16) == KERNEL_STATE_INITIALIZED),
        ('cores %s idle in WFI' % ','.join(map(str, sorted(IDLE_CORES.get(ini, {0, 1, 2, 3})))),
         IDLE_CORES.get(ini, {0, 1, 2, 3}) <= idle_cores),
        ('trace: 3 PSCI CpuOn via smc #1', trace['smc'][(1, 0xC4000003)] == 3),
        ('trace: SMC/MMIO/exceptions allowlisted, secrets redacted, no crash on UART', not trace['violations']),
    ] + profile_checks(soc, ini, trace, log, maintenance, long) + writeback_checks(soc, ini, nand, persist) + \
        usb_checks(soc, ini, trace, eth, long)


def writeback_checks(soc, ini, nand, persist):
    if nand != 'dir' or not persist or ini != 'ams':
        return []
    saves = os.path.join(HVM, 'nand', soc, 'dir', 'SYSTEM', 'save')
    names = set(os.listdir(saves)) if os.path.isdir(saves) else set()
    backups = os.path.join(HVM, 'sd', soc, 'dir', 'atmosphere', 'automatic_backups')
    with open(os.path.join(HVM, 'nand', soc, 'dir', 'PRODINFO.bin'), 'rb') as f:
        serial = f.read(0x250 + 14)[0x250:].decode('ascii', 'replace')
    return [('write-back: FS-created saves in the folder (SYSTEM/save/8000000000000000, 8000000000000120)',
             {'8000000000000000', '8000000000000120'} <= names),
            ('write-back: ams_mitm backs the CAL0 up as <serial>_PRODINFO.bin (valid for a secure backup)',
             os.path.isdir(backups) and serial + '_PRODINFO.bin' in os.listdir(backups))]


def usb_checks(soc, ini, trace, eth, long=False):
    """USB-C port: the usb sysmodule drives the PD controller; on --long, with the adapter plugged in, the XUSB host
    and eth drive the AX88772 (QEMU trace events) and nifm leases an address from hvm_net."""
    if ini not in ('ams', 'stock'):
        return []
    events = trace['events']
    resets = [a for name, a in events if name == 'bm92t36_command' and a.endswith('0x0d0d')]
    checks = [('usb: the PD controller completes one SYS_RESET (CMD_DONE through the CradleIrq alert, no retries)',
               len(resets) == 1)]
    if eth == 'none' or not long:                # the host starts once psm answers usb's power request
        return checks
    controls = [a for name, a in events if name == 'usb_asix_control']
    net = net_log(soc)
    checks += [
        ('late: usb: OTG plug -> XUSB host runs and enumerates the AX88772 (SET_CONFIGURATION 1)',
         ('usb_xhci_run', '') in events and any(name == 'usb_set_config' and 'config 1, ret 0' in a
                                                for name, a in events)),
        ('late: eth drives the AX88772: PHY select, MAC read, receiver started, no unsupported request',
         any(a.startswith('request 0x4022') for a in controls) and any(a.startswith('request 0xc013') for a in controls)
         and any(re.match(r'request 0x4010 value 0x0[0-9a-f][89a-f][0-9a-f]', a) for a in controls)
         and not any(name == 'usb_asix_unsupported' for name, _ in events)),
        ('late: nifm leases 10.0.2.15 from hvm_net (DHCP ACK to the adapter MAC)',
         'dhcp ACK 10.0.2.15 to %s' % ADAPTER_MAC[soc] in net),
        ('late: nifm connection test: ctest.cdn.nintendo.net answered NXDOMAIN (nothing leaves the host)',
         'dns A ctest.cdn.nintendo.net -> NXDOMAIN' in net),
    ]
    return checks


def net_log(soc):
    path = os.path.join(HVM, 'logs', 'net-%s.log' % soc)
    if not os.path.exists(path):
        return ''
    with open(path) as f:
        return f.read()


def user_smc_calls(trace):
    """Pair user SMCs with their returns (exosphere runs them with interrupts masked, one at a time per core)."""
    calls, last = [], {}
    for kind, cpu, sid, regs in trace['user_smc']:
        if kind == 'smc':
            last[cpu] = (sid, regs)
        elif cpu in last:
            sid0, args = last.pop(cpu)
            calls.append((sid0, args, regs))
    return calls


def registered_by(trace, name):
    pids = pids_named(trace, name)
    return {n for p, n in trace['registered'] if p in pids}


PRE_SD_BOOT2 = {'psc', 'pcie', 'Bus', 'settings', 'pcv', 'usb'}   # boot2_api LaunchPreSdCardBootProgramsAndBoot2
MAINTENANCE_SKIPPED = {'friends', 'bcat', 'eupld'}   # boot2_api: normal minus maintenance list (npns: both, 7.0.0+)


def ams_checks(trace, log, maintenance=False):
    names = set(trace['procs'].values())
    set_version = [(a, r) for sid, a, r in user_smc_calls(trace) if sid == 0xC3000401 and a.get(1) == '0xfde8']
    boot, mitm = pids_named(trace, 'boot'), pids_named(trace, 'ams.mitm')
    pcv = pids_named(trace, 'pcv')
    return [
        ('8 INI1 processes started', {'Loader', 'NCM', 'ProcessMana', 'sm', 'boot', 'spl', 'ams.mitm', 'FS'} <= names),
        ('FS drives the eMMC (SDMMC4 MMIO)', 'sdmmc' in trace['mmio']),
        ('FS registers fsp-srv fsp-pr fsp-ldr', {'fsp-srv', 'fsp-pr', 'fsp-ldr'} <= registered_by(trace, 'FS')),
        ('spl registers its services', SPL_SERVICES <= registered_by(trace, 'spl')),
        ('ncm mounted SYSTEM and its content meta DB: registers ncm lr', {'ncm', 'lr'} <= registered_by(trace, 'NCM')),
        ('boot sets the real HOS version: SetConfig(65000, 22.5.0) -> 0 on core 3',
         [(a.get(3), r.get(0)) for a, r in set_version] == [('0x16050000', '0x0')]),
        ('loader registers ldr:pm ldr:shel ldr:dmnt', {'ldr:pm', 'ldr:shel', 'ldr:dmnt'} <= registered_by(trace, 'Loader')),
        ('pm registers pm:shell pm:dmnt pm:bm pm:info',
         {'pm:shell', 'pm:dmnt', 'pm:bm', 'pm:info'} <= registered_by(trace, 'ProcessMana')),
        ('ams_mitm serves bpc:ams', any(p in mitm and what == 'ManageNamedPort' and n == 'bpc:ams'
                                        for p, what, n in trace['ports'])),
        ('boot initializes I2C/GPIO/PWM/display and notifies pm:shell (NotifyBootFinished)',
         {'i2c', 'gpio', 'pwm', 'host1x_modules'} <= set(trace['mmio'])
         and any(p in boot and n == 'pm:shell' for p, n in trace['lookups'])),
        ('pm launches psc pcie Bus settings pcv usb', PRE_SD_BOOT2 <= names),
        ('pcv initializes (no fatal:u) and serves clkrst: pcie registers pcie',
         pcv_ok(trace, pcv) and 'pcie' in registered_by(trace, 'pcie')),
        ('ams_mitm mounts the SD: pm launches Atmosphère boot2 from stratosphere.romfs, and it launches memlet',
         {'boot2', 'memlet'} <= names),
        crash_check('ams', trace),
        ('volume buttons held: boot2 launches its maintenance list (no friends bcat eupld)' if maintenance else
         'volume buttons released: boot2 launches its normal list (friends bcat eupld)',
         not MAINTENANCE_SKIPPED & names if maintenance else MAINTENANCE_SKIPPED <= names),
    ]


def late_checks(trace):
    """The frontier boot2's sysmodules reach given time (--long)."""
    registered = {n for _, n in trace['registered']}
    return [
        ('late: bluetooth/btm/hid serve btdrv btm xcd:sys (valid CAL0 Bluetooth address)',
         {'btdrv', 'btm', 'xcd:sys'} <= registered),
        ('late: omm serves spsm, nifm nifm:s', {'spsm', 'nifm:s'} <= registered),
        ('late frontier: account aborts building idgen:/context.bin (nifm lists no network interface)',
         ACCOUNT in trace['crashes']),
    ]


def cascade(trace):
    """account's fatal came first: later fatal:u lookups are other sysmodules failing to throw theirs."""
    return next(iter(trace['crashes']), None) == ACCOUNT


def pcv_ok(trace, pcv):
    return cascade(trace) or not any(p in pcv and n == 'fatal:u' for p, n in trace['lookups'])


def crash_check(ini, trace):
    return ('crashes: none, or account without a network interface' +
            (' and the fatal cascade it starts' if ini == 'stock' else ''),
            set(trace['crashes']) <= expected_crashes(ini)(list(trace['crashes'].items())))


BOOT2_MODULES = {'boot2.ProdB', 'psc', 'settings', 'usb', 'pcie', 'Bus', 'pcv'}   # KProcess names (12 chars)


def stock_checks(trace, log, ncm_db):
    """Nintendo's own 22.5.0 INI1 on exosphere + Mesosphere + the synthetic NAND."""
    names = set(trace['procs'].values())
    boot = pids_named(trace, 'boot')
    pm = pids_named(trace, 'ProcessMana')
    pcv = pids_named(trace, 'pcv')
    return [
        ('the 7 official INI1 processes started', {'FS', 'Loader', 'NCM', 'ProcessMana', 'sm', 'boot', 'spl'} <= names),
        ('FS drives the eMMC and registers fsp-srv fsp-pr fsp-ldr',
         'sdmmc' in trace['mmio'] and {'fsp-srv', 'fsp-pr', 'fsp-ldr'} <= registered_by(trace, 'FS')),
        ('spl, ncm, loader and pm register their services',
         SPL_SERVICES <= registered_by(trace, 'spl') and {'ncm', 'lr'} <= registered_by(trace, 'NCM')
         and {'ldr:pm', 'ldr:shel', 'ldr:dmnt'} <= registered_by(trace, 'Loader')
         and {'pm:shell', 'pm:dmnt', 'pm:bm', 'pm:info'} <= registered_by(trace, 'ProcessMana')),
        ('boot initializes I2C/GPIO/PWM/display, notifies pm:shell and exits',
         {'i2c', 'gpio', 'pwm', 'host1x_modules'} <= set(trace['mmio'])
         and any(p in boot and n == 'pm:shell' for p, n in trace['lookups'])
         and re.search(r'KProcess::Exit\(\) pid=\d+ name=boot', log) is not None),
    ] + ([
        ('with the ncm DB on the NAND, pm launches boot2 and it starts psc settings usb pcie Bus pcv',
         BOOT2_MODULES <= names),
        ('pcv initializes (no fatal:u); boot2 goes past omm: am nvservices vi ns hid audio',
         pcv_ok(trace, pcv) and {'am', 'nvservices', 'vi', 'ns', 'hid', 'audio'} <= names),
        crash_check('stock', trace),
    ] if ncm_db else [
        ('frontier: pm cannot launch boot2, ldr:pm GetProgramInfo -> 2008-0002 (Nintendo ncm does not rebuild its DB)',
         any(p in pm and svc == 'ldr:pm' and cmd == 1 and rc == LR_PROGRAM_NOT_FOUND
             for p, svc, cmd, rc in trace['ipc_failures'])),
    ])


def pids_named(trace, name):
    return {p for p, n in trace['procs'].items() if n == name}


def ncm_db_in_tree(soc):
    """BuiltInSystem content meta DB save, as persisted by a --persist run (images are built from the same tree)."""
    return os.path.exists(os.path.join(HVM, 'nand', soc, 'dir', 'SYSTEM', 'save', '8000000000000120'))


def profile_checks(soc, ini, trace, log, maintenance=False, long=False):
    if ini == 'empty':
        return []
    if ini == 'ams':
        return ams_checks(trace, log, maintenance) + (late_checks(trace) if long else [])
    if ini == 'stock':
        return stock_checks(trace, log, ncm_db_in_tree(soc)) + (late_checks(trace) if long else [])
    calls = user_smc_calls(trace)
    get_config = {(a.get(1), r.get(0)) for sid, a, r in calls if sid == 0xC3000002}
    sm, spl = pids_named(trace, 'sm'), pids_named(trace, 'spl')
    checks = [
        ('sm and spl started', bool(sm) and bool(spl)),
        ('sm serves the "sm:" named port', any(p in sm and what == 'ManageNamedPort' and n == 'sm:'
                                               for p, what, n in trace['ports'])),
        ('spl registers %s' % ' '.join(sorted(SPL_SERVICES)),
         SPL_SERVICES <= {n for p, n in trace['registered'] if p in spl}),
        ('user GetConfig(65000) -> NotInitialized, GetConfig(65012) ok',
         ('0xfde8', '0x7') in get_config and ('0xfdf4', '0x0') in get_config),
        ('spl RNG through user GenerateRandomBytes (redacted)', any(sid == 0xC3000006 for sid, _, _ in calls)),
    ]
    return checks


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', action='append', choices=['erista', 'mariko'])
    ap.add_argument('--ini', help='comma-separated INI1 profiles (default: every built build/package2-<ini>.bin)')
    ap.add_argument('--nand', help='comma-separated eMMC backends for run.sh --nand (default: run.sh default)')
    ap.add_argument('--persist', action='store_true', help='keep eMMC writes (run.sh --persist)')
    ap.add_argument('--maintenance', action='store_true', help='volume buttons held (run.sh --maintenance)')
    ap.add_argument('--long', action='store_true', help='ams/stock: wait %ds after boot2 and check the late '
                    'sysmodules' % LONG_SETTLE)
    ap.add_argument('--eth', choices=['ax88772', 'none'], help='USB Ethernet adapter (run.sh --eth; default: '
                    'ax88772 for ams/stock)')
    ap.add_argument('--timeout', type=int, default=600)
    args = ap.parse_args()
    os.umask(0o077)

    inis = args.ini.split(',') if args.ini else [
        i for i in PROFILES if os.path.exists(os.path.join(ROOT, 'build', 'package2-%s.bin' % i))]
    failed = False
    for nand in args.nand.split(',') if args.nand else [None]:
        for ini in inis:
            for soc in args.soc or ['erista', 'mariko']:
                for name, ok in smoke(soc, ini, nand, args.timeout, args.persist, args.maintenance, args.long,
                                      args.eth):
                    print('%-7s %-5s %-5s %-6s %s' % (soc, ini, nand or '', 'PASS' if ok else 'FAIL', name))
                    failed |= not ok
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
