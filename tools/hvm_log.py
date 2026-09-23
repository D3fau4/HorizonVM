#!/usr/bin/env python3
"""Summarize and check a HorizonVM trace (hvmtrace plugin log + QEMU -d int log + UART log)."""
import argparse
import collections
import os
import re
import struct
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SVC_HEADER = os.path.join(ROOT, 'third_party/Atmosphere/libraries/libvapours/include/vapours/svc/svc_definition_macro.hpp')

# Tegra X1/X1+ MMIO map as instantiated by tegra_qemu (hw/arm/tegra2/tegrax1.c).
DEVICES = [
    (0x50000000, 0x40000, 'host1x'), (0x50040000, 0x1000, 'avpcache'), (0x50041000, 0x1000, 'gic_dist'),
    (0x50042000, 0x2000, 'gic_cpu'), (0x50060000, 0x1000, 'mselect'), (0x54000000, 0x6C0000, 'host1x_modules'),
    (0x57000000, 0x1000000, 'gpu'), (0x60000000, 0x1000, 'pg'), (0x60001000, 0x2000, 'sema'),
    (0x60004000, 0x600, 'ictlr'), (0x60005000, 0x1000, 'timer'), (0x60006000, 0x1000, 'car'),
    (0x60007000, 0x1000, 'flow'), (0x60008000, 0x2000, 'ahb_dma'), (0x6000C000, 0x200, 'ahb_gizmo'),
    (0x6000C200, 0x100, 'sb'), (0x6000C800, 0x400, 'actmon'), (0x6000D000, 0x1000, 'gpio'),
    (0x6000F000, 0x1000, 'evp'), (0x6001DC00, 0x400, 'ipatch'), (0x60020000, 0x1000, 'apb_dma'),
    (0x70000000, 0x3000, 'apb_misc'), (0x70003000, 0x1000, 'pinmuxaux'), (0x70006000, 0x400, 'uart'),
    (0x7000A000, 0x100, 'pwm'), (0x7000C000, 0x1200, 'i2c'), (0x7000D400, 0x800, 'spi'),
    (0x7000E000, 0x400, 'rtc'), (0x7000E400, 0xC00, 'pmc'), (0x7000F000, 0x800, 'kfuse'),
    (0x7000F800, 0x800, 'fuse'), (0x70012000, 0x2000, 'se'), (0x70014000, 0x1000, 'tsensor'),
    (0x70019000, 0x1000, 'mc'), (0x7001B000, 0x5000, 'emc/mc01'), (0x700B0000, 0x800, 'sdmmc'),
    (0x700E3000, 0x100, 'mipi_cal'), (0x700F0000, 0x10000, 'sysctr0'), (0x70100000, 0x10000, 'sysctr1'), (0x70412000, 0x2000, 'se2'),
    (0x70420000, 0x10000, 'pka1'),
]

# Devices exosphere, the NX kernel and the INI1 processes are expected to touch (and why).
ALLOWED = {
    'gic_dist': 'kernel/exosphere GICv2', 'gic_cpu': 'kernel/exosphere GICv2', 'uart': 'exosphere + KDebugLog',
    'se': 'exosphere crypto/RNG', 'se2': 'exosphere (Mariko)', 'pka1': 'exosphere (Mariko)',
    'fuse': 'exosphere fuse_api', 'pmc': 'exosphere scratch/powergate', 'mc': 'exosphere carveouts/SMMU (kernel via SMC)',
    'car': 'CPU reset/clocks', 'flow': 'CPU power / BPMP-halted wait', 'sb': 'CPU reset vector', 'evp': 'reset vectors',
    'sysctr0': 'CNTFID0 check', 'timer': 'TIMERUS/WDT/TIMER_SHARED', 'apb_misc': 'APB slave security',
    'pinmuxaux': 'UART pinmux (log_api)', 'ahb_gizmo': 'AHB arbitration security', 'actmon': 'activity monitor IRQ',
    'mselect': 'secmon_setup_warm', 'host1x': 'secmon_setup host1x security',
    'sdmmc': 'FS eMMC driver (SDMMC4)',
}
# Hardware Nintendo's boot sysmodule initializes (PMIC/charger/fuel gauge over I2C, GPIO, backlight PWM,
# display/DSI); allowed only for INI1 profiles that run it (Atmosphère's boot stops at bpc:ams before this).
ALLOWED_BOOT_HW = {'i2c': 'boot: PMIC/charger/fuel gauge', 'gpio': 'boot: GPIO config', 'pwm': 'boot: backlight',
                   'host1x_modules': 'boot: display (DC/DSI)', 'mipi_cal': 'boot: DSI pad calibration'}

# exosphere dispatches on the smc immediate (secmon_smc_handler.cpp): 1 = kernel table, 0 = user table.
SMC_NAMES = {
    (1, 0xC3000004): 'GetConfig', (1, 0xC3000005): 'GenerateRandomBytes', (1, 0xC3000006): 'ShowError',
    (1, 0xC3000007): 'ConfigureCarveout', (1, 0xC3000008): 'ReadWriteRegister', (1, 0xC3000409): 'SetConfig',
    (1, 0xC4000001): 'CpuSuspend', (1, 0x84000002): 'CpuOff', (1, 0xC4000003): 'CpuOn',
    (0, 0xC3000401): 'SetConfig', (0, 0xC3000002): 'GetConfig', (0, 0xC3000003): 'GetResult',
    (0, 0xC3000404): 'GetResultData', (0, 0xC3000E05): 'ModularExponentiate', (0, 0xC3000006): 'GenerateRandomBytes',
    (0, 0xC3000007): 'GenerateAesKek', (0, 0xC3000008): 'LoadAesKey', (0, 0xC3000009): 'ComputeAes',
    (0, 0xC300000A): 'GenerateSpecificAesKey', (0, 0xC300040B): 'ComputeCmac',
    (0, 0xC300D60C): 'ReencryptDeviceUniqueData', (0, 0xC300100D): 'DecryptDeviceUniqueData',
    (0, 0xC300060F): 'ModularExponentiateByStorageKey', (0, 0xC3000610): 'PrepareEsDeviceUniqueKey',
    (0, 0xC3000011): 'LoadPreparedAesKey', (0, 0xC3000012): 'PrepareEsCommonTitleKey',
}
SMC_ARGS_PUBLIC = {k for k in SMC_NAMES if k[0] == 1} | {(0, 0xC3000002), (0, 0xC3000401)}   # = hvmtrace.c
SMC_RESULTS_PUBLIC = SMC_ARGS_PUBLIC - {(1, 0xC3000005)}
SMC_ARG_REGS_PUBLIC = {(0, 0xC3000007): {3, 4}}   # GenerateAesKek generation / option flags (= hvmtrace.c)
SECRET_RANGES = [(0x70012000, 0x70014000), (0x70412000, 0x70414000), (0x70420000, 0x70430000)]

# sm: commands (tipc: message type = 16 + id; also valid as CMIF ids), sm_user_service.hpp / sm_ams.
SM_COMMANDS = {0: 'RegisterClient', 1: 'GetServiceHandle', 2: 'RegisterService', 3: 'UnregisterService',
               4: 'DetachClient', 65000: 'AtmosphereInstallMitm', 65001: 'AtmosphereUninstallMitm',
               65003: 'AtmosphereAcknowledgeMitmSession', 65004: 'AtmosphereHasMitm', 65005: 'AtmosphereWaitMitm',
               65006: 'AtmosphereDeclareFutureMitm', 65007: 'AtmosphereClearFutureMitm',
               65100: 'AtmosphereHasService', 65101: 'AtmosphereWaitService'}
SM_NAMED = {1, 2, 3, 65000, 65001, 65004, 65005, 65006, 65007, 65100, 65101}

# Exceptions expected in normal operation: IRQs, SVCs from EL0, SMCs from the kernel, lazy-FPU traps
# (EC 0x7, kern_exception_handlers_asm.s FpuAccessExceptionHandler) and the SE interrupt, a group 0 FIQ
# that exosphere takes at EL3 on core 3 for asynchronous user SMCs (secmon_setup.cpp SecurityEngineInterruptId).
EXC_ALLOWED = {('IRQ', 'EL0', 'EL1'), ('IRQ', 'EL1', 'EL1'), ('SVC', 'EL0', 'EL1'),
               ('Secure Monitor Call', 'EL1', 'EL3'), ('FIQ', 'EL0', 'EL3'), ('FIQ', 'EL1', 'EL3')}
EC_FP_ACCESS = 0x7
# Kernel panics, kernel dumps of crashed user processes, svc::Break, and stratosphere aborts/asserts
# (diag_default_abort_observer.cpp: "<reason>: '<expr>' in <func>, process=0x..").
UART_BAD = re.compile(r"Kernel Panic|Exception occurred|svc::Break|: '[^'\n]*' in \S+, process=0x")

SMC_RE = re.compile(r'^(smc|smc_ret) cpu=(\d+) el=(\d+) pc=0x([0-9a-f]+) imm=(\d+) id=0x([0-9a-f]+)(.*)$')
SVC_RE = re.compile(r'^(svc|svc_ret) cpu=(\d+) pid=(\d+) tls=0x([0-9a-f]+) pc=0x[0-9a-f]+ id=0x([0-9a-f]+)(.*)$')
MMIO_RE = re.compile(r'^mmio cpu=(\d+) pc=0x[0-9a-f]+ ([RW]) addr=0x([0-9a-f]+) size=\d+ val=(\S+)$')
EXC_RE = re.compile(r'Taking exception \d+ \[([^\]]+)\] on CPU \d+\n\.\.\.from (EL\d) to (EL\d)\n'
                    r'(?:\.\.\.with ESR 0x([0-9a-f]+)/)?')
REGS_RE = re.compile(r' x(\d)=(\S+)')
PROC_RE = re.compile(r'KProcess::Run\(\) pid=(\d+) name=(\S+)')


def load_svc_names(path=SVC_HEADER):
    names = {}
    if os.path.exists(path):
        with open(path) as f:
            for m in re.finditer(r'HANDLER\((0x[0-9A-Fa-f]+),\s*[\w:]+,\s*(\w+)', f.read()):
                names.setdefault(int(m.group(1), 16), m.group(2))
    return names


SVC_NAMES = load_svc_names()


def device_of(addr):
    for start, size, name in DEVICES:
        if start <= addr < start + size:
            return name
    return 'unknown@%#x' % (addr & ~0xFFF)


def decode_sm(msg):
    """Decode a tipc or CMIF request to sm: -> (command name, service name or None)."""
    words = struct.unpack_from('<4I', msg)
    mtype, special = words[0] & 0xFFFF, words[1] >> 31
    off = 8
    if special:
        sh = words[2]
        off += 4 + (8 if sh & 1 else 0) + 4 * (((sh >> 1) & 0xF) + ((sh >> 5) & 0xF))
    if mtype >= 16:                                  # tipc
        cmd = mtype - 16
    elif mtype in (4, 6):                            # CMIF request: 16-byte aligned "SFCI" header
        off = (off + 15) & ~15
        if msg[off:off + 4] != b'SFCI':
            return 'cmif?', None
        cmd = struct.unpack_from('<I', msg, off + 8)[0]
        off += 16
    else:
        return 'type%d' % mtype, None
    name = None
    if cmd in SM_NAMED and off + 8 <= len(msg):
        name = msg[off:off + 8].split(b'\0')[0].decode('latin-1')
    return SM_COMMANDS.get(cmd, 'cmd%d' % cmd), name


def decode_sm_reply(msg):
    """First moved handle of a reply from sm (GetServiceHandle / RegisterService)."""
    w1, sh = struct.unpack_from('<II', msg, 4)
    if not w1 >> 31 or not (sh >> 5) & 0xF:
        return None
    off = 12 + (8 if sh & 1 else 0) + 4 * ((sh >> 1) & 0xF)
    return struct.unpack_from('<I', msg, off)[0]


def result_str(rc):
    """Horizon result code as 2MMM-DDDD (module, description)."""
    return '2%03d-%04d' % (rc & 0x1FF, (rc >> 9) & 0x1FFF)


def regs_of(rest):
    return dict((int(i), v) for i, v in REGS_RE.findall(rest))


def analyze(trace_path, qemu_log_path=None, uart_path=None, allowed=ALLOWED):
    smc, smc_ret, smc_el, mmio = collections.Counter(), collections.Counter(), collections.Counter(), {}
    user_smc, user_smc_cores, leaks = [], collections.Counter(), []
    svc = collections.Counter()
    ports, registered, lookups = [], [], []
    pending = {}          # (pid, tls) -> (svc id, description) of the last call without a return yet
    last_call = {}
    handles = {}          # (pid, handle) -> service name, from sm replies
    ipc_calls = {}        # (pid, tls) -> (service, command) of an outstanding SendSyncRequest
    ipc_failures = collections.Counter()   # (pid, service, command, result) -> count
    with open(trace_path, errors='replace') as f:
        for line in f:
            m = SVC_RE.match(line)
            if m:
                kind, _, pid, tls, sid, rest = m.groups()
                pid, sid, key = int(pid), int(sid, 16), (int(pid), tls)
                if kind == 'svc':
                    svc[(pid, sid)] += 1
                    desc = SVC_NAMES.get(sid, 'svc%#x' % sid)
                    nm = re.search(r' name=(\S*)', rest)
                    if nm:
                        ports.append((pid, desc, nm.group(1)))
                        desc += '(%s)' % nm.group(1)
                    ipc = re.search(r' ipc=(\w+):(\d+)', rest)
                    if ipc:
                        regs = regs_of(rest)
                        h = int(regs[0 if sid == 0x21 else 2], 16)
                        service = handles.get((pid, h), 'h%#x' % h)
                        ipc_calls[key] = (service, int(ipc.group(2)))
                        desc = 'ipc %s cmd %s' % (service, ipc.group(2))
                    sm_msg = re.search(r' sm_msg=([0-9a-f]+)', rest)
                    if sm_msg:
                        cmd, name = decode_sm(bytes.fromhex(sm_msg.group(1)))
                        desc = 'sm %s(%s)' % (cmd, name or '')
                        if cmd == 'RegisterService':
                            registered.append((pid, name))
                        elif cmd == 'GetServiceHandle':
                            lookups.append((pid, name))
                            ipc_calls[key] = ('sm:', 'GetServiceHandle', name)
                    pending[key] = (sid, desc)
                    last_call[key] = (sid, desc)
                else:
                    pending.pop(key, None)
                    call = ipc_calls.pop(key, None)
                    reply = re.search(r' sm_reply=([0-9a-f]+)', rest)
                    if call and len(call) == 3 and reply:
                        h = decode_sm_reply(bytes.fromhex(reply.group(1)))
                        if h is not None:
                            handles[(pid, h)] = call[2]
                    res = re.search(r' ipc_result=0x([0-9a-f]+)', rest)
                    if call and res and int(res.group(1), 16):
                        ipc_failures[(pid,) + tuple(call[:2]) + (int(res.group(1), 16),)] += 1
                continue
            m = SMC_RE.match(line)
            if m:
                kind, cpu, el, _, imm, sid, rest = m.groups()
                k = (int(imm), int(sid, 16))
                (smc if kind == 'smc' else smc_ret)[k] += 1
                regs = regs_of(rest)
                public = SMC_ARGS_PUBLIC if kind == 'smc' else SMC_RESULTS_PUBLIC
                open_regs = SMC_ARG_REGS_PUBLIC.get(k, set()) if kind == 'smc' else set()
                if k not in public and any(v != '<redacted>' for r, v in regs.items() if r not in open_regs):
                    leaks.append('%s %s not redacted' % (kind, SMC_NAMES.get(k, '%d/%#x' % k)))
                if kind == 'smc':
                    smc_el[int(el)] += 1
                    if k[0] == 0:
                        user_smc_cores[int(cpu)] += 1
                if k[0] == 0:
                    user_smc.append((kind, int(cpu), k[1], regs))
                continue
            m = MMIO_RE.match(line)
            if m:
                _, rw, addr, val = m.groups()
                addr = int(addr, 16)
                dev = device_of(addr)
                mmio.setdefault(dev, collections.Counter())[rw] += 1
                if any(a <= addr < b for a, b in SECRET_RANGES) and val != '<redacted>':
                    leaks.append('SE/PKA value not redacted at %#x' % addr)

    exc = collections.Counter()
    if qemu_log_path and os.path.exists(qemu_log_path):
        with open(qemu_log_path, errors='replace') as f:
            for name, frm, to, ec in EXC_RE.findall(f.read()):
                if name == 'Undefined Instruction' and ec and int(ec, 16) == EC_FP_ACCESS:
                    name = 'FP access'
                exc[(name, frm, to)] += 1

    procs, uart_bad = {}, []
    if uart_path and os.path.exists(uart_path):
        with open(uart_path, errors='replace') as f:
            uart = f.read()
        procs = {int(p): n for p, n in PROC_RE.findall(uart)}
        uart_bad = sorted({m.group(0) for m in UART_BAD.finditer(uart)})

    violations = []
    violations += ['unknown SMC imm=%d id=%#x' % k for k in smc if k not in SMC_NAMES]
    violations += ['SMC issued from EL%d' % el for el in smc_el if el != 1]
    violations += ['user SMC issued on core %d (exosphere requires core 3)' % c for c in user_smc_cores if c != 3]
    violations += ['MMIO to %s (not in allowlist)' % d for d in mmio if d not in allowed]
    violations += ['exception %s %s->%s' % e for e in exc
                   if e not in EXC_ALLOWED and e != ('FP access', 'EL0', 'EL1')]
    violations += ['UART: %s' % b for b in uart_bad]
    violations += sorted(set(leaks))
    return {'allowed': allowed, 'smc': smc, 'smc_ret': smc_ret, 'mmio': mmio, 'exc': exc, 'violations': violations,
            'svc': svc, 'procs': procs, 'ports': ports, 'registered': registered, 'lookups': lookups,
            'pending': pending, 'user_smc': user_smc, 'ipc_failures': ipc_failures}


def proc_name(r, pid):
    return r['procs'].get(pid, 'pid%d' % pid)


def report(r):
    print('== SMC (count / returned)')
    for k, n in sorted(r['smc'].items()):
        print('  %-26s imm=%d %#010x %6d / %d' % (SMC_NAMES.get(k, '?'), k[0], k[1], n, r['smc_ret'][k]))
    print('== MMIO per device (R / W)')
    for dev, c in sorted(r['mmio'].items(), key=lambda kv: -sum(kv[1].values())):
        print('  %-14s %7d / %-7d %s' % (dev, c['R'], c['W'], r['allowed'].get(dev, 'NOT ALLOWED')))
    print('== Exceptions')
    for (name, frm, to), n in sorted(r['exc'].items()):
        print('  %-22s %s->%s %d' % (name, frm, to, n))
    pids = sorted({p for p, _ in r['svc']} | set(r['procs']))
    if pids:
        print('== Processes')
    for pid in pids:
        calls = sum(n for (p, _), n in r['svc'].items() if p == pid)
        print('  %-12s pid=%-3d svc=%d' % (proc_name(r, pid), pid, calls))
        ports = collections.Counter((what, name) for p, what, name in r['ports'] if p == pid)
        for (what, name), n in ports.items():
            print('      %s(%s)%s' % (what, name, ' x%d' % n if n > 1 else ''))
        regs = [n for p, n in r['registered'] if p == pid]
        if regs:
            print('      registers: %s' % ' '.join(n or '?' for n in regs))
        looks = [n for p, n in r['lookups'] if p == pid]
        if looks:
            print('      looks up:  %s' % ' '.join(sorted({n or '?' for n in looks})))
        for (p, service, cmd, rc), n in sorted(r['ipc_failures'].items()):
            if p == pid:
                print('      ipc %s cmd %s -> %s%s' % (service, cmd, result_str(rc), ' x%d' % n if n > 1 else ''))
        for (p, tls), (_, desc) in sorted(r['pending'].items()):
            if p == pid:
                print('      thread tls=0x%s blocked in %s' % (tls, desc))
    print('== Checks: %s' % ('OK' if not r['violations'] else 'FAIL'))
    for v in r['violations']:
        print('  ' + v)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', default='erista')
    ap.add_argument('--boot-hw', action='store_true', help="also allow the hardware Nintendo's boot initializes")
    args = ap.parse_args()
    logs = os.path.join(os.environ.get('HORIZONVM_HOME', os.path.expanduser('~/.horizonvm')), 'logs')
    r = analyze(os.path.join(logs, 'hvmtrace-%s.log' % args.soc), os.path.join(logs, 'qemu-%s.log' % args.soc),
                os.path.join(logs, 'uart-%s.log' % args.soc), dict(ALLOWED, **ALLOWED_BOOT_HW) if args.boot_hw else ALLOWED)
    report(r)
    sys.exit(1 if r['violations'] else 0)


if __name__ == '__main__':
    main()
