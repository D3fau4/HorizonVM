#!/usr/bin/env python3
"""Summarize and check a HorizonVM trace (hvmtrace plugin log + QEMU -d int log)."""
import argparse
import collections
import os
import re
import sys

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
    (0x700F0000, 0x10000, 'sysctr0'), (0x70100000, 0x10000, 'sysctr1'), (0x70412000, 0x2000, 'se2'),
    (0x70420000, 0x10000, 'pka1'),
]

# Devices exosphere + the NX kernel are expected to touch during early boot (and why).
ALLOWED = {
    'gic_dist': 'kernel/exosphere GICv2', 'gic_cpu': 'kernel/exosphere GICv2', 'uart': 'exosphere + KDebugLog',
    'se': 'exosphere crypto/RNG', 'se2': 'exosphere (Mariko)', 'pka1': 'exosphere (Mariko)',
    'fuse': 'exosphere fuse_api', 'pmc': 'exosphere scratch/powergate', 'mc': 'exosphere carveouts/SMMU (kernel via SMC)',
    'car': 'CPU reset/clocks', 'flow': 'CPU power / BPMP-halted wait', 'sb': 'CPU reset vector', 'evp': 'reset vectors',
    'sysctr0': 'CNTFID0 check', 'timer': 'TIMERUS/WDT/TIMER_SHARED', 'apb_misc': 'APB slave security',
    'pinmuxaux': 'UART pinmux (log_api)', 'ahb_gizmo': 'AHB arbitration security', 'actmon': 'activity monitor IRQ',
    'mselect': 'secmon_setup_warm', 'host1x': 'secmon_setup host1x security',
}

# Kernel (smc #1) calls of the NX board (kern_secure_monitor.cpp) and PSCI.
SMC_NAMES = {
    0xC3000004: 'GetConfig', 0xC3000005: 'GenerateRandomBytes', 0xC3000006: 'ShowError',
    0xC3000007: 'ConfigureCarveout', 0xC3000008: 'ReadWriteRegister', 0xC3000409: 'SetConfig',
    0xC4000001: 'CpuSuspend', 0x84000002: 'CpuOff', 0xC4000003: 'CpuOn',
}
SECRET_RANGES = [(0x70012000, 0x70014000), (0x70412000, 0x70414000), (0x70420000, 0x70430000)]

SMC_RE = re.compile(r'^(smc|smc_ret) cpu=(\d+) el=(\d+) pc=0x([0-9a-f]+) id=0x([0-9a-f]+)(.*)$')
MMIO_RE = re.compile(r'^mmio cpu=(\d+) pc=0x[0-9a-f]+ ([RW]) addr=0x([0-9a-f]+) size=\d+ val=(\S+)$')
EXC_RE = re.compile(r'Taking exception \d+ \[([^\]]+)\] on CPU \d+\n\.\.\.from (EL\d) to (EL\d)')


def device_of(addr):
    for start, size, name in DEVICES:
        if start <= addr < start + size:
            return name
    return 'unknown@%#x' % (addr & ~0xFFF)


def analyze(trace_path, qemu_log_path=None):
    smc, smc_ret, smc_el, mmio = collections.Counter(), collections.Counter(), collections.Counter(), {}
    leaks = []
    with open(trace_path, errors='replace') as f:
        for line in f:
            m = SMC_RE.match(line)
            if m:
                kind, _, el, _, sid, rest = m.groups()
                sid = int(sid, 16)
                (smc if kind == 'smc' else smc_ret)[sid] += 1
                if kind == 'smc':
                    smc_el[int(el)] += 1
                if kind == 'smc_ret' and sid == 0xC3000005 and '<redacted>' not in rest:
                    leaks.append('RNG result not redacted')
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
            exc.update(EXC_RE.findall(f.read()))

    violations = []
    violations += ['unknown SMC id %#x' % i for i in smc if i not in SMC_NAMES]
    violations += ['SMC issued from EL%d' % el for el in smc_el if el != 1]
    violations += ['MMIO to %s (not in allowlist)' % d for d in mmio if d not in ALLOWED]
    violations += ['exception %s %s->%s' % e for e in exc if e[2] == 'EL2' or e[0] not in ('IRQ', 'Secure Monitor Call')]
    violations += sorted(set(leaks))
    return {'smc': smc, 'smc_ret': smc_ret, 'mmio': mmio, 'exc': exc, 'violations': violations}


def report(r):
    print('== SMC (count / returned)')
    for sid, n in sorted(r['smc'].items()):
        print('  %-20s %#010x %6d / %d' % (SMC_NAMES.get(sid, '?'), sid, n, r['smc_ret'][sid]))
    print('== MMIO per device (R / W)')
    for dev, c in sorted(r['mmio'].items(), key=lambda kv: -sum(kv[1].values())):
        print('  %-14s %7d / %-7d %s' % (dev, c['R'], c['W'], ALLOWED.get(dev, 'NOT ALLOWED')))
    print('== Exceptions')
    for (name, frm, to), n in sorted(r['exc'].items()):
        print('  %-22s %s->%s %d' % (name, frm, to, n))
    print('== Checks: %s' % ('OK' if not r['violations'] else 'FAIL'))
    for v in r['violations']:
        print('  ' + v)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', default='erista')
    args = ap.parse_args()
    logs = os.path.join(os.environ.get('HORIZONVM_HOME', os.path.expanduser('~/.horizonvm')), 'logs')
    r = analyze(os.path.join(logs, 'hvmtrace-%s.log' % args.soc), os.path.join(logs, 'qemu-%s.log' % args.soc))
    report(r)
    sys.exit(1 if r['violations'] else 0)


if __name__ == '__main__':
    main()
