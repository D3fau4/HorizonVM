"""GDB helpers for HorizonVM: Mesosphere symbols (physical + KASLR) and early-boot checkpoints.

Commands:
  hvm-trace [N]   run from reset, log checkpoints, stop once HorizonKernelMain ran on N cores
"""
import os
import struct

import gdb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MESO_DIR = os.path.join(ROOT, 'third_party/Atmosphere/mesosphere')
OUT = 'nintendo_nx_arm64_armv8a/debug'
KERNEL_ELF = os.path.join(MESO_DIR, 'kernel/out', OUT, 'kernel.elf')
LDR_ELF = os.path.join(MESO_DIR, 'kernel_ldr/out', OUT, 'kernel_ldr.elf')
MESO_BIN = os.path.join(MESO_DIR, 'out', OUT, 'mesosphere.bin')

KERNEL_PHYS = 0x80060000          # exosphere loads package2 payload 0 here (entrypoint 0x60000)
INI1_PHYS = 0x17F400000           # base + intended(4 GiB) - 12 MiB (KSystemControlBase::Init::GetInitialProcessBinaryLayout)

SYM = {
    'StartCore0': '_ZN3ams4kern4init10StartCore0Emm',
    'loader::Main': '_ZN3ams4kern4init6loader4MainEmPNS1_12KernelLayoutEm',
    'InitializeCorePhase1': '_ZN3ams4kern4init20InitializeCorePhase1EmPPv',
    'InitializeCorePhase2': '_ZN3ams4kern4init20InitializeCorePhase2Ev',
    'TurnOnCpu': '_ZN3ams4kern18KSystemControlBase4Init9TurnOnCpuEmPKNS0_4init14KInitArgumentsE',
    'CpuOnImpl': '_ZN3ams4kern5board8nintendo2nx14KSystemControl4Init9CpuOnImplEmmm',
    'StartOtherCore': '_ZN3ams4kern4init14StartOtherCoreEPKNS1_14KInitArgumentsE',
    'HorizonKernelMain': '_ZN3ams4kern17HorizonKernelMainEi',
}


def reg(name):
    return int(gdb.parse_and_eval('$' + name)) & 0xFFFFFFFFFFFFFFFF


def current_el():
    return (reg('cpsr') >> 2) & 3


def cpu_index():
    return gdb.selected_thread().num - 1


def link_addr(elf_sym, load_offset):
    """Link-time address of a symbol from an objfile added with `add-symbol-file -o load_offset`."""
    return (int(gdb.parse_and_eval("(unsigned long)&'%s'" % elf_sym)) - load_offset) & 0xFFFFFFFFFFFFFFFF


def ldr_phys_base():
    with open(MESO_BIN, 'rb') as f:
        m = f.read()
    meta = struct.unpack_from('<I', m, 8)[0]
    return KERNEL_PHYS + meta + 8 + struct.unpack_from('<q', m, meta + 8)[0]


def find_insn(start, count, pred):
    arch = gdb.selected_frame().architecture()
    for insn in arch.disassemble(start, count=count):
        if pred(insn['asm']):
            return insn['addr'] + insn['length']
    raise gdb.GdbError('instruction not found after 0x%x' % start)


class Checkpoint(gdb.Breakpoint):
    """Logs and continues (or stops when `stop_when` returns True)."""

    def __init__(self, label, addr, describe=None, stop_when=None):
        super().__init__('*0x%x' % addr, internal=True)
        self.label, self.describe, self.stop_when = label, describe, stop_when

    def stop(self):
        extra = self.describe() if self.describe else ''
        line = '[hvm] %-22s cpu%d EL%d %s' % (self.label, cpu_index(), current_el(), extra)
        gdb.write(line.rstrip() + '\n')
        return bool(self.stop_when and self.stop_when())


class HvmTrace(gdb.Command):
    def __init__(self):
        super().__init__('hvm-trace', gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        want_cores = int(arg.split()[-1]) if arg.strip() else 4
        gdb.execute('set pagination off')
        gdb.execute('set confirm off')

        # Phase 1: physical addresses (MMU off / identity map).
        gdb.execute('add-symbol-file %s -o 0x%x' % (KERNEL_ELF, KERNEL_PHYS), to_string=True)
        ldr = ldr_phys_base()
        gdb.execute('add-symbol-file %s -o 0x%x' % (LDR_ELF, ldr), to_string=True)
        start_core0 = KERNEL_PHYS + link_addr(SYM['StartCore0'], KERNEL_PHYS)
        ldr_main = ldr + link_addr(SYM['loader::Main'], ldr)
        virt_links = {k: link_addr(SYM[k], KERNEL_PHYS) for k in
                      ('InitializeCorePhase1', 'InitializeCorePhase2', 'TurnOnCpu', 'CpuOnImpl', 'HorizonKernelMain')}
        # The image is not in DRAM yet (exosphere copies it later): disassemble from the ELF files.
        gdb.execute('set trust-readonly-sections on')
        after_smc = find_insn(start_core0, 64, lambda a: a.startswith('smc'))
        after_main = find_insn(ldr, 128, lambda a: a.startswith('bl') and ('%x' % ldr_main) in a)
        gdb.execute('set trust-readonly-sections off')

        Checkpoint('_start', KERNEL_PHYS)
        Checkpoint('GetConfig(65000) ret', after_smc,
                   lambda: 'x0=%#x target_fw=%#x' % (reg('x0'), reg('x1') & 0xFFFFFFFF))
        Checkpoint('loader::Main', ldr_main, lambda: 'kernel_base=%#x ini1=%#x' % (reg('x0'), reg('x2')))
        slide_bp = gdb.Breakpoint('*0x%x' % after_main, internal=True)
        gdb.execute('continue')
        slide = reg('x0')
        slide_bp.delete()
        virt_base = (KERNEL_PHYS + slide) & 0xFFFFFFFFFFFFFFFF
        gdb.write('[hvm] %-22s cpu%d EL%d kaslr virt_base=%#x\n' % ('loader::Main ret', cpu_index(), current_el(), virt_base))

        # Phase 2: kernel virtual addresses.
        gdb.execute('add-symbol-file %s -o 0x%x' % (KERNEL_ELF, virt_base), to_string=True)
        cores = set()

        def main_seen():
            cores.add(cpu_index())
            return len(cores) >= want_cores

        Checkpoint('InitializeCorePhase1', virt_base + virt_links['InitializeCorePhase1'])
        Checkpoint('InitializeCorePhase2', virt_base + virt_links['InitializeCorePhase2'])
        Checkpoint('TurnOnCpu', virt_base + virt_links['TurnOnCpu'], lambda: 'target=%#x' % reg('x0'))
        Checkpoint('CpuOnImpl (smc #1)', virt_base + virt_links['CpuOnImpl'],
                   lambda: 'core=%#x entry=%#x arg=%#x' % (reg('x0'), reg('x1'), reg('x2')))
        Checkpoint('HorizonKernelMain', virt_base + virt_links['HorizonKernelMain'],
                   lambda: 'core_id=%d' % reg('x0'), stop_when=main_seen)
        gdb.execute('continue')

        ini = gdb.execute('monitor xp /4wx 0x%x' % INI1_PHYS, to_string=True).strip()
        gdb.write('[hvm] INI1 @%#x: %s\n' % (INI1_PHYS, ini.split(':', 1)[-1].strip()))
        gdb.write('[hvm] HorizonKernelMain cores: %s\n' % sorted(cores))


HvmTrace()
