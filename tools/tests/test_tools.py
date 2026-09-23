import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import hvm_log  # noqa: E402
import mkexo0   # noqa: E402
import mkfuses  # noqa: E402
import mkpkg2   # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
AMS = os.path.join(ROOT, 'third_party', 'Atmosphere')
MESO = os.path.join(AMS, 'mesosphere/out/nintendo_nx_arm64_armv8a/debug/mesosphere.bin')
GXX = os.path.join(os.environ.get('DEVKITPRO', '/opt/devkitpro'), 'devkitA64/bin/aarch64-none-elf-g++')
FW = os.environ.get('HVM_FW', '')
FW_INI1 = os.path.join(FW, 'Processed/BootImagePackage/romfs/nx/package2.storage/INI1.bin')
AMS_KIPS = [os.path.join(AMS, 'stratosphere/%s/out/nintendo_nx_arm64_armv8a/debug/%s.kip' % (m, m))
            for m in ('sm', 'spl', 'pm', 'loader', 'ncm', 'boot')]


def read(path):
    with open(path, 'rb') as f:
        return f.read()


def fake_meso(size=0x3000, meta_offset=0x800):
    m = bytearray(size)
    m[4:8] = b'MSS1'
    struct.pack_into('<I', m, 8, meta_offset)
    return bytes(m)


def fake_kip(program_id, size=0x200, caps=()):
    k = bytearray(size)
    k[0:4] = b'KIP1'
    struct.pack_into('<Q', k, 0x10, program_id)
    struct.pack_into('<I', k, 0x28, size - 0x100)
    struct.pack_into('<32I', k, 0x80, *(list(caps) + [0xFFFFFFFF] * (32 - len(caps))))
    return bytes(k)


def compile_check(src, *includes):
    """Compile static_asserts against Atmosphère headers with devkitA64 (syntax only)."""
    cmd = [GXX, '-std=gnu++23', '-fsyntax-only', '-fno-rtti', '-fno-exceptions', '-x', 'c++', '-',
           '-D__SWITCH__', '-DATMOSPHERE', '-DATMOSPHERE_ARCH_ARM64', '-DATMOSPHERE_BOARD_NINTENDO_NX',
           '-DATMOSPHERE_OS_HORIZON', '-DATMOSPHERE_CPU_ARM_CORTEX_A57', '-DATMOSPHERE_ARCH_ARM_V8A',
           '-DATMOSPHERE_IS_EXOSPHERE', '-I' + os.path.join(AMS, 'libraries/libvapours/include'),
           '-I' + os.path.join(AMS, 'libraries/libexosphere/include')] + ['-I' + i for i in includes]
    return subprocess.run(cmd, input=src, capture_output=True, text=True)


class TestMkpkg2(unittest.TestCase):
    def check_layout(self, meso, kips):
        pkg2 = mkpkg2.build_package2(meso, kips)
        self.assertTrue(mkpkg2.verify_package2(pkg2))
        payload = pkg2[0x200:]
        meta_offset = struct.unpack_from('<I', meso, 8)[0]
        ini_rel = struct.unpack_from('<q', payload, meta_offset)[0]
        ini_off = meta_offset + ini_rel
        self.assertEqual(ini_off, len(meso))
        magic, size, count, _ = struct.unpack_from('<4sIII', payload, ini_off)
        self.assertEqual((magic, count), (b'INI1', len(kips)))
        self.assertEqual(size, 0x10 + sum(len(k) for k in kips))
        return pkg2

    def test_empty_ini(self):
        self.check_layout(fake_meso(), [])

    def test_with_kips(self):
        self.check_layout(fake_meso(), [fake_kip(0x0100000000000004), fake_kip(0x0100000000000003)])

    def test_duplicate_kip_rejected(self):
        with self.assertRaises(ValueError):
            mkpkg2.build_package2(fake_meso(), [fake_kip(1), fake_kip(1)])

    def test_rejects_non_mesosphere(self):
        with self.assertRaises(ValueError):
            mkpkg2.build_package2(bytes(0x1000))

    def test_verifier_catches_corruption(self):
        good = mkpkg2.build_package2(fake_meso())
        for off, val in ((0x150, 0), (0x15D, 0x18), (0x154, 0x10000000), (0x100, 0x1234)):
            bad = bytearray(good)
            if off == 0x154 or off == 0x100:
                struct.pack_into('<I', bad, off, val)
            else:
                bad[off] = val
            self.assertFalse(mkpkg2.verify_package2(bytes(bad)), hex(off))

    def test_ini1_roundtrip(self):
        kips = [fake_kip(0x0100000000000004, 0x300), fake_kip(0x0100000000000028, 0x180)]
        self.assertEqual(mkpkg2.split_ini1(mkpkg2.build_ini1(kips)), kips)

    def test_kip_capabilities_checked(self):
        for caps in ([0], [(0x3F << 16) | 0x7], [0x1F]):     # zero slot, CorePriority, unknown type
            with self.assertRaises(ValueError):
                mkpkg2.build_ini1([fake_kip(1, caps=caps)])
        mkpkg2.build_ini1([fake_kip(1, caps=[0x0000000F, 0x00083FFF])])   # SyscallMask, KernelVersion

    @unittest.skipUnless(os.path.exists(FW_INI1), 'HVM_FW not set')
    def test_official_ini1(self):
        kips = mkpkg2.split_ini1(read(FW_INI1))
        self.assertEqual(len(kips), 7)
        mkpkg2.build_ini1(kips)

    @unittest.skipUnless(all(map(os.path.exists, AMS_KIPS)), 'stratosphere KIPs not built')
    def test_atmosphere_kips(self):
        mkpkg2.build_ini1([read(k) for k in AMS_KIPS])

    @unittest.skipUnless(os.path.exists(MESO), 'mesosphere.bin not built')
    def test_real_mesosphere(self):
        pkg2 = self.check_layout(read(MESO), [])
        self.assertEqual(struct.unpack_from('<I', pkg2, 0x154)[0], 0x60000)


def read_reg(cache, off):
    return struct.unpack_from('<I', cache, off - mkfuses.CACHE_START)[0]


class TestMkfuses(unittest.TestCase):
    ECID = {'vendor': 0xA, 'fab': 0x2A, 'lot0': 0xDEADBEEF, 'lot1': 0x0ABCDEF,
            'wafer': 0x15, 'x': 0x123, 'y': 0x0F0, 'reserved': 0x3}

    def decode(self, cache):
        """Port of fuse_api.cpp GetHardwareType/GetHardwareState/GetDramId/GetSocType/IsNewFuseFormat."""
        w = read_reg(cache, mkfuses.FUSE_RESERVED_ODM0 + 16)
        bit = lambda lo, n: (w >> lo) & ((1 << n) - 1)
        hw_type = bit(2, 1) | (bit(8, 1) << 1) | (bit(16, 4) << 2)
        state = bit(0, 2) | (bit(9, 1) << 2)
        dram = bit(3, 5) | (bit(12, 3) << 5)
        name = {0x01: 'Icosa', 0x02: 'Calcio', 0x04: 'Iowa', 0x08: 'Hoag', 0x10: 'Aula'}.get(hw_type, 'Undefined')
        soc = 'erista' if name == 'Icosa' else ('mariko' if name != 'Undefined' else None)
        new_fmt = bit(11, 1) == 1 and (read_reg(cache, 0x1C8), read_reg(cache, 0x1CC)) == mkfuses.NEW_FUSE_FORMAT_MAGIC
        return name, soc, {3: 'Development', 4: 'Production'}.get(state), dram, new_fmt

    def test_profiles(self):
        for soc, (name, dram) in {'erista': ('Icosa', 0), 'mariko': ('Iowa', 3)}.items():
            cache = mkfuses.build_fuse_cache(soc, self.ECID)
            self.assertEqual(len(cache), 0x400 - 0x1C8)
            self.assertEqual(self.decode(cache), (name, soc, 'Production', dram, True))

    def test_ecid_placement(self):
        cache = mkfuses.build_fuse_cache('erista', self.ECID)
        for field, (off, _) in mkfuses.ECID_FIELDS.items():
            self.assertEqual(read_reg(cache, off), self.ECID[field], field)

    def test_ecid_persisted(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, 'ecid.json')
            self.assertEqual(mkfuses.load_or_create_ecid(p), mkfuses.load_or_create_ecid(p))
        finally:
            shutil.rmtree(d)

    @unittest.skipUnless(os.path.exists(GXX), 'devkitA64 not available')
    def test_offsets_match_atmosphere(self):
        fields = {'chip_common.FUSE_RESERVED_ODM_0': mkfuses.FUSE_RESERVED_ODM0,
                  'chip_common.FUSE_OPT_VENDOR_CODE': mkfuses.FUSE_OPT_VENDOR_CODE,
                  'chip_common.FUSE_OPT_FAB_CODE': mkfuses.FUSE_OPT_FAB_CODE,
                  'chip_common.FUSE_OPT_LOT_CODE_0': mkfuses.FUSE_OPT_LOT_CODE_0,
                  'chip_common.FUSE_OPT_LOT_CODE_1': mkfuses.FUSE_OPT_LOT_CODE_1,
                  'chip_common.FUSE_OPT_WAFER_ID': mkfuses.FUSE_OPT_WAFER_ID,
                  'chip_common.FUSE_OPT_X_COORDINATE': mkfuses.FUSE_OPT_X_COORDINATE,
                  'chip_common.FUSE_OPT_Y_COORDINATE': mkfuses.FUSE_OPT_Y_COORDINATE,
                  'chip_common.FUSE_OPT_OPS_RESERVED': mkfuses.FUSE_OPT_OPS_RESERVED}
        src = '#include <exosphere.hpp>\n#include "fuse_registers.hpp"\n#include <cstddef>\n'
        src += ''.join('static_assert(offsetof(ams::fuse::FuseRegisterRegion, %s) == 0x%x);\n' % kv for kv in fields.items())
        r = compile_check(src, os.path.join(AMS, 'libraries/libexosphere/source/fuse'))
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])


class TestMkexo0(unittest.TestCase):
    def test_contents(self):
        cfg = mkexo0.build_exo0()
        self.assertEqual(len(cfg), mkexo0.EXO0_SIZE)
        magic, tf, f0, f1 = struct.unpack_from('<4sIII', cfg, 0)
        self.assertEqual((magic, tf, f0, f1), (b'EXO0', 0x16050000, 0b1010, 0))
        self.assertEqual(struct.unpack_from('<I', mkexo0.build_exo0(user_exception_handlers=True), 8)[0], 0b10)
        self.assertEqual(struct.unpack_from('<I', cfg, mkexo0.OFFSETS['log_baud_rate'])[0], 115200)

    @unittest.skipUnless(os.path.exists(GXX), 'devkitA64 not available')
    def test_layout_matches_atmosphere(self):
        t = 'ams::secmon::SecureMonitorStorageConfiguration'
        src = '#include <exosphere.hpp>\n#include <cstddef>\n'
        src += ''.join('static_assert(offsetof(%s, %s) == 0x%x);\n' % (t, f, o) for f, o in mkexo0.OFFSETS.items())
        src += 'static_assert(sizeof(%s) == 0x%x);\n' % (t, mkexo0.EXO0_SIZE)
        src += 'static_assert(%s::Magic == 0x%08x);\n' % (t, struct.unpack('<I', b'EXO0')[0])
        src += 'static_assert(static_cast<unsigned>(ams::TargetFirmware_Current) == 0x%x);\n' % mkexo0.TARGET_FIRMWARE_22_5_0
        src += 'static_assert(ams::secmon::MemoryRegionPhysicalDramMonitorConfiguration.GetAddress() == 0x%x);\n' % mkexo0.EXO0_ADDRESS
        for name, val in (('IsDevelopmentFunctionEnabledForKernel', mkexo0.FLAG_DEVFN_KERNEL),
                          ('DisableUserModeExceptionHandlers', mkexo0.FLAG_DISABLE_USER_EXCEPTION_HANDLERS)):
            src += 'static_assert(ams::secmon::SecureMonitorConfigurationFlag_%s == 0x%x);\n' % (name, val)
        r = compile_check(src)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])


class TestHvmKeys(unittest.TestCase):
    MASTER = '00112233445566778899aabbccddeeff'
    KEK = 'ffeeddccbbaa99887766554433221100'

    def run_tool(self, soc, ident, keys):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'tools/hvm_keys.py'), '--soc', soc,
                               '--prod-keys', keys, '--identity', ident], capture_output=True, text=True, check=True)

    def test_profiles_and_identity(self):
        d = tempfile.mkdtemp()
        try:
            keys = os.path.join(d, 'prod.keys')
            with open(keys, 'w') as f:
                f.write('master_key_15 = %s\nmariko_kek = %s\n' % (self.MASTER, self.KEK))
            for soc, slots in (('erista', (10, 12, 13, 15)), ('mariko', (12, 14))):
                ident = os.path.join(d, soc)
                out1 = self.run_tool(soc, ident, keys)
                files = {s: os.path.join(ident, 'aeskeyslot%d.bin' % s) for s in slots}
                first = {s: read(p) for s, p in files.items()}
                out2 = self.run_tool(soc, ident, keys)
                self.assertEqual(first, {s: read(p) for s, p in files.items()}, 'identity must persist')
                self.assertEqual(stat.S_IMODE(os.stat(ident).st_mode), 0o700)
                for p in files.values():
                    self.assertEqual(os.path.getsize(p), 16)
                    self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
                for out in (out1, out2):
                    self.assertNotIn(self.MASTER, out.stdout + out.stderr)
                    self.assertNotIn(self.KEK, out.stdout + out.stderr)
            self.assertEqual(read(os.path.join(d, 'erista/aeskeyslot13.bin')), bytes.fromhex(self.MASTER))
            self.assertEqual(read(os.path.join(d, 'mariko/aeskeyslot12.bin')), bytes.fromhex(self.KEK))
        finally:
            shutil.rmtree(d)


def tipc(cmd, name=b'', pid=False):
    """A tipc request as it sits in TLS (sm_msg dump)."""
    words = [16 + cmd, (1 << 31) if pid else 0]
    body = struct.pack('<II', *words)
    if pid:
        body += struct.pack('<IQ', 1, 0x55)
    return (body + name.ljust(8, b'\0')).ljust(0x30, b'\0')


class TestHvmLog(unittest.TestCase):
    GOOD = ('smc cpu=0 el=1 pc=0x800c3048 imm=1 id=0xc4000003 x1=0x1 x2=0x800d1200 x3=0x0 x4=0x0 x5=0x0 x6=0x0 x7=0x0\n'
            'smc_ret cpu=0 el=1 pc=0x800c304c imm=1 id=0xc4000003 x0=0x0 x1=0x1 x2=0x0 x3=0x0\n'
            'smc_ret cpu=0 el=1 pc=0x800c304c imm=1 id=0xc3000005 x0=<redacted> x1=<redacted> x2=<redacted> x3=<redacted>\n'
            'smc cpu=3 el=1 pc=0x800c3100 imm=0 id=0xc3000002 x1=0xfde8 x2=0x0 x3=0x0 x4=0x0 x5=0x0 x6=0x0 x7=0x0\n'
            'smc_ret cpu=3 el=1 pc=0x800c3104 imm=0 id=0xc3000002 x0=0x7 x1=0x0 x2=0x0 x3=0x0\n'
            'smc cpu=3 el=1 pc=0x800c3100 imm=0 id=0xc3000006 x1=<redacted> x2=<redacted> x3=<redacted> '
            'x4=<redacted> x5=<redacted> x6=<redacted> x7=<redacted>\n'
            'mmio cpu=0 pc=0x1f0000000 W addr=0x50041100 size=4 val=0xffffffff\n'
            'mmio cpu=0 pc=0x1f0000000 W addr=0x70012300 size=4 val=<redacted>\n')
    QEMU = ('Taking exception 5 [IRQ] on CPU 0\n...from EL1 to EL1\n...with ESR 0x15/0x56000000\n'
            'Taking exception 2 [SVC] on CPU 3\n...from EL0 to EL1\n...with ESR 0x15/0x5600001f\n'
            'Taking exception 1 [Undefined Instruction] on CPU 3\n...from EL0 to EL1\n...with ESR 0x7/0x1fe00000\n')
    UART = 'KProcess::Run() pid=1 name=sm           thread=1\nKProcess::Run() pid=2 name=spl          thread=2\n'

    def analyze(self, trace, qemu=QEMU, uart=UART):
        d = tempfile.mkdtemp()
        try:
            t, q, u = os.path.join(d, 't'), os.path.join(d, 'q'), os.path.join(d, 'u')
            for path, text in ((t, trace), (q, qemu), (u, uart)):
                with open(path, 'w') as f:
                    f.write(text)
            return hvm_log.analyze(t, q, u)
        finally:
            shutil.rmtree(d)

    def test_clean_trace(self):
        r = self.analyze(self.GOOD)
        self.assertEqual(r['violations'], [])
        self.assertEqual(r['smc'][(1, 0xC4000003)], 1)
        self.assertEqual(r['smc'][(0, 0xC3000002)], 1)
        self.assertEqual(r['mmio']['gic_dist']['W'], 1)
        self.assertEqual(r['exc'][('FP access', 'EL0', 'EL1')], 1)
        self.assertEqual(r['procs'], {1: 'sm', 2: 'spl'})

    def test_svc_and_sm(self):
        trace = ('svc cpu=3 pid=1 tls=0x1000 pc=0x100 id=0x71 x0=0x0 x1=0x2000 x2=0x40 x3=0x0 name=sm:\n'
                 'svc_ret cpu=3 pid=1 tls=0x1000 pc=0x104 id=0x71 x0=0x0 x1=0xd000 x2=0x0 x3=0x0\n'
                 'svc cpu=3 pid=1 tls=0x1000 pc=0x200 id=0x43 x0=0x0 x1=0x3000 x2=0x1 x3=0x0\n'
                 'svc cpu=3 pid=2 tls=0x9000 pc=0x300 id=0x21 x0=0xd001 x1=0x0 x2=0x0 x3=0x0 sm_msg=%s\n'
                 'svc_ret cpu=3 pid=2 tls=0x9000 pc=0x304 id=0x21 x0=0x0 x1=0x0 x2=0x0 x3=0x0\n'
                 'svc cpu=3 pid=2 tls=0x9000 pc=0x300 id=0x21 x0=0xd001 x1=0x0 x2=0x0 x3=0x0 sm_msg=%s\n'
                 % (tipc(2, b'spl:').hex(), tipc(1, b'fsp-pr').hex()))
        r = self.analyze(trace)
        self.assertEqual(r['violations'], [])
        self.assertEqual(r['ports'], [(1, 'ManageNamedPort', 'sm:')])
        self.assertEqual(r['registered'], [(2, 'spl:')])
        self.assertEqual(r['lookups'], [(2, 'fsp-pr')])
        blocked = {k: v[1] for k, v in r['pending'].items()}
        self.assertEqual(blocked, {(1, '1000'): 'ReplyAndReceive', (2, '9000'): 'sm GetServiceHandle(fsp-pr)'})
        self.assertEqual(hvm_log.decode_sm(tipc(0, pid=True)), ('RegisterClient', None))

    def test_violations(self):
        cases = {
            'mmio cpu=0 pc=0x0 W addr=0x57000000 size=4 val=0x1\n': 'gpu',
            'mmio cpu=0 pc=0x0 W addr=0x70012300 size=4 val=0x1234\n': 'not redacted',
            'smc cpu=0 el=1 pc=0x0 imm=1 id=0xc3000002 x1=<redacted>\n': 'unknown SMC',
            'smc_ret cpu=0 el=1 pc=0x0 imm=1 id=0xc3000005 x0=0x0 x1=0x5\n': 'not redacted',
            'smc cpu=3 el=1 pc=0x0 imm=0 id=0xc3000007 x1=0x1234 x2=<redacted>\n': 'GenerateAesKek not redacted',
            'smc_ret cpu=3 el=1 pc=0x0 imm=0 id=0xc3000006 x0=0x0 x1=0xabcd\n': 'GenerateRandomBytes not redacted',
            'smc cpu=1 el=1 pc=0x0 imm=0 id=0xc3000002 x1=0x3\n': 'core 1',
        }
        for line, expect in cases.items():
            v = self.analyze(self.GOOD + line)['violations']
            self.assertTrue(any(expect in x for x in v), (line, v))
        for qemu in ('Taking exception 1 [Undefined Instruction] on CPU 0\n...from EL1 to EL2\n',
                     'Taking exception 4 [Data Abort] on CPU 3\n...from EL0 to EL1\n...with ESR 0x24/0x92000007\n',
                     'Taking exception 1 [Undefined Instruction] on CPU 3\n...from EL0 to EL1\n...with ESR 0x0/0x2000000\n'):
            self.assertTrue(self.analyze(self.GOOD, qemu)['violations'], qemu)
        for uart in ('Exception occurred. 0100000000000028\n', 'Core[3]: Kernel Panic at x.cpp:1\n',
                     "Abort: 'R_SUCCEEDED(rc)' in Main, process=0x02, thread=5 (main)\n"):
            self.assertTrue(self.analyze(self.GOOD, uart=uart)['violations'], uart)


if __name__ == '__main__':
    unittest.main()
