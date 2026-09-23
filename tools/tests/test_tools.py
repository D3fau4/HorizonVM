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
import mkfuses  # noqa: E402
import mkpkg2   # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
AMS = os.path.join(ROOT, 'third_party', 'Atmosphere')
MESO = os.path.join(AMS, 'mesosphere/out/nintendo_nx_arm64_armv8a/debug/mesosphere.bin')
GXX = os.path.join(os.environ.get('DEVKITPRO', '/opt/devkitpro'), 'devkitA64/bin/aarch64-none-elf-g++')


def read(path):
    with open(path, 'rb') as f:
        return f.read()


def fake_meso(size=0x3000, meta_offset=0x800):
    m = bytearray(size)
    m[4:8] = b'MSS1'
    struct.pack_into('<I', m, 8, meta_offset)
    return bytes(m)


def fake_kip(program_id, size=0x200):
    k = bytearray(size)
    k[0:4] = b'KIP1'
    struct.pack_into('<Q', k, 0x10, program_id)
    return bytes(k)


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
        lx = os.path.join(AMS, 'libraries/libexosphere')
        cmd = [GXX, '-std=gnu++23', '-fsyntax-only', '-fno-rtti', '-fno-exceptions', '-x', 'c++', '-',
               '-D__SWITCH__', '-DATMOSPHERE', '-DATMOSPHERE_ARCH_ARM64', '-DATMOSPHERE_BOARD_NINTENDO_NX',
               '-DATMOSPHERE_OS_HORIZON', '-DATMOSPHERE_CPU_ARM_CORTEX_A57', '-DATMOSPHERE_ARCH_ARM_V8A',
               '-DATMOSPHERE_IS_EXOSPHERE', '-I' + os.path.join(AMS, 'libraries/libvapours/include'),
               '-I' + os.path.join(lx, 'include'), '-I' + os.path.join(lx, 'source/fuse')]
        r = subprocess.run(cmd, input=src, capture_output=True, text=True)
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


class TestHvmLog(unittest.TestCase):
    GOOD = ('smc cpu=0 el=1 pc=0x800c3048 id=0xc4000003 x1=0x1 x2=0x800d1200 x3=0x0 x4=0x0 x5=0x0 x6=0x0 x7=0x0\n'
            'smc_ret cpu=0 el=1 pc=0x800c304c id=0xc4000003 x0=0x0 x1=0x1 x2=0x0 x3=0x0\n'
            'smc_ret cpu=0 el=1 pc=0x800c304c id=0xc3000005 x0=<redacted> x1=<redacted> x2=<redacted> x3=<redacted>\n'
            'mmio cpu=0 pc=0x1f0000000 W addr=0x50041100 size=4 val=0xffffffff\n'
            'mmio cpu=0 pc=0x1f0000000 W addr=0x70012300 size=4 val=<redacted>\n')
    QEMU = 'Taking exception 5 [IRQ] on CPU 0\n...from EL1 to EL1\n'

    def analyze(self, trace, qemu=QEMU):
        d = tempfile.mkdtemp()
        try:
            t, q = os.path.join(d, 't'), os.path.join(d, 'q')
            with open(t, 'w') as f:
                f.write(trace)
            with open(q, 'w') as f:
                f.write(qemu)
            return hvm_log.analyze(t, q)
        finally:
            shutil.rmtree(d)

    def test_clean_trace(self):
        r = self.analyze(self.GOOD)
        self.assertEqual(r['violations'], [])
        self.assertEqual(r['smc'][0xC4000003], 1)
        self.assertEqual(r['mmio']['gic_dist']['W'], 1)

    def test_violations(self):
        cases = {
            'mmio cpu=0 pc=0x0 W addr=0x57000000 size=4 val=0x1\n': 'gpu',
            'mmio cpu=0 pc=0x0 W addr=0x70012300 size=4 val=0x1234\n': 'not redacted',
            'smc cpu=0 el=1 pc=0x0 id=0xc3000002 x1=<redacted>\n': 'unknown SMC',
            'smc_ret cpu=0 el=1 pc=0x0 id=0xc3000005 x0=0x0 x1=0x5\n': 'RNG',
        }
        for line, expect in cases.items():
            v = self.analyze(self.GOOD + line)['violations']
            self.assertTrue(any(expect in x for x in v), (line, v))
        v = self.analyze(self.GOOD, 'Taking exception 1 [Undefined Instruction] on CPU 0\n...from EL1 to EL2\n')['violations']
        self.assertTrue(v)


if __name__ == '__main__':
    unittest.main()
