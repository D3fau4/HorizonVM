import hashlib
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import hvm_keys  # noqa: E402
import hvm_log  # noqa: E402
import hvm_nand  # noqa: E402
import hvm_nbd   # noqa: E402
import mknand   # noqa: E402
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
            self.assertEqual(len(cache), 0x400 - mkfuses.CACHE_START)
            self.assertLessEqual(len(cache), 0x368)   # tegra_qemu fuse.c: largest cache it accepts
            self.assertEqual(read_reg(cache, mkfuses.FUSE_SOC_SPEEDO_1_CALIB), 0x7F)
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
        fields = {'chip_common.FUSE_SOC_SPEEDO_1_CALIB': mkfuses.FUSE_SOC_SPEEDO_1_CALIB,
                  'chip_common.FUSE_RESERVED_ODM_0': mkfuses.FUSE_RESERVED_ODM0,
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
        src += 'static_assert((ams::fuse::PatchVersion_Odnx02A2 & 0xFFF) == 0x%x);\n' % mkfuses.PATCH_VERSION_ODNX02A2
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
    SOURCES = {n: hashlib.sha256(n.encode()).hexdigest()[:64 if n.startswith('bis_key_source') else 32]
               for n in hvm_keys.BIS_SOURCES + ['master_key_00']}

    def run_tool(self, soc, ident, keys, *extra):
        return subprocess.run([sys.executable, os.path.join(ROOT, 'tools/hvm_keys.py'), '--soc', soc,
                               '--prod-keys', keys, '--identity', ident] + list(extra),
                              capture_output=True, text=True, check=True)

    def test_profiles_and_identity(self):
        d = tempfile.mkdtemp()
        try:
            keys = os.path.join(d, 'prod.keys')
            with open(keys, 'w') as f:
                f.write('master_key_15 = %s\nmariko_kek = %s\n' % (self.MASTER, self.KEK))
                f.write(''.join('%s = %s\n' % kv for kv in self.SOURCES.items()))
            secret_hex = [self.MASTER, self.KEK] + [v[:32] for v in self.SOURCES.values()]
            for soc, slots in (('erista', (10, 12, 13, 15)), ('mariko', (12, 14))):
                ident = os.path.join(d, soc)
                out1 = self.run_tool(soc, ident, keys, '--derive-bis')
                files = {s: os.path.join(ident, 'aeskeyslot%d.bin' % s) for s in slots}
                files['bis'] = os.path.join(ident, 'bis.bin')
                first = {s: read(p) for s, p in files.items()}
                out2 = self.run_tool(soc, ident, keys, '--derive-bis')
                self.assertEqual(first, {s: read(p) for s, p in files.items()}, 'identity must persist')
                self.assertEqual(stat.S_IMODE(os.stat(ident).st_mode), 0o700)
                for name, p in files.items():
                    self.assertEqual(os.path.getsize(p), 128 if name == 'bis' else 16)
                    self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
                bis = first['bis']
                self.assertEqual(bis[64:96], bis[96:128], 'SYSTEM and USER share bis_key_source_02')
                self.assertEqual(len({bis[i:i + 16] for i in range(0, 128, 16)}), 6)   # BIS3 == BIS2
                secret_hex += [bis[i:i + 16].hex() for i in range(0, 128, 16)]
                for out in (out1, out2):
                    for h in secret_hex:
                        self.assertNotIn(h, (out.stdout + out.stderr).lower())
            self.assertEqual(read(os.path.join(d, 'erista/aeskeyslot13.bin')), bytes.fromhex(self.MASTER))
            self.assertEqual(read(os.path.join(d, 'mariko/aeskeyslot12.bin')), bytes.fromhex(self.KEK))
            self.assertNotEqual(read(os.path.join(d, 'erista/bis.bin')), read(os.path.join(d, 'mariko/bis.bin')))
        finally:
            shutil.rmtree(d)

    def test_bis_derivation_chain(self):
        """Erista BIS keys follow exosphere's GenerateSpecificAesKey / GenerateAesKek+LoadAesKey chains."""
        src = {n: bytes.fromhex(v) for n, v in self.SOURCES.items()}
        duk = bytes(range(16))
        bis = hvm_keys.derive_bis_keys(duk, src)
        d = hvm_keys.aes_dec
        kek0 = d(duk, src['retail_specific_aes_key_source'])
        self.assertEqual(bis[0], d(kek0, src['bis_key_source_00'][:16]) + d(kek0, src['bis_key_source_00'][16:]))
        g = d(d(duk, src['aes_kek_generation_source']), src['bis_kek_source'])
        kb = d(g, src['aes_key_generation_source'])
        self.assertEqual(bis[1], d(kb, src['bis_key_source_01'][:16]) + d(kb, src['bis_key_source_01'][16:]))

    @unittest.skipUnless(os.path.exists(GXX), 'devkitA64 not available')
    def test_volatile_keys_layout(self):
        fields = hvm_keys.parse_volatile_keys()
        self.assertEqual([n for n, _ in hvm_keys.VOLATILE_KEYS], list(fields))
        t = 'ams::secmon::VolatileKeys'
        src = '#include <exosphere.hpp>\n#include <cstddef>\n'
        src += 'static_assert(sizeof(%s) == 0x%x);\n' % (t, hvm_keys.VOLATILE_KEYS_SIZE)
        off = 0
        for name, size in hvm_keys.VOLATILE_KEYS:
            if name != 'rsa_moduli':   # the three 0x100-byte moduli are separate members
                src += 'static_assert(offsetof(%s, %s) == 0x%x);\n' % (t, name, off)
            off += size
        src += 'static_assert(ams::pkg1::KeyGeneration_Count == %d);\n' % hvm_keys.KEY_GENERATION_COUNT
        src += 'static_assert(ams::pkg1::OldDeviceMasterKeyCount == %d);\n' % hvm_keys.DEVICE_MASTER_KEY_COUNT
        r = compile_check(src)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])


def xts_reference(key, data, unit):
    """Textbook IEEE 1619 XTS from AES-ECB, with Nintendo's big-endian data unit number as the tweak."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    ecb = lambda k: Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    t = int.from_bytes(ecb(key[16:]).update(unit.to_bytes(16, 'big')), 'little')
    out = b''
    for i in range(0, len(data), 16):
        tb = t.to_bytes(16, 'little')
        x = bytes(a ^ b for a, b in zip(data[i:i + 16], tb))
        out += bytes(a ^ b for a, b in zip(ecb(key[:16]).update(x), tb))
        t = ((t << 1) ^ (0x87 if t >> 127 else 0)) & ((1 << 128) - 1)
    return out


TOOLS_AVAILABLE = all(shutil.which(t) for t in ('mkfs.fat', 'mcopy', 'fsck.fat', 'sgdisk'))


class TestNand(unittest.TestCase):
    def test_xts_matches_reference(self):
        key = hashlib.sha256(b'k').digest()
        data = hashlib.sha512(b'd').digest() * 512        # two XTS units
        enc = hvm_nand.xts(key, data, 5, True)
        self.assertEqual(enc[:0x4000], xts_reference(key, data[:0x4000], 5))
        self.assertEqual(enc[0x4000:], xts_reference(key, data[0x4000:], 6))
        self.assertEqual(hvm_nand.xts(key, enc, 5, False), data)

    def test_layout(self):
        parts = hvm_nand.PARTITIONS
        for (_, o1, s1, *_), (_, o2, *_) in zip(parts, parts[1:]):
            self.assertLessEqual(o1 + s1, o2)
        self.assertEqual(parts[0][1], 34 * hvm_nand.LBA)                     # first usable LBA
        end = parts[-1][1] + parts[-1][2]
        self.assertLessEqual(end, hvm_nand.USER_AREA_SIZE - 33 * hvm_nand.LBA)   # room for the backup GPT
        self.assertEqual({p[4] for p in parts if p[5]}, {0, 1, 2, 3})

    def test_blank_cal0(self):
        cal = hvm_nand.build_blank_cal0()
        self.assertTrue(hvm_nand.check_cal0(cal))
        for off, size in hvm_nand.CAL0_CRC_BLOCKS:
            self.assertEqual(hvm_nand.crc16(cal[off:off + size - 2]), struct.unpack_from('<H', cal, off + size - 2)[0])
        bad = bytearray(cal)
        bad[0x300] ^= 1
        self.assertFalse(hvm_nand.check_cal0(bytes(bad)))

    @unittest.skipUnless(TOOLS_AVAILABLE, 'dosfstools/mtools/gdisk not available')
    def test_image_roundtrip(self):
        d = tempfile.mkdtemp()
        old = hvm_nand.HVM
        try:
            hvm_nand.HVM = d
            ident = os.path.join(d, 'identity', 'erista')
            os.makedirs(ident)
            with open(os.path.join(ident, 'bis.bin'), 'wb') as f:
                f.write(hashlib.sha512(b'a').digest() + hashlib.sha512(b'b').digest())
            with open(os.path.join(ident, 'ecid.json'), 'w') as f:
                f.write('{"lot0": 1}')
            tree = os.path.join(d, 'tree')
            for sub in mknand.TREE_DIRS:
                os.makedirs(os.path.join(tree, sub))
            reg = os.path.join(tree, 'SYSTEM/Contents/registered')
            for i in range(3):
                with open(os.path.join(reg, '%032x.nca' % i), 'wb') as f:
                    f.write(hashlib.sha512(bytes([i])).digest() * (0x900 * (i + 1)) + bytes(0x8000))
            with open(os.path.join(tree, 'PRODINFO.bin'), 'wb') as f:
                f.write(hvm_nand.build_blank_cal0())
            img = os.path.join(d, 'emmc.img')
            mknand.build_image('erista', tree, img)
            self.assertEqual(os.path.getsize(img), hvm_nand.IMAGE_SIZE)
            self.assertEqual(mknand.verify('erista', tree, img), [])

            with open(os.path.join(reg, '%032x.nca' % 1), 'r+b') as f:   # tree changed after the build
                f.write(b'X')
            self.assertTrue(any('content differs' in p for p in mknand.verify('erista', tree, img)))
            with open(os.path.join(ident, 'bis.bin'), 'r+b') as f:        # wrong keys: nothing decrypts
                f.seek(64)
                f.write(bytes(32))
            problems = mknand.verify('erista', tree, img)
            self.assertTrue(any(p.startswith('SYSTEM: fsck.fat') for p in problems), problems)
            self.assertFalse(any(p.startswith('GPT') for p in problems))
            with open(img, 'r+b') as f:                                   # corrupt the primary GPT header
                f.seek(2 * hvm_nand.BOOT_PART_SIZE + hvm_nand.LBA + 40)
                f.write(b'\xff')
            self.assertTrue(any(p.startswith('GPT') for p in mknand.verify('erista', tree, img)))
        finally:
            hvm_nand.HVM = old
            shutil.rmtree(d)


def make_nand_fixture(d):
    """Temporary HORIZONVM_HOME with an erista identity and a small NAND tree."""
    ident = os.path.join(d, 'identity', 'erista')
    os.makedirs(ident)
    with open(os.path.join(ident, 'bis.bin'), 'wb') as f:
        f.write(hashlib.sha512(b'a').digest() + hashlib.sha512(b'b').digest())
    with open(os.path.join(ident, 'ecid.json'), 'w') as f:
        f.write('{"lot0": 1}')
    tree = os.path.join(d, 'tree')
    for sub in mknand.TREE_DIRS:
        os.makedirs(os.path.join(tree, sub))
    reg = os.path.join(tree, 'SYSTEM/Contents/registered')
    for i in range(12):
        with open(os.path.join(reg, '%032x.nca' % (i * 0x1111)), 'wb') as f:
            f.write(hashlib.sha512(bytes([i])).digest() * (0x300 * (i + 1)))
    with open(os.path.join(tree, 'SAFE', 'lowercase-long-name.txt'), 'wb') as f:
        f.write(b'safe')
    with open(os.path.join(tree, 'PRODINFO.bin'), 'wb') as f:
        f.write(hvm_nand.build_blank_cal0())
    return tree


def nbd_client(sock):
    """Minimal fixed-newstyle NBD client: NBD_OPT_GO, then (read, write, flush) helpers."""
    magic, opt_magic, _ = struct.unpack('>QQH', sock.recv(18, socket.MSG_WAITALL))
    assert (magic, opt_magic) == (hvm_nbd.NBDMAGIC, hvm_nbd.IHAVEOPT)
    sock.sendall(struct.pack('>I', 3))
    sock.sendall(struct.pack('>QII', hvm_nbd.IHAVEOPT, 8, 0))          # STRUCTURED_REPLY: must be refused
    reply = struct.unpack('>QIII', sock.recv(20, socket.MSG_WAITALL))
    assert reply[2] == hvm_nbd.REP_ERR_UNSUP
    sock.sendall(struct.pack('>QII', hvm_nbd.IHAVEOPT, hvm_nbd.OPT_GO, 6) + struct.pack('>IH', 0, 0))
    size = None
    while True:
        _, _, rtype, length = struct.unpack('>QIII', sock.recv(20, socket.MSG_WAITALL))
        data = sock.recv(length, socket.MSG_WAITALL) if length else b''
        if rtype == hvm_nbd.REP_INFO:
            size = struct.unpack('>HQH', data)[1]
        if rtype == hvm_nbd.REP_ACK:
            break

    def cmd(kind, off, length, payload=b''):
        sock.sendall(struct.pack('>IHHQQI', hvm_nbd.REQUEST_MAGIC, 0, kind, 7, off, length) + payload)
        magic, err, handle = struct.unpack('>IIQ', sock.recv(16, socket.MSG_WAITALL))
        assert (magic, handle) == (hvm_nbd.SIMPLE_REPLY_MAGIC, 7)
        return err, sock.recv(length, socket.MSG_WAITALL) if kind == hvm_nbd.CMD_READ and not err else b''
    return size, cmd


@unittest.skipUnless(TOOLS_AVAILABLE, 'dosfstools/mtools/gdisk not available')
class TestNbd(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.old = hvm_nand.HVM
        hvm_nand.HVM = self.d
        self.tree = make_nand_fixture(self.d)
        self.disk = hvm_nbd.VirtualEmmc('erista', self.tree, self.d)

    def tearDown(self):
        hvm_nand.HVM = self.old
        shutil.rmtree(self.d)

    def test_matches_image_outside_fat(self):
        img = os.path.join(self.d, 'emmc.img')
        mknand.build_image('erista', self.tree, img)
        user = 2 * hvm_nand.BOOT_PART_SIZE
        _, off, size, *_ = hvm_nand.PART['PRODINFO']
        with open(img, 'rb') as f:
            for start, n in ((0, 0x10000), (user, 34 * hvm_nand.LBA), (user + off, size),
                             (hvm_nand.IMAGE_SIZE - 33 * hvm_nand.LBA, 33 * hvm_nand.LBA)):
                f.seek(start)
                self.assertEqual(self.disk.read(start, n), f.read(n), hex(start))

    def test_fat_partitions(self):
        key = hvm_nand.load_bis_keys('erista')[2]
        _, off, *_ = hvm_nand.PART['SYSTEM']
        cipher = self.disk.read(2 * hvm_nand.BOOT_PART_SIZE + off, 0x100000)
        self.assertEqual(hvm_nand.xts(key, cipher, 0, False), self.disk.fats['SYSTEM'].read(0, 0x100000))
        for name in ('SYSTEM', 'SAFE', 'PRODINFOF', 'USER'):
            plain = os.path.join(self.d, name + '.fat')
            hvm_nbd.export_partition('erista', self.tree, name, plain)
            r = subprocess.run(['fsck.fat', '-n', plain], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, name + ': ' + r.stdout[-500:])
            out = os.path.join(self.d, name + '.files')
            os.makedirs(out)
            subprocess.run(['mcopy', '-s', '-n', '-i', plain, '::/*', out], env=mknand.MTOOLS_ENV, capture_output=True)
            want, got = mknand.tree_files(os.path.join(self.tree, name)), mknand.tree_files(out)
            self.assertEqual(set(want), set(got), name)
            for k in want:
                self.assertEqual(mknand.file_hash(want[k]), mknand.file_hash(got[k]), k)
            if name == 'SAFE':
                self.assertIn('lowercase-long-name.txt', os.listdir(out))   # LFN keeps case and length

    def test_nbd_protocol_and_overlay(self):
        import threading
        a, b = socket.socketpair()
        t = threading.Thread(target=lambda: hvm_nbd.serve_connection(b, self.disk))
        t.start()
        size, cmd = nbd_client(a)
        self.assertEqual(size, hvm_nand.IMAGE_SIZE)
        err, gpt = cmd(hvm_nbd.CMD_READ, 2 * hvm_nand.BOOT_PART_SIZE + hvm_nand.LBA, 8)
        self.assertEqual((err, gpt), (0, b'EFI PART'))
        data = bytes(range(256)) * 6                    # unaligned write spanning three 512-byte sectors
        self.assertEqual(cmd(hvm_nbd.CMD_WRITE, 0x10100, len(data), data)[0], 0)
        self.assertEqual(cmd(hvm_nbd.CMD_FLUSH, 0, 0)[0], 0)
        self.assertEqual(cmd(hvm_nbd.CMD_READ, 0x10100, len(data)), (0, data))
        self.assertEqual(cmd(hvm_nbd.CMD_READ, 0x10000, 0x100), (0, bytes(0x100)))   # rest of the sector intact
        self.assertEqual(cmd(hvm_nbd.CMD_READ, size - 8, 16)[0], hvm_nbd.EINVAL)
        a.sendall(struct.pack('>IHHQQI', hvm_nbd.REQUEST_MAGIC, 0, hvm_nbd.CMD_DISC, 0, 0, 0))
        t.join(5)
        self.assertFalse(t.is_alive())
        a.close()
        b.close()


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

    def test_ipc_results_and_handles(self):
        reply = struct.pack('<IIII', 0, (1 << 31) | 3, 1 << 5, 0xd00a).ljust(0x40, b'\0')   # one moved handle
        lookup = tipc(1, b'ldr:pm').hex()
        trace = ('svc cpu=3 pid=4 tls=0x9000 pc=0x300 id=0x21 x0=0xd001 x1=0x0 x2=0x0 x3=0x0 ipc=tipc:1 sm_msg=%s\n'
                 'svc_ret cpu=3 pid=4 tls=0x9000 pc=0x304 id=0x21 x0=0x0 x1=0x0 x2=0x0 x3=0x0 ipc_result=0x0 sm_reply=%s\n'
                 'svc cpu=3 pid=4 tls=0x9000 pc=0x300 id=0x21 x0=0xd00a x1=0x0 x2=0x0 x3=0x0 ipc=cmif:1\n'
                 'svc_ret cpu=3 pid=4 tls=0x9000 pc=0x304 id=0x21 x0=0x0 x1=0x0 x2=0x0 x3=0x0 ipc_result=0x408\n'
                 % (lookup, reply.hex()))
        r = self.analyze(trace)
        self.assertEqual(dict(r['ipc_failures']), {(4, 'ldr:pm', 1, 0x408): 1})
        self.assertEqual(hvm_log.result_str(0x408), '2008-0002')

    def test_generate_aes_kek_generation_is_public(self):
        ok = 'smc cpu=3 el=1 pc=0x0 imm=0 id=0xc3000007 x1=<redacted> x2=<redacted> x3=0x16 x4=0x0 x5=<redacted>\n'
        self.assertEqual(self.analyze(self.GOOD + ok)['violations'], [])

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
