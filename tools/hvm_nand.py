"""NX eMMC layout, GPT, BIS AES-XTS and CAL0 helpers shared by mknand (image) and hvm_nbd (live folders)."""
import hashlib
import json
import os
import struct
import uuid
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HVM = os.environ.get('HORIZONVM_HOME', os.path.expanduser('~/.horizonvm'))
LBA = 0x200
XTS_SECTOR = 0x4000                # BIS AES-XTS data unit (tweak = big-endian unit index in the partition)
BOOT_PART_SIZE = 0x400000          # tegra_qemu emmc: BOOT0 + BOOT1 precede the user area (tegrax1.c, README)
USER_AREA_SIZE = 0x747C00000       # 32 GB eMMC user area
IMAGE_SIZE = 2 * BOOT_PART_SIZE + USER_AREA_SIZE
GPT_ENTRIES, GPT_ENTRY_SIZE = 128, 128

# (name, offset, size, GPT type GUID, BIS key index or None, filesystem) - switchbrew Flash_Filesystem.
PARTITIONS = [
    ('PRODINFO',                0x0004400, 0x003FBC00, '98109E25-64E2-4C95-8A77-414916F5BCEB', 0, None),
    ('PRODINFOF',               0x0400000, 0x00400000, 'F3056AEC-5449-494C-9F2C-5FDCB75B6E6E', 0, 'fat12'),
    ('BCPKG2-1-Normal-Main',    0x0800000, 0x00800000, '5365DE36-911B-4BB4-8FF9-AA1EBCD73990', None, None),
    ('BCPKG2-2-Normal-Sub',     0x1000000, 0x00800000, '8455717B-BD2B-4162-8454-91695218FC38', None, None),
    ('BCPKG2-3-SafeMode-Main',  0x1800000, 0x00800000, '8ED6C9A6-9C48-490B-BBEB-001D17A4C0F7', None, None),
    ('BCPKG2-4-SafeMode-Sub',   0x2000000, 0x00800000, '5E99751C-56C9-47CC-AA30-B65039888917', None, None),
    ('BCPKG2-5-Repair-Main',    0x2800000, 0x00800000, 'C447D9A2-24B7-468A-98C8-595CD077165A', None, None),
    ('BCPKG2-6-Repair-Sub',     0x3000000, 0x00800000, '9586E1A1-3AA2-4C90-91B3-2F4A5195B4D2', None, None),
    ('SAFE',                    0x3800000, 0x04000000, 'A44F9F6B-4ED3-441F-A34A-56AAA136BC6A', 1, 'fat32'),
    ('SYSTEM',                  0x7800000, 0xA0000000, 'ACB0CDF0-4F72-432D-AA0D-5388C733B224', 2, 'fat32'),
    ('USER',                   0xA7800000, 0x680000000, '2B777F63-E842-47AF-94C4-25A7F18B2280', 3, 'fat32'),
]
PART = {p[0]: p for p in PARTITIONS}
FAT_OPTS = {'PRODINFOF': ['-F', '12'], 'SAFE': ['-F', '32', '-s', '1'],     # mkfs.fat options per volume
            'SYSTEM': ['-F', '32', '-s', '32'], 'USER': ['-F', '32', '-s', '32'],  # 16 KiB clusters
            'SD': ['-F', '32', '-s', '64']}                                        # 32 KiB clusters

# SD card (SDMMC1): MBR + one FAT32 LBA partition (type 0x0C), no BIS encryption.
SD_PART_OFFSET = 0x400000
SD_DEFAULT_SIZE = 8 << 30


def soc_paths(soc):
    return {'identity': os.path.join(HVM, 'identity', soc), 'nand': os.path.join(HVM, 'nand', soc),
            'dir': os.path.join(HVM, 'nand', soc, 'dir'), 'image': os.path.join(HVM, 'nand', soc, 'emmc.img')}


def sd_paths(soc):
    """Per SoC: ams_mitm writes that identity's PRODINFO and BIS key backups to the card."""
    root = os.path.join(HVM, 'sd', soc)
    return {'sd': root, 'dir': os.path.join(root, 'dir'), 'image': os.path.join(root, 'sd.img'),
            'config': os.path.join(root, 'sd.json')}


def sd_size(soc):
    try:
        with open(sd_paths(soc)['config']) as f:
            return json.load(f)['size']
    except FileNotFoundError:
        return SD_DEFAULT_SIZE


def build_mbr(disk_size, disk_id):
    mbr = bytearray(LBA)
    struct.pack_into('<I', mbr, 440, disk_id)
    struct.pack_into('<B3sB3sII', mbr, 446, 0, b'\xfe\xff\xff', 0x0C, b'\xfe\xff\xff',
                     SD_PART_OFFSET // LBA, (disk_size - SD_PART_OFFSET) // LBA)
    mbr[510:512] = b'\x55\xaa'
    return bytes(mbr)


def sd_disk_id(soc):
    return disk_guids(soc)[0].int & 0xFFFFFFFF


def load_bis_keys(soc):
    with open(os.path.join(soc_paths(soc)['identity'], 'bis.bin'), 'rb') as f:
        data = f.read()
    if len(data) != 4 * 32:
        raise ValueError('bis.bin: unexpected size (run hvm_keys.py --derive-bis)')
    return [data[i:i + 32] for i in range(0, 128, 32)]


def xts(key, data, first_unit, encrypt):
    """Nintendo BIS AES-128-XTS: key = crypt || tweak, one data unit per 0x4000 bytes, big-endian tweak."""
    out = bytearray()
    for i in range(0, len(data), XTS_SECTOR):
        c = Cipher(algorithms.AES(key), modes.XTS((first_unit + i // XTS_SECTOR).to_bytes(16, 'big')))
        op = c.encryptor() if encrypt else c.decryptor()
        out += op.update(bytes(data[i:i + XTS_SECTOR])) + op.finalize()
    return bytes(out)


def disk_guids(soc):
    """Deterministic disk/partition GUIDs derived from the VM identity (ECID)."""
    with open(os.path.join(soc_paths(soc)['identity'], 'ecid.json')) as f:
        seed = json.dumps(json.load(f), sort_keys=True)
    ns = uuid.uuid5(uuid.NAMESPACE_OID, 'horizonvm-nand:' + seed)
    return uuid.uuid5(ns, 'disk'), {p[0]: uuid.uuid5(ns, p[0]) for p in PARTITIONS}


def build_gpt(disk_guid, part_guids, user_size=USER_AREA_SIZE):
    """Protective MBR + primary GPT (LBA 0..33) and backup GPT (last 33 LBAs) of the eMMC user area."""
    last = user_size // LBA - 1
    entries = bytearray(GPT_ENTRIES * GPT_ENTRY_SIZE)
    for i, (name, off, size, tguid, _, _) in enumerate(PARTITIONS):
        struct.pack_into('<16s16sQQQ72s', entries, i * GPT_ENTRY_SIZE, uuid.UUID(tguid).bytes_le,
                         part_guids[name].bytes_le, off // LBA, (off + size) // LBA - 1, 0,
                         name.encode('utf-16-le'))
    entries_crc = zlib.crc32(entries)

    def header(current, backup, entries_lba):
        h = bytearray(LBA)
        struct.pack_into('<8sIIIIQQQQ16sQIII', h, 0, b'EFI PART', 0x00010000, 92, 0, 0, current, backup,
                         34, last - 33, disk_guid.bytes_le, entries_lba, GPT_ENTRIES, GPT_ENTRY_SIZE, entries_crc)
        struct.pack_into('<I', h, 16, zlib.crc32(h[:92]))
        return bytes(h)

    mbr = bytearray(LBA)
    struct.pack_into('<B3sB3sII', mbr, 446, 0, b'\x00\x02\x00', 0xEE, b'\xff\xff\xff', 1, min(last, 0xFFFFFFFF))
    mbr[510:512] = b'\x55\xaa'
    primary = bytes(mbr) + header(1, last, 2) + bytes(entries)
    backup = bytes(entries) + header(last, 1, last - 32)
    return primary, backup


def crc16(data):
    """CAL0 CRC16 (cal_crc_utils.cpp)."""
    table = (0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
             0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400)
    crc = 0x55AA
    for b in data:
        crc = (crc >> 4) ^ table[crc & 0xF] ^ table[b & 0xF]
        crc = (crc >> 4) ^ table[crc & 0xF] ^ table[b >> 4]
    return crc


CAL0_SIZE = 0x8000
CAL0_BLANK_SERIAL = b'XAW00000000000'
# Blocks Blank() resets with a fresh CRC16: serial, ssl certificate size, amiibo root certs, extended ssl key.
# (It only zeroes the ssl certificate itself and leaves its SHA-256 as is, i.e. zero for a new CAL0.)
CAL0_CRC_BLOCKS = [(0x0250, 0x020), (0x0AD0, 0x010), (0x35A0, 0x080), (0x36A0, 0x0A0), (0x3AE0, 0x140)]


def build_blank_cal0():
    """The blank CAL0 ams_mitm serves (amsmitm_prodinfo_utils.cpp Blank(CalibrationInfo &))."""
    cal = bytearray(CAL0_SIZE)
    struct.pack_into('<4sII', cal, 0, b'CAL0', 0, CAL0_SIZE - 0x40)
    struct.pack_into('<H', cal, 0x1E, crc16(cal[:0x1E]))
    cal[0x250:0x250 + len(CAL0_BLANK_SERIAL)] = CAL0_BLANK_SERIAL
    for off, size in CAL0_CRC_BLOCKS:
        struct.pack_into('<H', cal, off + size - 2, crc16(cal[off:off + size - 2]))
    cal[0x20:0x40] = hashlib.sha256(cal[0x40:]).digest()
    return bytes(cal)


def check_cal0(cal):
    magic, _, body_size = struct.unpack_from('<4sII', cal, 0)
    return (magic == b'CAL0' and crc16(cal[:0x1E]) == struct.unpack_from('<H', cal, 0x1E)[0]
            and hashlib.sha256(cal[0x40:0x40 + body_size]).digest() == cal[0x20:0x40])
