#!/usr/bin/env python3
"""Build a plaintext package2 (mesosphere + INI1) the way fusee's RebuildPackage2 does."""
import argparse
import struct
import sys

PACKAGE2_SIZE_MAX = 8 * 1024 * 1024 - 16 * 1024   # pkg2::Package2SizeMax
INI_SIZE_MAX = 12 * 1024 * 1024                    # kern::InitialProcessBinarySizeMax
KEY_GENERATION_COUNT = 22                          # pkg1::KeyGeneration_Count @ 6e6af69
KEY_GENERATION_CURRENT = KEY_GENERATION_COUNT - 1
KERNEL_PAYLOAD_BASE = 0x60000
BOOTLOADER_VERSION = 0x17                          # pkg2::CurrentBootloaderVersion
HEADER_SIZE = 0x200


def align_up(v, a):
    return (v + a - 1) // a * a


# kern_k_capabilities.hpp CapabilityType: the type is the number of trailing one bits.
CAP_TYPES = {(1 << n) - 1 for n in (3, 4, 6, 7, 10, 11, 13, 14, 15, 16)} | {0xFFFFFFFF}
CAP_CORE_PRIORITY = (1 << 3) - 1


def kip_size(k):
    """KInitialProcessReader: 0x100-byte header followed by the rx/ro/rw segments (compressed sizes)."""
    return 0x100 + sum(struct.unpack_from('<I', k, off)[0] for off in (0x28, 0x38, 0x48))


def check_kip(k):
    """Reject what Mesosphere would panic on when creating an initial process (kern_k_capabilities.cpp)."""
    if len(k) < 0x100 or k[:4] != b'KIP1':
        raise ValueError('not a KIP1 image')
    name = k[4:0x10].rstrip(b'\0').decode(errors='replace')
    if kip_size(k) != len(k):
        raise ValueError('%s: size 0x%x does not match its header (0x%x)' % (name, len(k), kip_size(k)))
    for cap in struct.unpack_from('<32I', k, 0x80):
        ctype = ((~cap & (cap + 1)) - 1) & 0xFFFFFFFF
        if ctype == 0:
            raise ValueError('%s: invalid capability 0x%08x (unused slots must be 0xFFFFFFFF)' % (name, cap))
        if ctype == CAP_CORE_PRIORITY:
            raise ValueError('%s: initial processes cannot have a CorePriority capability' % name)
        if ctype not in CAP_TYPES:
            raise ValueError('%s: unknown capability 0x%08x' % (name, cap))


def split_ini1(ini):
    magic, size, count, _ = struct.unpack_from('<4sIII', ini, 0)
    if magic != b'INI1' or size > len(ini):
        raise ValueError('not an INI1 image')
    kips, off = [], 0x10
    for _ in range(count):
        n = kip_size(ini[off:off + 0x100])
        kips.append(ini[off:off + n])
        off += n
    if off != size:
        raise ValueError('INI1 size mismatch (0x%x != 0x%x)' % (off, size))
    return kips


def build_ini1(kips):
    seen = set()
    for k in kips:
        check_kip(k)
        pid = struct.unpack_from('<Q', k, 0x10)[0]
        if pid in seen:
            raise ValueError('duplicate program_id %016x' % pid)
        seen.add(pid)
    body = b''.join(kips)
    ini = struct.pack('<4sIII', b'INI1', 0x10 + len(body), len(kips), 0) + body
    if len(ini) > INI_SIZE_MAX:
        raise ValueError('INI1 too big (0x%x)' % len(ini))
    return ini


def build_package2(meso, kips=()):
    if meso[4:8] != b'MSS1':
        raise ValueError('mesosphere.bin: missing MSS1 metadata')
    meso = bytearray(meso)
    meta_offset = struct.unpack_from('<I', meso, 8)[0]
    if meta_offset > len(meso) - 8:
        raise ValueError('mesosphere.bin: bad metadata offset')
    # __metadata_ini_offset is relative to itself; point it right after the kernel image (fusee_stratosphere.cpp).
    struct.pack_into('<q', meso, meta_offset, len(meso) - meta_offset)

    payload = bytes(meso) + build_ini1(list(kips))
    payload += b'\0' * (align_up(len(payload), 0x10) - len(payload))

    meta = bytearray(0x100)
    struct.pack_into('<I', meta, 0x00, HEADER_SIZE + len(payload))
    meta[0x04] = KEY_GENERATION_CURRENT
    meta[0x50:0x54] = b'PK21'
    struct.pack_into('<I', meta, 0x54, KERNEL_PAYLOAD_BASE)
    meta[0x5C] = 0                   # package2_version = MinimumValidDataVersion
    meta[0x5D] = BOOTLOADER_VERSION
    struct.pack_into('<III', meta, 0x60, len(payload), 0, 0)
    struct.pack_into('<III', meta, 0x70, KERNEL_PAYLOAD_BASE, 0, 0)
    pkg2 = bytes(0x100) + bytes(meta) + payload
    if len(pkg2) > PACKAGE2_SIZE_MAX:
        raise ValueError('package2 too big (0x%x)' % len(pkg2))
    return pkg2


def verify_package2(pkg2):
    """Port of exosphere's VerifyPackage2Meta/VerifyPackage2Version (secmon_package2.cpp)."""
    meta = pkg2[0x100:0x200]
    iv = meta[0x05:0x10]
    size = struct.unpack_from('<I', meta, 0)[0] ^ struct.unpack_from('<I', iv, 3)[0] ^ struct.unpack_from('<I', iv, 7)[0]
    key_generation = max(0, (meta[0x04] ^ iv[1] ^ iv[2]) - 1)
    entrypoint = struct.unpack_from('<I', meta, 0x54)[0]
    sizes = struct.unpack_from('<III', meta, 0x60)
    offsets = struct.unpack_from('<III', meta, 0x70)
    checks = [
        HEADER_SIZE < size <= PACKAGE2_SIZE_MAX,
        key_generation < KEY_GENERATION_COUNT,
        meta[0x50:0x54] == b'PK21',
        entrypoint % 4 == 0 and all(s % 4 == 0 for s in sizes),
        size == HEADER_SIZE + sum(sizes),
        all(o + s <= 0xFFFFFFFF for o, s in zip(offsets, sizes)),
        not any(i < j and s1 and s2 and o1 < o2 + s2 and o2 < o1 + s1
                for i, (o1, s1) in enumerate(zip(offsets, sizes))
                for j, (o2, s2) in enumerate(zip(offsets, sizes))),
        any(o <= entrypoint < o + s for o, s in zip(offsets, sizes)),
        meta[0x5D] <= BOOTLOADER_VERSION and meta[0x5C] >= 0,
        len(pkg2) == size,
    ]
    return all(checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mesosphere')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--ini1', help='take the KIPs of an existing INI1 (placed before --kip ones)')
    ap.add_argument('--kip', action='append', default=[], help='KIP to embed in the INI1 (repeatable)')
    args = ap.parse_args()

    def read(path):
        with open(path, 'rb') as f:
            return f.read()

    kips = split_ini1(read(args.ini1)) if args.ini1 else []
    kips += [read(k) for k in args.kip]
    pkg2 = build_package2(read(args.mesosphere), kips)
    if not verify_package2(pkg2):
        sys.exit('internal error: package2 fails exosphere validation')
    with open(args.output, 'wb') as f:
        f.write(pkg2)
    print('%s: 0x%x bytes, %d KIP(s)' % (args.output, len(pkg2), len(kips)))


if __name__ == '__main__':
    main()
