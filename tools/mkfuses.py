#!/usr/bin/env python3
"""Generate the synthetic fuse cache (tegra.fuse.cache secret) for a HorizonVM SoC profile."""
import argparse
import json
import os
import secrets
import struct

# Offsets inside the fuse register block (0x7000F800), from libexosphere fuse_registers.hpp.
FUSE_RESERVED_ODM0 = 0x1C8
FUSE_OPT_VENDOR_CODE = 0x200
FUSE_OPT_FAB_CODE = 0x204
FUSE_OPT_LOT_CODE_0 = 0x208
FUSE_OPT_LOT_CODE_1 = 0x20C
FUSE_OPT_WAFER_ID = 0x210
FUSE_OPT_X_COORDINATE = 0x214
FUSE_OPT_Y_COORDINATE = 0x218
FUSE_OPT_OPS_RESERVED = 0x220

# tegra_qemu maps a secret of length L onto fuse registers [0x400 - L, 0x400) (fuse.c).
CACHE_START = FUSE_RESERVED_ODM0
CACHE_END = 0x400

NEW_FUSE_FORMAT_MAGIC = (0x8E61ECAE, 0xF2BA3BB2)   # fuse_api.cpp IsNewFuseFormat
HARDWARE_STATE_PRODUCTION = 4                        # fuse_api.cpp GetHardwareState

PROFILES = {
    # raw ODM4 hardware-type value (fuse_api.cpp GetHardwareType) and a 4 GB DramId (fuse.hpp)
    'erista': {'hw_type': 0x01, 'dram_id': 0},    # Icosa, DramId_IcosaSamsung4GB
    'mariko': {'hw_type': 0x04, 'dram_id': 3},    # Iowa,  DramId_IowaHynix1y4GB
}

ECID_FIELDS = {  # name: (offset, bit width) as read by fuse::GetEcid
    'vendor': (FUSE_OPT_VENDOR_CODE, 4), 'fab': (FUSE_OPT_FAB_CODE, 6),
    'lot0': (FUSE_OPT_LOT_CODE_0, 32), 'lot1': (FUSE_OPT_LOT_CODE_1, 28),
    'wafer': (FUSE_OPT_WAFER_ID, 6), 'x': (FUSE_OPT_X_COORDINATE, 9),
    'y': (FUSE_OPT_Y_COORDINATE, 9), 'reserved': (FUSE_OPT_OPS_RESERVED, 6),
}


def encode_odm4(hw_type, hw_state, dram_id, format_version=1):
    v = hw_state & 3
    v |= (hw_type & 1) << 2
    v |= (dram_id & 0x1F) << 3
    v |= ((hw_type >> 1) & 1) << 8
    v |= ((hw_state >> 2) & 1) << 9
    v |= (format_version & 1) << 11
    v |= ((dram_id >> 5) & 7) << 12
    v |= ((hw_type >> 2) & 0xF) << 16
    return v


def build_fuse_cache(profile, ecid):
    p = PROFILES[profile]
    regs = {
        FUSE_RESERVED_ODM0 + 0 * 4: NEW_FUSE_FORMAT_MAGIC[0],
        FUSE_RESERVED_ODM0 + 1 * 4: NEW_FUSE_FORMAT_MAGIC[1],
        FUSE_RESERVED_ODM0 + 4 * 4: encode_odm4(p['hw_type'], HARDWARE_STATE_PRODUCTION, p['dram_id']),
    }
    for name, (off, bits) in ECID_FIELDS.items():
        regs[off] = ecid[name] & ((1 << bits) - 1)
    data = bytearray(CACHE_END - CACHE_START)
    for off, val in regs.items():
        struct.pack_into('<I', data, off - CACHE_START, val)
    return bytes(data)


def load_or_create_ecid(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    ecid = {name: secrets.randbits(bits) for name, (_, bits) in ECID_FIELDS.items()}
    with open(path, 'w') as f:
        json.dump(ecid, f, indent=1)
    return ecid


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', choices=sorted(PROFILES), required=True)
    ap.add_argument('--identity', help='identity dir (default ~/.horizonvm/identity/<soc>)')
    args = ap.parse_args()
    os.umask(0o077)   # identity and secrets are private

    ident = os.path.expanduser(args.identity or '~/.horizonvm/identity/%s' % args.soc)
    os.makedirs(ident, mode=0o700, exist_ok=True)
    ecid = load_or_create_ecid(os.path.join(ident, 'ecid.json'))
    out = os.path.join(ident, 'fuses.bin')
    with open(out, 'wb') as f:
        f.write(build_fuse_cache(args.soc, ecid))
    print('%s: ok (%s)' % (out, args.soc))


if __name__ == '__main__':
    main()
