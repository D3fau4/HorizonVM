#!/usr/bin/env python3
"""Prepare SE keyslot secrets for a HorizonVM SoC profile, and derive its BIS keys. Never prints key material."""
import argparse
import os
import re
import secrets
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
KEY_DATA_S = os.path.join(ROOT, 'third_party/Atmosphere/exosphere/program/source/boot/secmon_boot_key_data.s')
SMC_AES_CPP = os.path.join(ROOT, 'third_party/Atmosphere/exosphere/program/source/smc/secmon_smc_aes.cpp')
KEY_TYPE_DEFAULT, SEAL_KEY_IMPORT_ES_DEVICE_KEY = 0, 3        # secmon_smc_aes.cpp KeyType / SealKey

# keyslot -> source. 'synthetic' keys are console-unique: generated once, they are the VM identity.
PROFILES = {
    # Erista: fusee leaves Master(13), DeviceMaster(12), DeviceMasterKeySourceKekErista(10), Device(15) loaded
    # (pkg1_se_key_slots.hpp). Exosphere @ 6e6af69 knows 22 key generations, so the master key must be 0x15.
    # The identity is Device(15) plus DeviceMasterKeySourceKek(10) for generations >= 4.0.0; exosphere only uses
    # slot 12 once as a kek for a random key and then overwrites it (secmon_boot_setup.cpp DeriveAllDeviceMasterKeys).
    'erista': {13: 'master_key_15', 12: 'synthetic', 10: 'synthetic', 15: 'synthetic'},
    # Mariko: exosphere derives everything from MarikoKek(12) and SecureBoot(14) (secmon_boot_setup.cpp).
    'mariko': {12: 'mariko_kek', 14: 'synthetic'},
}

# secmon_volatile_context.hpp VolatileKeys, as laid out in secmon_boot_key_data.s (22 key generations,
# 19 device master key generations starting at 4.0.0).
KEY_GENERATION_COUNT = 22
DEVICE_MASTER_KEY_COUNT = KEY_GENERATION_COUNT - 3
VOLATILE_KEYS = [('rsa_moduli', 3 * 0x100), ('package2_aes_key', 0x10), ('master_key_source', 0x10),
                 ('device_master_key_source_kek_source', 0x10), ('mariko_dev_master_kek_source', 0x10),
                 ('mariko_prod_master_kek_source', 0x10),
                 ('dev_master_key_vectors', KEY_GENERATION_COUNT * 0x10),
                 ('prod_master_key_vectors', KEY_GENERATION_COUNT * 0x10),
                 ('device_master_key_source_sources', DEVICE_MASTER_KEY_COUNT * 0x10),
                 ('dev_device_master_kek_sources', DEVICE_MASTER_KEY_COUNT * 0x10),
                 ('prod_device_master_kek_sources', DEVICE_MASTER_KEY_COUNT * 0x10)]
VOLATILE_KEYS_SIZE = sum(n for _, n in VOLATILE_KEYS)

# Global sources used by FS (bis keys) and exosphere (secmon_smc_aes.cpp), looked up by name in prod.keys.
BIS_SOURCES = ['retail_specific_aes_key_source', 'aes_kek_generation_source', 'aes_key_generation_source',
               'bis_kek_source', 'bis_key_source_00', 'bis_key_source_01', 'bis_key_source_02']


def parse_keys(path):
    keys = {}
    with open(path) as f:
        for line in f:
            if '=' in line:
                name, value = (s.strip() for s in line.split('=', 1))
                keys[name] = value
    return keys


def aes_dec(key, data):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(data) + d.finalize()


def parse_volatile_keys(path=KEY_DATA_S):
    """Byte image of exosphere's VolatileKeys from its assembly source, split into named fields."""
    with open(path) as f:
        text = f.read()
    body = text.split('_ZN3ams6secmon4boot15VolatileKeyDataE:', 1)[1]
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    data = bytes(int(b, 16) for line in re.findall(r'^\s*\.byte\s+(.*)$', body, re.M) for b in line.split(','))
    if len(data) != VOLATILE_KEYS_SIZE:
        raise ValueError('unexpected VolatileKeys size 0x%x' % len(data))
    fields, off = {}, 0
    for name, size in VOLATILE_KEYS:
        fields[name] = data[off:off + size]
        off += size
    return fields


def parse_smc_table(name, path=SMC_AES_CPP):
    """A u8[N][16] table of exosphere's secmon_smc_aes.cpp (designated initializers, in enum order)."""
    with open(path) as f:
        text = f.read()
    body = re.search(r'constexpr const u8 %s\[[^\]]*\]\[AesKeySize\] = \{(.*?)\n\s*\};' % name, text, re.S).group(1)
    return [bytes(int(b, 16) for b in re.findall(r'0x([0-9A-Fa-f]{2})', row))
            for row in re.findall(r'=\s*\{([^}]*)\}', body)]


def es_device_key_kek(keys):
    """The key exosphere decrypts es' device key blob with (ImportEsDeviceKey): GenerateAesKek(eticket_rsa_kekek_source,
    generation 1.0.0, KeyType_Default, SealKey_ImportEsDeviceKey), then eticket_rsa_kek_source (secmon_smc_aes.cpp)."""
    static = bytes(a ^ b for a, b in zip(parse_smc_table('KeyTypeSources')[KEY_TYPE_DEFAULT],
                                         parse_smc_table('SealKeyMasks')[SEAL_KEY_IMPORT_ES_DEVICE_KEY]))
    kek = aes_dec(aes_dec(get_key(keys, 'master_key_00'), static), get_key(keys, 'eticket_rsa_kekek_source'))
    return aes_dec(kek, get_key(keys, 'eticket_rsa_kek_source'))


def device_unique_key(soc, ident, keys):
    """Key exosphere uses for device-unique generation 0 (secmon_smc_aes.cpp PrepareDeviceMasterKey)."""
    if soc == 'erista':
        return read_secret(os.path.join(ident, 'aeskeyslot15.bin'))                 # Device keyslot
    # Mariko: DMK[4.0.0] (secmon_boot_setup.cpp DeriveAllDeviceMasterKeys), from the SBK and master key 0.
    v = parse_volatile_keys()
    sbk = read_secret(os.path.join(ident, 'aeskeyslot14.bin'))
    master_key_0 = get_key(keys, 'master_key_00')
    dmk_source_kek = aes_dec(sbk, v['device_master_key_source_kek_source'])
    kek = aes_dec(master_key_0, v['prod_device_master_kek_sources'][:0x10])
    return aes_dec(kek, aes_dec(dmk_source_kek, v['device_master_key_source_sources'][:0x10]))


def derive_bis_keys(duk, src):
    """BIS keys 0..3 (crypt || tweak) as FS obtains them from spl (amsmitm_initialization.cpp)."""
    kek0 = aes_dec(duk, src['retail_specific_aes_key_source'])                      # GenerateSpecificAesKey
    kek = aes_dec(aes_dec(aes_dec(duk, src['aes_kek_generation_source']), src['bis_kek_source']),
                  src['aes_key_generation_source'])                                  # GenerateAesKek + GenerateAesKey
    out = []
    for n, (k, source) in enumerate(((kek0, 'bis_key_source_00'), (kek, 'bis_key_source_01'),
                                     (kek, 'bis_key_source_02'), (kek, 'bis_key_source_02'))):
        out.append(aes_dec(k, src[source][:0x10]) + aes_dec(k, src[source][0x10:]))
    return out


def get_key(keys, name, length=16):
    value = keys.get(name)
    if value is None:
        sys.exit('%s not found in prod.keys' % name)
    try:
        data = bytes.fromhex(value)
    except ValueError:
        sys.exit('%s is not valid hex' % name)
    if len(data) != length:
        sys.exit('%s has unexpected length %d' % (name, len(data)))
    return data


def read_secret(path):
    with open(path, 'rb') as f:
        return f.read()


def write_secret(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', choices=sorted(PROFILES), required=True)
    ap.add_argument('--prod-keys', required=True)
    ap.add_argument('--identity', help='identity dir (default ~/.horizonvm/identity/<soc>)')
    ap.add_argument('--derive-bis', action='store_true', help='also write bis.bin (BIS keys 0..3, crypt||tweak)')
    args = ap.parse_args()
    os.umask(0o077)   # identity and secrets are private

    ident = os.path.expanduser(args.identity or '~/.horizonvm/identity/%s' % args.soc)
    os.makedirs(ident, mode=0o700, exist_ok=True)
    keys = parse_keys(args.prod_keys)

    for slot, source in sorted(PROFILES[args.soc].items()):
        path = os.path.join(ident, 'aeskeyslot%d.bin' % slot)
        if source == 'synthetic':
            if not os.path.exists(path):
                write_secret(path, secrets.token_bytes(16))
                print('aeskeyslot%d: created (synthetic)' % slot)
            else:
                print('aeskeyslot%d: kept (synthetic)' % slot)
            continue
        write_secret(path, get_key(keys, source))
        print('aeskeyslot%d: ok (%s)' % (slot, source))

    if args.derive_bis:
        src = {name: get_key(keys, name, 32 if name.startswith('bis_key_source') else 16) for name in BIS_SOURCES}
        write_secret(os.path.join(ident, 'bis.bin'), b''.join(derive_bis_keys(device_unique_key(args.soc, ident, keys), src)))
        print('bis.bin: ok (derived)')


if __name__ == '__main__':
    main()
