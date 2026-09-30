#!/usr/bin/env python3
"""Generate a HorizonVM PRODINFO (CAL0 v7) for a SoC profile.

Identity (serial number, WLAN/BT addresses, battery lot, unique random number, device id in the certificates) is
synthetic, derived from the VM identity's ECID; keys are zero. Only the non-identifying factory calibration of
IMPORTED is taken from an optional reference PRODINFO, otherwise the defaults of CaramelDunes/prodinfo_gen are used.
Layout: switchbrew Calibration; blocks run up to the next field, CRC16 in their last two bytes
(amsmitm_prodinfo_utils.cpp). Blocks HOS treats as optional keep an invalid CRC (= absent) unless the reference
provides them: with a valid CRC HOS uses them (prodinfo_gen cal_blocks.h). Written to the eMMC tree's
PRODINFO.bin unless -o is given.
"""
import argparse
import hashlib
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

import hvm_keys
import hvm_nand as nand

VERSION = 7
BODY_SIZE = nand.CAL0_SIZE - 0x40
REF_DEFAULT = os.path.join(nand.HVM, 'ref', 'prodinfo-ref.bin')

# (offset, name) in layout order; each block ends where the next one starts.
FIELDS = [
    (0x0040, 'ConfigurationId1'), (0x0060, 'Reserved'), (0x0080, 'WlanCountryCodes'),
    (0x0210, 'WlanMacAddress'), (0x0220, 'BdAddress'), (0x0230, 'AccelerometerOffset'),
    (0x0238, 'AccelerometerScale'), (0x0240, 'GyroscopeOffset'), (0x0248, 'GyroscopeScale'),
    (0x0250, 'SerialNumber'), (0x0270, 'EccP256DeviceKey'), (0x02B0, 'EccP256DeviceCertificate'),
    (0x0440, 'EccB233DeviceKey'), (0x0480, 'EccB233DeviceCertificate'), (0x0610, 'EccP256ETicketKey'),
    (0x0650, 'EccP256ETicketCertificate'), (0x07E0, 'EccB233ETicketKey'), (0x0820, 'EccB233ETicketCertificate'),
    (0x09B0, 'SslKey'), (0x0AD0, 'SslCertificateSize'), (0x0AE0, 'SslCertificate'),
    (0x12E0, 'SslCertificateHash'), (0x1300, 'RandomNumber'), (0x2300, 'RandomNumberHash'),
    (0x2320, 'GameCardKey'), (0x2440, 'GameCardCertificate'), (0x2840, 'GameCardCertificateHash'),
    (0x2860, 'Rsa2048ETicketKey'), (0x2A90, 'Rsa2048ETicketCertificate'), (0x2CE0, 'BatteryLot'),
    (0x2D00, 'SpeakerCalibrationValue'), (0x3510, 'RegionCode'), (0x3520, 'AmiiboKey'),
    (0x3580, 'AmiiboEcqvCertificate'), (0x35A0, 'AmiiboEcdsaCertificate'), (0x3620, 'AmiiboEcqvBlsKey'),
    (0x3670, 'AmiiboEcqvBlsCertificate'), (0x36A0, 'AmiiboEcqvBlsRootCertificate'), (0x3740, 'ProductModel'),
    (0x3750, 'ColorVariation'), (0x3760, 'LcdBacklightBrightnessMapping'), (0x3770, 'ExtendedEccB233DeviceKey'),
    (0x37D0, 'ExtendedEccP256ETicketKey'), (0x3830, 'ExtendedEccB233ETicketKey'),
    (0x3890, 'ExtendedRsa2048ETicketKey'), (0x3AE0, 'ExtendedSslKey'), (0x3C20, 'ExtendedGameCardKey'),
    (0x3D60, 'LcdVendorId'), (0x3D70, 'ExtendedRsa2048DeviceKey'), (0x3FC0, 'Rsa2048DeviceCertificate'),
    (0x4210, 'UsbTypeCPowerSourceCircuitVersion'), (0x4220, 'HousingSubColor'), (0x4230, 'HousingBezelColor'),
    (0x4240, 'HousingMainColor1'), (0x4250, 'HousingMainColor2'), (0x4260, 'HousingMainColor3'),
    (0x4270, 'AnalogStickModuleTypeL'), (0x4280, 'AnalogStickModelParameterL'),
    (0x42A0, 'AnalogStickFactoryCalibrationL'), (0x42B0, 'AnalogStickModuleTypeR'),
    (0x42C0, 'AnalogStickModelParameterR'), (0x42E0, 'AnalogStickFactoryCalibrationR'),
    (0x42F0, 'ConsoleSixAxisSensorModuleType'), (0x4300, 'ConsoleSixAxisSensorHorizontalOffset'),
    (0x4310, 'BatteryVersion'), (0x4320, 'TouchIcVendorId'), (0x4330, 'ColorModel'),
    (0x4340, 'ConsoleSixAxisSensorMountType'),
]
END = 0x4350
BLOCKS = {name: (off, nxt - off) for (off, name), nxt in zip(FIELDS, [f[0] for f in FIELDS[1:]] + [END])}
# Except the MAC addresses: 6 bytes + CRC16, then 8 bytes of zero padding (prodinfo_gen cal_blocks.h; settings
# checks the CRC at +6 and answers set:cal GetBluetoothBdAddress/GetWirelessLanMacAddress with 2105-0582 otherwise).
BLOCKS.update(WlanMacAddress=(0x210, 8), BdAddress=(0x220, 8))
# Raw data protected by a separate SHA-256 block instead of a CRC, and unused space.
SHA_DATA = {'SslCertificate': 'SslCertificateHash', 'RandomNumber': 'RandomNumberHash',
            'GameCardCertificate': 'GameCardCertificateHash'}
NO_CRC = set(SHA_DATA) | set(SHA_DATA.values()) | {'Reserved'}
# Present only if the reference has them (a valid CRC makes HOS use them), or not at all for the device RSA pair
# and the extended keys, which are encrypted with device keys the VM does not model.
OPTIONAL = {
    'ExtendedRsa2048DeviceKey', 'Rsa2048DeviceCertificate', 'UsbTypeCPowerSourceCircuitVersion',
    'AnalogStickModuleTypeL', 'AnalogStickModelParameterL', 'AnalogStickFactoryCalibrationL',
    'AnalogStickModuleTypeR', 'AnalogStickModelParameterR', 'AnalogStickFactoryCalibrationR',
    'ConsoleSixAxisSensorModuleType', 'ConsoleSixAxisSensorHorizontalOffset', 'BatteryVersion',
    'TouchIcVendorId', 'ConsoleSixAxisSensorMountType',
}
ABSENT = {'ExtendedRsa2048DeviceKey', 'Rsa2048DeviceCertificate', 'ExtendedEccB233DeviceKey', 'ExtendedGameCardKey'}
# Written only with the es key sources (eticket_rsa_kek*_source in prod.keys), absent otherwise.
ETICKET_KEY = 'ExtendedRsa2048ETicketKey'

# Non-identifying factory calibration imported from the reference (approved list).
IMPORTED = {
    'ConfigurationId1', 'WlanCountryCodes', 'AccelerometerOffset', 'AccelerometerScale', 'GyroscopeOffset',
    'GyroscopeScale', 'SpeakerCalibrationValue', 'RegionCode', 'ColorVariation', 'LcdBacklightBrightnessMapping',
    'LcdVendorId', 'UsbTypeCPowerSourceCircuitVersion', 'HousingSubColor', 'HousingBezelColor', 'HousingMainColor1',
    'HousingMainColor2', 'HousingMainColor3', 'AnalogStickModuleTypeL', 'AnalogStickModelParameterL',
    'AnalogStickFactoryCalibrationL', 'AnalogStickModuleTypeR', 'AnalogStickModelParameterR',
    'AnalogStickFactoryCalibrationR', 'ConsoleSixAxisSensorModuleType', 'ConsoleSixAxisSensorHorizontalOffset',
    'BatteryVersion', 'TouchIcVendorId', 'ColorModel', 'ConsoleSixAxisSensorMountType',
}
# ProductModel follows the SoC profile (settings ProductModel: 1 = Nx/Icosa, 3 = Iowa), not the reference.
PROFILES = {'erista': {'product_model': 1, 'serial_prefix': 'XAW1'},
            'mariko': {'product_model': 3, 'serial_prefix': 'XKW1'}}

# prodinfo_gen defaults (cal0.c) for a console without factory data.
DEFAULTS = {
    'ConfigurationId1': b'MP_00_01_00_00',
    'WlanCountryCodes': bytes((0x01, 0, 0, 0, 0, 0, 0, 0, 0x52, 0x31)),
    'AccelerometerOffset': bytes.fromhex('fcfffaffc400'), 'AccelerometerScale': bytes.fromhex('4606ff3fff3f'),
    'GyroscopeOffset': bytes.fromhex('fdffddfff3ff'), 'GyroscopeScale': bytes.fromhex('1b13ff3fff3f'),
    'SpeakerCalibrationValue': bytes.fromhex(
        '0003005aed870000c1611eaf095bc960188d0000de2a0fdbfcb60000089301f31faa00001fb4004b'
        '1fb40800080000c160411f8004806b3004041212000094940000aaaa500000802f80000000000000'),
    'RegionCode': struct.pack('<I', 1),
    'ColorVariation': b'\x01',
    'LcdBacklightBrightnessMapping': bytes.fromhex('0000803f000000000ad7a33c'),
    'HousingSubColor': bytes((0x00, 0xFF, 0x00, 0xFF)), 'HousingMainColor2': bytes((0xFF, 0x00, 0xFF, 0xFF)),
    'HousingMainColor3': bytes((0xFF, 0xFF, 0x00, 0xFF)),
}
SSL_CERTIFICATE_SIZE = 0x5E9                     # prodinfo_gen: an empty certificate of the usual size
DEVICE_ID_PREFIX = 0x6300000000000000            # certificate device id = "NX" + %016X + "-0" (prodinfo_gen)
CERT_NAME_OFFSET = 0xC4


def crc_ok(cal, name):
    off, size = BLOCKS[name]
    return nand.crc16(cal[off:off + size - 2]) == struct.unpack_from('<H', cal, off + size - 2)[0]


class Derive:
    """Deterministic synthetic values from the VM identity."""

    def __init__(self, ecid):
        self.seed = json.dumps(ecid, sort_keys=True).encode()

    def bytes(self, label, n):
        out, i = b'', 0
        while len(out) < n:
            out += hashlib.sha256(b'horizonvm-cal0:%s:%d:' % (label.encode(), i) + self.seed).digest()
            i += 1
        return out[:n]

    def mac(self, label):
        b = bytearray(self.bytes(label, 6))
        b[0] = (b[0] | 0x02) & ~0x01             # locally administered, unicast
        return bytes(b)

    def digits(self, label, n):
        return ''.join(str(b % 10) for b in self.bytes(label, n))


def check_digit(digits):
    """Serial check digit (switchbrew Product_Information, as on the 3DS): 3 x even positions + odd positions."""
    odd = sum(int(c) for c in digits[0::2])
    even = sum(int(c) for c in digits[1::2])
    return str((10 - (3 * even + odd) % 10) % 10)


def serial_number(soc, derive):
    prefix = PROFILES[soc]['serial_prefix']
    body = prefix[3:] + derive.digits('serial', 9)
    return (prefix[:3] + body + check_digit(body)).encode()


def device_id(ecid):
    """fuse::GetDeviceId (libexosphere fuse_api.cpp): what spl GetConfig(DeviceId) returns for this identity."""
    clot0 = 0
    for i in range(4, -1, -1):
        clot0 = clot0 * 36 + ((ecid['lot0'] >> (i * 6)) & 0x3F)
    return (ecid['y'] & 0x1FF) | (ecid['x'] & 0x1FF) << 9 | (ecid['wafer'] & 0x3F) << 18 | \
        (clot0 & ((1 << 26) - 1)) << 24 | (ecid['fab'] & 0x3F) << 50


def device_certificate(size, name):
    """Only the subject name: HOS compares its device id with the fuses' (EccB233DeviceCertificate before 14.0.0,
    Rsa2048ETicketCertificate since); no signature, nothing on the VM verifies it against Nintendo's CA."""
    cert = bytearray(size)
    cert[CERT_NAME_OFFSET:CERT_NAME_OFFSET + len(name)] = name
    return bytes(cert)


RSA_SIZE = 0x100
DEVICE_UNIQUE_PADDING = 8                        # secmon_smc_device_unique_data.hpp: iv | enc(data, pad, id) | mac


def eticket_rsa_key(ident):
    """The VM's RSA-2048 eTicket device key: generated once, kept with the identity (0600)."""
    path = os.path.join(ident, 'eticket_rsa.der')
    if not os.path.exists(path):
        der = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        hvm_keys.write_secret(path, der)
    return serialization.load_der_private_key(hvm_keys.read_secret(path), password=None)


def encrypt_device_unique(key, iv, data, device_id):
    """exosphere's EncryptDeviceUniqueData: AES-128-CTR over data | padding | big-endian device id, then a GMAC
    (AES-GCM, 16-byte iv, the plaintext as AAD) - what DecryptDeviceUniqueData verifies."""
    plain = data + bytes(DEVICE_UNIQUE_PADDING) + struct.pack('>Q', device_id)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor().update(plain)
    mac = AESGCM(key).encrypt(iv, b'', plain)
    return iv + enc + mac


def eticket_key_block(kek, private_key, device_id, iv):
    n = private_key.private_numbers()
    data = n.d.to_bytes(RSA_SIZE, 'big') + n.public_numbers.n.to_bytes(RSA_SIZE, 'big') + struct.pack('>I', n.public_numbers.e)
    data += bytes(-len(data) % 16)               # AlignUp(2 * RsaSize + sizeof(u32), AesBlockSize)
    return encrypt_device_unique(kek, iv, data, device_id)


def build_cal0(soc, ecid, ref=None, eticket=None):
    """eticket: (kek, RSA private key) to write a valid ExtendedRsa2048ETicketKey, else it stays absent."""
    derive = Derive(ecid)
    cal = bytearray(nand.CAL0_SIZE)

    def put(name, data):
        off, size = BLOCKS[name]
        room = size if name in NO_CRC else size - 2
        if len(data) > room:
            raise ValueError('%s: 0x%x bytes do not fit in 0x%x' % (name, len(data), room))
        cal[off:off + len(data)] = data

    for name, data in DEFAULTS.items():
        put(name, data)
    bezel_main = struct.pack('<Q', device_id(ecid))
    put('HousingBezelColor', bezel_main[0:3] + b'\xff')
    put('HousingMainColor1', bezel_main[3:6] + b'\xff')
    present = set()
    if ref is not None:
        if len(ref) < nand.CAL0_SIZE or ref[:4] != b'CAL0':
            raise ValueError('reference is not a CAL0')
        for name in IMPORTED:                    # blocks the reference itself never wrote keep the default
            if crc_ok(ref, name):
                off, size = BLOCKS[name]
                cal[off:off + size - 2] = ref[off:off + size - 2]
                present.add(name)

    dev = b'NX%016X-0' % (device_id(ecid) | DEVICE_ID_PREFIX)
    put('ProductModel', struct.pack('<I', PROFILES[soc]['product_model']))
    put('WlanMacAddress', derive.mac('wlan'))
    put('BdAddress', derive.mac('bd'))
    put('SerialNumber', serial_number(soc, derive))
    lot = bytearray(derive.digits('battery', 16).encode())
    lot[7] = ord('A')                            # powctl battery vendor (max17050 driver), 'A' is its default
    put('BatteryLot', bytes(lot))
    put('RandomNumber', derive.bytes('random', BLOCKS['RandomNumber'][1]))
    put('EccB233DeviceCertificate', device_certificate(0x180, dev))
    eticket_cert = bytearray(device_certificate(0x240, dev))
    if eticket is not None:
        kek, private_key = eticket
        pub = private_key.public_key().public_numbers()
        eticket_cert[0x108:0x208] = pub.n.to_bytes(RSA_SIZE, 'big')      # certificate public key: modulus, exponent
        eticket_cert[0x208:0x20C] = struct.pack('>I', pub.e)
        put(ETICKET_KEY, eticket_key_block(kek, private_key, device_id(ecid) | DEVICE_ID_PREFIX,
                                           derive.bytes('eticket-iv', 16)))
    put('Rsa2048ETicketCertificate', bytes(eticket_cert))
    put('SslCertificateSize', struct.pack('<Q', SSL_CERTIFICATE_SIZE))

    for data, hash_name in SHA_DATA.items():
        off, size = BLOCKS[data]
        n = struct.unpack_from('<Q', cal, BLOCKS['SslCertificateSize'][0])[0] if data == 'SslCertificate' else size
        put(hash_name, hashlib.sha256(cal[off:off + n]).digest())
    for name, (off, size) in BLOCKS.items():
        if name in NO_CRC or name in ABSENT or (name in OPTIONAL and name not in present) or \
                (name == ETICKET_KEY and eticket is None):
            continue
        struct.pack_into('<H', cal, off + size - 2, nand.crc16(cal[off:off + size - 2]))

    struct.pack_into('<4sIIHH', cal, 0, b'CAL0', VERSION, BODY_SIZE, PROFILES[soc]['product_model'], 0)
    struct.pack_into('<H', cal, 0x1E, nand.crc16(cal[:0x1E]))
    cal[0x20:0x40] = hashlib.sha256(cal[0x40:0x40 + BODY_SIZE]).digest()
    return bytes(cal)


def check_blocks(cal):
    """Names of required blocks whose CRC16 / SHA-256 does not match."""
    bad = [n for n in BLOCKS if n not in NO_CRC | OPTIONAL | ABSENT | {ETICKET_KEY} and not crc_ok(cal, n)]
    for data, hash_name in SHA_DATA.items():
        off, size = BLOCKS[data]
        n = struct.unpack_from('<Q', cal, BLOCKS['SslCertificateSize'][0])[0] if data == 'SslCertificate' else size
        if hashlib.sha256(cal[off:off + n]).digest() != cal[BLOCKS[hash_name][0]:BLOCKS[hash_name][0] + 0x20]:
            bad.append(hash_name)
    return bad


def load_ecid(soc):
    with open(os.path.join(nand.soc_paths(soc)['identity'], 'ecid.json')) as f:
        return json.load(f)


def load_eticket(soc, prod_keys):
    """(kek, key) when prod.keys has the es key sources; None otherwise (the block then stays absent)."""
    if not prod_keys or not os.path.exists(prod_keys):
        return None
    keys = hvm_keys.parse_keys(prod_keys)
    if not all(k in keys for k in ('master_key_00', 'eticket_rsa_kek_source', 'eticket_rsa_kekek_source')):
        return None
    return hvm_keys.es_device_key_kek(keys), eticket_rsa_key(nand.soc_paths(soc)['identity'])


def load_ref(path):
    if path and os.path.exists(path):
        with open(path, 'rb') as f:
            return f.read()
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--soc', required=True, choices=sorted(PROFILES))
    ap.add_argument('--ref', default=REF_DEFAULT, help='reference PRODINFO for the factory calibration '
                    '(default ~/.horizonvm/ref/prodinfo-ref.bin if present)')
    ap.add_argument('--prod-keys', help='prod.keys with eticket_rsa_kek_source and eticket_rsa_kekek_source: '
                    'writes the eTicket device key es imports (absent otherwise)')
    ap.add_argument('-o', '--output', help='default: ~/.horizonvm/nand/<soc>/dir/PRODINFO.bin')
    args = ap.parse_args()
    os.umask(0o077)
    eticket = load_eticket(args.soc, args.prod_keys)
    if args.prod_keys and eticket is None:
        print('warning: no eticket_rsa_kek*_source in %s: ExtendedRsa2048ETicketKey stays absent' % args.prod_keys)
    cal = build_cal0(args.soc, load_ecid(args.soc), load_ref(args.ref), eticket)
    if check_blocks(cal) or not nand.check_cal0(cal):
        sys.exit('internal error: generated CAL0 does not validate')
    out = args.output or os.path.join(nand.soc_paths(args.soc)['dir'], 'PRODINFO.bin')
    with open(out, 'wb') as f:
        f.write(cal)
    print('%s: ok (%s, calibration from %s, eTicket key %s)' % (
        out, args.soc, 'reference' if load_ref(args.ref) else 'defaults', 'written' if eticket else 'absent'))


if __name__ == '__main__':
    main()
