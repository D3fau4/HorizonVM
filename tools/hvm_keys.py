#!/usr/bin/env python3
"""Prepare SE keyslot secrets for a HorizonVM SoC profile. Never prints key material."""
import argparse
import os
import secrets
import sys

# keyslot -> source. 'synthetic' keys are console-unique: generated once, they are the VM identity.
PROFILES = {
    # Erista: fusee leaves Master(13), DeviceMaster(12), DeviceMasterKeySourceKekErista(10), Device(15) loaded
    # (pkg1_se_key_slots.hpp). Exosphere @ 6e6af69 knows 22 key generations, so the master key must be 0x15.
    'erista': {13: 'master_key_15', 12: 'synthetic', 10: 'synthetic', 15: 'synthetic'},
    # Mariko: exosphere derives everything from MarikoKek(12) and SecureBoot(14) (secmon_boot_setup.cpp).
    'mariko': {12: 'mariko_kek', 14: 'synthetic'},
}


def parse_keys(path):
    keys = {}
    with open(path) as f:
        for line in f:
            if '=' in line:
                name, value = (s.strip() for s in line.split('=', 1))
                keys[name] = value
    return keys


def write_secret(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', choices=sorted(PROFILES), required=True)
    ap.add_argument('--prod-keys', required=True)
    ap.add_argument('--identity', help='identity dir (default ~/.horizonvm/identity/<soc>)')
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
        value = keys.get(source)
        if value is None:
            sys.exit('aeskeyslot%d: %s not found in %s' % (slot, source, args.prod_keys))
        try:
            data = bytes.fromhex(value)
        except ValueError:
            sys.exit('aeskeyslot%d: %s is not valid hex' % (slot, source))
        if len(data) != 16:
            sys.exit('aeskeyslot%d: %s has unexpected length %d' % (slot, source, len(data)))
        write_secret(path, data)
        print('aeskeyslot%d: ok (%s)' % (slot, source))


if __name__ == '__main__':
    main()
