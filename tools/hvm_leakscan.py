#!/usr/bin/env python3
"""Look for the VM identities' secrets (SE keyslots, BIS keys, eTicket RSA key) outside the places meant to hold them.

Scanned: ~/.horizonvm (logs, NAND folder trees, tmp, ...) and the repository's files (tracked or not ignored).
Exempt: identity/ (where they live), ref/, the eMMC/SD images and overlays (BIS-encrypted or raw disks) and each
SoC's SD folder, where ams_mitm backs up the BIS keys (<ref>_BISKEYS.bin) by design. Prints only paths and counts,
never key material.
"""
import argparse
import fnmatch
import glob
import os
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
HVM = os.environ.get('HORIZONVM_HOME', os.path.expanduser('~/.horizonvm'))
SECRET_FILES = ('aeskeyslot*.bin', 'bis.bin', 'eticket_rsa.der')
EXEMPT_DIRS = ('identity', 'ref', 'sd')
EXEMPT_NAMES = ('emmc.img', 'overlay.img', 'overlay.map', 'sd.img')
CHUNK = 16


def secret_values(path):
    with open(path, 'rb') as f:
        data = f.read()
    if not path.endswith('.der'):
        return [data]
    key = serialization.load_der_private_key(data, None).private_numbers()   # the modulus is public (certificate)
    return [n.to_bytes((n.bit_length() + 7) // 8, 'big')
            for n in (key.d, key.p, key.q, key.dmp1, key.dmq1, key.iqmp)]


def secret_chunks(identity_root):
    """16-byte windows of every secret, skipping low-entropy ones (padding)."""
    chunks = set()
    for pattern in SECRET_FILES:
        for path in glob.glob(os.path.join(identity_root, '*', pattern)):
            for data in secret_values(path):
                for i in range(0, len(data) - CHUNK + 1, CHUNK):
                    c = data[i:i + CHUNK]
                    if len(set(c)) >= 8:
                        chunks.add(c)
    return chunks


def needles(chunks):
    """Raw bytes, hex dumps (both cases) and 64-bit register values (little-endian halves as printed by 0x%x).
    Raw needles are split at NUL/newline (grep patterns are lines) and kept from 8 bytes up."""
    raw, text = set(), set()
    for c in chunks:
        for piece in c.replace(b'\0', b'\n').split(b'\n'):
            if len(piece) >= 8:
                raw.add(piece)
        text.add(c.hex().encode())
        for half in (c[:8], c[8:]):
            text.add(half.hex().encode())
            value = b'%x' % int.from_bytes(half, 'little')
            if len(value) >= 12:
                text.add(value)
    return raw, text | {t.upper() for t in text}


def repo_files(repo, ignored=False):
    """Tracked and untracked files; with ignored=True the ignored ones instead (a key file there is still a leak)."""
    which = ['--others', '--ignored'] if ignored else ['--cached', '--others']
    out = subprocess.run(['git', '-C', repo, 'ls-files', '-z', '--exclude-standard'] + which,
                         capture_output=True, text=True, check=True).stdout
    return [os.path.join(repo, p) for p in out.split('\0') if p]


def targets(hvm, repo):
    for dirpath, dirnames, filenames in os.walk(hvm):
        if dirpath == hvm:
            dirnames[:] = [d for d in dirnames if d not in EXEMPT_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if name not in EXEMPT_NAMES and os.path.isfile(path) and not os.path.islink(path):   # no sockets
                yield path
    yield from (p for p in repo_files(repo) if os.path.isfile(p))


def grep_counts(patterns, paths, tmp):
    """{path: matching lines} for fixed-string patterns (GNU grep, Aho-Corasick); patterns stay in a private file."""
    if not patterns or not paths:
        return {}
    pat = os.path.join(tmp, 'patterns')
    with open(pat, 'wb') as f:
        f.write(b'\n'.join(sorted(patterns)) + b'\n')      # grep -F: Aho-Corasick over all of them
    counts = {}
    for i in range(0, len(paths), 500):
        out = subprocess.run(['grep', '-a', '-F', '-c', '-Z', '-f', pat] + ['--'] + paths[i:i + 500],
                             capture_output=True, env=dict(os.environ, LC_ALL='C')).stdout   # binary patterns: C locale
        for line in out.splitlines():
            path, _, n = line.partition(b'\0')
            if n and int(n):
                counts[path.decode()] = int(n)
    os.unlink(pat)
    return counts


def scan(hvm=HVM, repo=ROOT):
    """-> list of (path, what) findings."""
    raw, text = needles(secret_chunks(os.path.join(hvm, 'identity')))
    paths = list(targets(hvm, repo))
    findings = [(p, 'BIS key backup outside the SD folder') for p in paths if p.endswith('_BISKEYS.bin')]
    os.makedirs(os.path.join(hvm, 'tmp'), mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='leakscan-', dir=os.path.join(hvm, 'tmp')) as tmp:
        hits = grep_counts(raw | text, paths, tmp)
    findings += [(p, '%d line(s) with secret matches' % n) for p, n in sorted(hits.items())]
    findings += [(p, 'identity/key file inside the repository') for p in repo_files(repo) + repo_files(repo, True)
                 if any(fnmatch.fnmatch(os.path.basename(p), pat) for pat in SECRET_FILES + ('*.keys',))]
    return findings


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.parse_args()
    chunks = secret_chunks(os.path.join(HVM, 'identity'))
    findings = scan()
    for path, what in findings:
        print('leak: %s: %s' % (path, what))
    print('leak scan: %d secret chunks, %d finding(s)' % (len(chunks), len(findings)))
    sys.exit(1 if findings or not chunks else 0)


if __name__ == '__main__':
    main()
