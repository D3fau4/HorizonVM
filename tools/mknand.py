#!/usr/bin/env python3
"""Build a HorizonVM eMMC: a per-partition folder tree from a firmware dump (--fw) and/or the BIS-encrypted
image tegra_qemu attaches to SDMMC4 (--image), and check an image against its tree (--verify)."""
import argparse
import glob
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

import hvm_nand as nand

TREE_DIRS = ['PRODINFOF', 'SAFE', 'SYSTEM/Contents/registered', 'SYSTEM/Contents/placehld', 'SYSTEM/save',
             'SYSTEM/saveMeta', 'USER/Contents/registered', 'USER/Contents/placehld', 'USER/save',
             'USER/saveMeta', 'USER/temp']
MTOOLS_ENV = dict(os.environ, MTOOLS_SKIP_CHECK='1', MTOOLS_NO_VFAT='0')


def populate_tree(tree, fw):
    """SYSTEM holds every NCA of the dump, flat as ncm's BuiltInSystem storage expects (registered/<id>.nca)."""
    ncas = sorted(glob.glob(os.path.join(fw, 'sysupdate-*', '*.nca')))
    if not ncas:
        sys.exit('no NCAs under %s/sysupdate-*/' % fw)
    for d in TREE_DIRS:
        os.makedirs(os.path.join(tree, d), mode=0o700, exist_ok=True)
    reg = os.path.join(tree, 'SYSTEM/Contents/registered')
    for src in ncas:
        name = os.path.basename(src)
        shutil.copyfile(src, os.path.join(reg, name[:32] + '.nca'))    # <id>.cnmt.nca -> <id>.nca
    cal0 = os.path.join(tree, 'PRODINFO.bin')
    if not os.path.exists(cal0):
        with open(cal0, 'wb') as f:
            f.write(nand.build_blank_cal0())
    return len(ncas)


def extents(path, size):
    """Data extents of a sparse file, widened to whole XTS units."""
    fd = os.open(path, os.O_RDONLY)
    try:
        off = 0
        while off < size:
            try:
                start = os.lseek(fd, off, os.SEEK_DATA)
            except OSError:
                return
            end = os.lseek(fd, start, os.SEEK_HOLE)
            yield (start // nand.XTS_SECTOR * nand.XTS_SECTOR,
                   min(size, (end + nand.XTS_SECTOR - 1) // nand.XTS_SECTOR * nand.XTS_SECTOR))
            off = end
    finally:
        os.close(fd)


def fat_metadata_end(plain):
    """End of the reserved sectors + FATs + (FAT12/16) root directory, plus the first data cluster."""
    with open(plain, 'rb') as f:
        bpb = f.read(0x60)
    bps, spc, reserved, nfats, root_entries, _, _, fat16 = struct.unpack_from('<HBHBHHBH', bpb, 11)
    fat_size = fat16 or struct.unpack_from('<I', bpb, 36)[0]
    return (reserved + nfats * fat_size) * bps + root_entries * 32 + spc * bps


def make_fat(name, src_dir, tmp, size=None):
    size = size or nand.PART[name][2]
    plain = os.path.join(tmp, name + '.fat')
    with open(plain, 'wb') as f:
        f.truncate(size)
    subprocess.run(['mkfs.fat', '--invariant', '-S', '512', '-n', name[:11]] + nand.FAT_OPTS[name] + [plain],
                   check=True, stdout=subprocess.DEVNULL)
    entries = sorted(os.listdir(src_dir)) if os.path.isdir(src_dir) else []
    if entries:
        subprocess.run(['mcopy', '-s', '-p', '-m', '-i', plain] + [os.path.join(src_dir, e) for e in entries] + ['::/'],
                       check=True, env=MTOOLS_ENV)
    return plain


def write_encrypted(img, part_off, key, plain, size, ranges):
    with open(plain, 'rb') as src, open(img, 'r+b') as dst:
        for start, end in ranges:
            for off in range(start, end, 1 << 22):
                n = min(1 << 22, end - off)
                src.seek(off)
                data = src.read(n).ljust(n, b'\0')
                dst.seek(part_off + off)
                dst.write(nand.xts(key, data, off // nand.XTS_SECTOR, True))


def merge_ranges(ranges):
    out = []
    for s, e in sorted(ranges):
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def build_image(soc, tree, img):
    keys = nand.load_bis_keys(soc)
    tmp_root = os.path.join(nand.HVM, 'tmp')
    os.makedirs(tmp_root, mode=0o700, exist_ok=True)
    with open(img, 'wb') as f:
        f.truncate(nand.IMAGE_SIZE)
    user = 2 * nand.BOOT_PART_SIZE
    with open(img, 'r+b') as f:
        for i, boot in enumerate(('BOOT0.bin', 'BOOT1.bin')):
            p = os.path.join(tree, boot)
            if os.path.exists(p):
                f.seek(i * nand.BOOT_PART_SIZE)
                f.write(read_file(p)[:nand.BOOT_PART_SIZE])
        primary, backup = nand.build_gpt(*nand.disk_guids(soc))
        f.seek(user)
        f.write(primary)
        f.seek(user + nand.USER_AREA_SIZE - len(backup))
        f.write(backup)

    tmp = tempfile.mkdtemp(dir=tmp_root)
    try:
        for name, off, size, _, bis, fs in nand.PARTITIONS:
            part_off = user + off
            if fs:
                plain = make_fat(name, os.path.join(tree, name), tmp)
                ranges = list(extents(plain, size)) + [(0, min(size, fat_metadata_end(plain)))]
                if size <= 0x4000000:   # small partitions: encrypt everything
                    ranges = [(0, size)]
                write_encrypted(img, part_off, keys[bis], plain, size, merge_ranges(
                    (s, (e + nand.XTS_SECTOR - 1) // nand.XTS_SECTOR * nand.XTS_SECTOR) for s, e in ranges))
                os.unlink(plain)
                continue
            src = os.path.join(tree, name + '.bin')
            if not os.path.exists(src):
                continue
            data = read_file(src)[:size]
            if bis is None:
                with open(img, 'r+b') as f:
                    f.seek(part_off)
                    f.write(data)
            else:
                plain = os.path.join(tmp, name + '.bin')
                with open(plain, 'wb') as f:
                    f.write(data.ljust(size, b'\0'))
                write_encrypted(img, part_off, keys[bis], plain, size, [(0, size)])
                os.unlink(plain)
    finally:
        shutil.rmtree(tmp)


def decrypt_partition(img, soc, name, out):
    """Decrypt one BIS partition of an image into a sparse plaintext file (holes stay holes)."""
    _, off, size, _, bis, _ = nand.PART[name]
    key = nand.load_bis_keys(soc)[bis]
    part_off = 2 * nand.BOOT_PART_SIZE + off
    with open(out, 'wb') as f:
        f.truncate(size)
    with open(img, 'rb') as src, open(out, 'r+b') as dst:
        for start, end in extents_in(img, part_off, size):
            for o in range(start, end, 1 << 22):
                n = min(1 << 22, end - o)
                src.seek(part_off + o)
                dst.seek(o)
                dst.write(nand.xts(key, src.read(n), o // nand.XTS_SECTOR, False))


def extents_in(img, part_off, size):
    """Data extents of the image inside one partition, relative to the partition, in whole XTS units."""
    fd = os.open(img, os.O_RDONLY)
    try:
        off = part_off
        while off < part_off + size:
            try:
                start = os.lseek(fd, off, os.SEEK_DATA)
            except OSError:
                return
            if start >= part_off + size:
                return
            end = min(os.lseek(fd, start, os.SEEK_HOLE), part_off + size)
            s = (start - part_off) // nand.XTS_SECTOR * nand.XTS_SECTOR
            e = min(size, (end - part_off + nand.XTS_SECTOR - 1) // nand.XTS_SECTOR * nand.XTS_SECTOR)
            yield s, e
            off = part_off + e
    finally:
        os.close(fd)


def read_file(path):
    with open(path, 'rb') as f:
        return f.read()


def file_hash(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.digest()


def tree_files(root):
    out = {}
    for dirpath, _, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            out[os.path.relpath(p, root).upper()] = p
    return out


def verify(soc, tree, img):
    """GPT (sgdisk -v), each FAT (fsck.fat -n + file hashes vs the tree), CAL0 header."""
    problems = []
    tmp_root = os.path.join(nand.HVM, 'tmp')
    os.makedirs(tmp_root, mode=0o700, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=tmp_root)
    try:
        user = os.path.join(tmp, 'user.img')
        with open(img, 'rb') as f, open(user, 'wb') as u:
            u.truncate(nand.USER_AREA_SIZE)
            f.seek(2 * nand.BOOT_PART_SIZE)
            u.write(f.read(34 * nand.LBA))
            f.seek(2 * nand.BOOT_PART_SIZE + nand.USER_AREA_SIZE - 33 * nand.LBA)
            u.seek(nand.USER_AREA_SIZE - 33 * nand.LBA)
            u.write(f.read(33 * nand.LBA))
        r = subprocess.run(['sgdisk', '-v', user], capture_output=True, text=True)
        out = r.stdout + r.stderr
        if r.returncode != 0 or 'No problems found' not in out or any(w in out for w in ('Warning', 'Caution', 'ERROR')):
            problems.append('GPT: ' + ' / '.join(l.strip() for l in out.splitlines() if l.strip())[:300])
        os.unlink(user)

        cal = os.path.join(tmp, 'PRODINFO')
        decrypt_partition(img, soc, 'PRODINFO', cal)
        cal0 = read_file(cal)[:nand.CAL0_SIZE]
        if not nand.check_cal0(cal0):
            problems.append('PRODINFO: CAL0 header/hash invalid')
        tree_cal = os.path.join(tree, 'PRODINFO.bin')
        if os.path.exists(tree_cal) and read_file(tree_cal) != cal0[:os.path.getsize(tree_cal)]:
            problems.append('PRODINFO: differs from the tree')
        os.unlink(cal)

        for name, _, size, _, _, fs in nand.PARTITIONS:
            if not fs:
                continue
            plain = os.path.join(tmp, name)
            decrypt_partition(img, soc, name, plain)
            r = subprocess.run(['fsck.fat', '-n', plain], capture_output=True, text=True)
            if r.returncode != 0:
                problems.append('%s: fsck.fat: %s' % (name, (r.stdout + r.stderr).strip().splitlines()[-1]))
            out = os.path.join(tmp, name + '.files')
            os.makedirs(out)
            # An empty root makes mcopy fail on '::/*'; the comparison below catches real problems.
            subprocess.run(['mcopy', '-s', '-n', '-i', plain, '::/*', out], env=MTOOLS_ENV, capture_output=True)
            want, got = tree_files(os.path.join(tree, name)), tree_files(out)
            if set(want) != set(got):
                problems.append('%s: files differ from the tree (%d vs %d)' % (name, len(got), len(want)))
            for rel in sorted(set(want) & set(got)):
                if file_hash(want[rel]) != file_hash(got[rel]):
                    problems.append('%s: %s content differs' % (name, rel))
            shutil.rmtree(out)
            os.unlink(plain)
    finally:
        shutil.rmtree(tmp)
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', required=True, choices=['erista', 'mariko'])
    ap.add_argument('--fw', help='firmware dump (sysupdate-*/ NCAs) to populate the folder tree')
    ap.add_argument('--image', action='store_true', help='build emmc.img from the folder tree')
    ap.add_argument('--verify', action='store_true', help='check emmc.img against the folder tree')
    ap.add_argument('--tree', help='folder tree (default ~/.horizonvm/nand/<soc>/dir)')
    ap.add_argument('--output', help='image path (default ~/.horizonvm/nand/<soc>/emmc.img)')
    args = ap.parse_args()
    os.umask(0o077)   # the tree and image hold firmware and the VM identity's data

    paths = nand.soc_paths(args.soc)
    tree = args.tree or paths['dir']
    img = args.output or paths['image']
    if args.fw:
        print('%s: %d NCAs' % (tree, populate_tree(tree, args.fw)))
    if args.image:
        build_image(args.soc, tree, img)
        print('%s: ok' % img)
    if args.verify:
        problems = verify(args.soc, tree, img)
        for p in problems:
            print('verify: ' + p)
        print('verify: %s' % ('ok' if not problems else 'FAIL'))
        sys.exit(1 if problems else 0)


if __name__ == '__main__':
    main()
