#!/usr/bin/env python3
"""Build a HorizonVM SD card: its folder (the card's root) from an Atmosphère release (--dist) and/or the image
tegra_qemu attaches to SDMMC1 (--image: MBR + one FAT32 volume), and check an image against its folder (--verify)."""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

import hvm_nand as nand
import mknand

SD_TOP = ('atmosphere/',)   # only what the VM uses (no bootloader/, switch/, hbmenu.nro)


def parse_size(text):
    units = {'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30}
    n = int(text[:-1]) * units[text[-1].upper()] if text[-1].upper() in units else int(text)
    if n % (1 << 20) or n < (4 << 30):
        sys.exit('--size: a whole number of MiB, at least 4G (FAT32 with 32 KiB clusters)')
    return n


def populate(tree, dist):
    """Copy (overwrite) the release's atmosphere/ into the card; files the guest created are kept."""
    os.makedirs(tree, mode=0o700, exist_ok=True)
    count = 0
    if os.path.isdir(dist):
        for dirpath, _, files in os.walk(dist):
            for fn in files:
                rel = os.path.relpath(os.path.join(dirpath, fn), dist)
                if rel.replace(os.sep, '/').startswith(SD_TOP):
                    os.makedirs(os.path.join(tree, os.path.dirname(rel)), mode=0o700, exist_ok=True)
                    shutil.copyfile(os.path.join(dirpath, fn), os.path.join(tree, rel))
                    count += 1
        return count
    with zipfile.ZipFile(dist) as z:
        for info in z.infolist():
            if info.filename.startswith(SD_TOP):
                if info.is_dir():
                    os.makedirs(os.path.join(tree, info.filename), mode=0o700, exist_ok=True)
                    continue
                dest = os.path.join(tree, info.filename)
                os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
                with z.open(info) as src, open(dest, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                count += 1
    return count


def build_image(soc, tree, img):
    size = nand.sd_size(soc)
    tmp_root = os.path.join(nand.HVM, 'tmp')
    os.makedirs(tmp_root, mode=0o700, exist_ok=True)
    with open(img, 'wb') as f:
        f.truncate(size)
        f.write(nand.build_mbr(size, nand.sd_disk_id(soc)))
    tmp = tempfile.mkdtemp(dir=tmp_root)
    try:
        plain = mknand.make_fat('SD', tree, tmp, size - nand.SD_PART_OFFSET)
        with open(plain, 'rb') as src, open(img, 'r+b') as dst:
            for start, end in mknand.extents(plain, size - nand.SD_PART_OFFSET):
                for off in range(start, end, 1 << 22):
                    src.seek(off)
                    data = src.read(min(1 << 22, end - off))
                    dst.seek(nand.SD_PART_OFFSET + off)
                    dst.write(data)
    finally:
        shutil.rmtree(tmp)


def verify(soc, tree, img):
    """MBR entry, fsck.fat -n on the volume, and file hashes against the folder."""
    problems = []
    size = nand.sd_size(soc)
    with open(img, 'rb') as f:
        mbr = f.read(nand.LBA)
    if os.path.getsize(img) != size or mbr != nand.build_mbr(size, nand.sd_disk_id(soc)):
        problems.append('MBR/size differ from sd.json')
    tmp_root = os.path.join(nand.HVM, 'tmp')
    os.makedirs(tmp_root, mode=0o700, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=tmp_root)
    try:
        vol = os.path.join(tmp, 'sd.fat')
        with open(img, 'rb') as src, open(vol, 'wb') as dst:
            dst.truncate(size - nand.SD_PART_OFFSET)
            for start, end in mknand.extents_in(img, nand.SD_PART_OFFSET, size - nand.SD_PART_OFFSET):
                src.seek(nand.SD_PART_OFFSET + start)
                dst.seek(start)
                dst.write(src.read(end - start))
        r = subprocess.run(['fsck.fat', '-n', vol], capture_output=True, text=True)
        if r.returncode != 0:
            problems.append('fsck.fat: %s' % (r.stdout + r.stderr).strip().splitlines()[-1])
        out = os.path.join(tmp, 'files')
        os.makedirs(out)
        subprocess.run(['mcopy', '-s', '-n', '-i', vol, '::/*', out], env=mknand.MTOOLS_ENV, capture_output=True)
        want, got = mknand.tree_files(tree), mknand.tree_files(out)
        if set(want) != set(got):
            problems.append('files differ from the folder (%d vs %d)' % (len(got), len(want)))
        for rel in sorted(set(want) & set(got)):
            if mknand.file_hash(want[rel]) != mknand.file_hash(got[rel]):
                problems.append('%s content differs' % rel)
    finally:
        shutil.rmtree(tmp)
    return problems


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--soc', required=True, choices=['erista', 'mariko'])
    ap.add_argument('--dist', help='Atmosphère release (.zip or unpacked folder) to copy atmosphere/ from')
    ap.add_argument('--size', help='card size, fixed when the folder is created (default 8G)')
    ap.add_argument('--image', action='store_true', help='build sd.img from the folder')
    ap.add_argument('--verify', action='store_true', help='check sd.img against the folder')
    args = ap.parse_args()
    os.umask(0o077)   # ams_mitm backs up this identity's PRODINFO and BIS keys to the card

    paths = nand.sd_paths(args.soc)
    os.makedirs(paths['sd'], mode=0o700, exist_ok=True)
    if args.size or not os.path.exists(paths['config']):
        with open(paths['config'], 'w') as f:
            json.dump({'size': parse_size(args.size) if args.size else nand.SD_DEFAULT_SIZE}, f)
    if args.dist:
        print('%s: %d files' % (paths['dir'], populate(paths['dir'], args.dist)))
    if args.image:
        build_image(args.soc, paths['dir'], paths['image'])
        print('%s: ok (%d GiB)' % (paths['image'], nand.sd_size(args.soc) >> 30))
    if args.verify:
        problems = verify(args.soc, paths['dir'], paths['image'])
        for p in problems:
            print('verify: ' + p)
        print('verify: %s' % ('ok' if not problems else 'FAIL'))
        sys.exit(1 if problems else 0)


if __name__ == '__main__':
    main()
