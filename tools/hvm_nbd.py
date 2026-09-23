#!/usr/bin/env python3
"""Serve a HorizonVM eMMC live from its per-partition folder tree over NBD (QEMU -drive ...,file.driver=nbd).

The disk is composed on the fly: BOOT0/1 and binary partitions from their .bin files, the GPT from hvm_nand, and
each FAT partition synthesized from its folder (geometry and boot sector from mkfs.fat, FATs and directories
generated in memory, file data read from the host files), AES-XTS encrypted with the VM's BIS keys.
Guest writes go to an overlay.
"""
import argparse
import array
import bisect
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

import hvm_nand as nand

FAT_OPTS = {'PRODINFOF': ['-F', '12'], 'SAFE': ['-F', '32', '-s', '1'],
            'SYSTEM': ['-F', '32', '-s', '32'], 'USER': ['-F', '32', '-s', '32']}   # = mknand
SHORT_CHARS = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$%\'-_@~`!(){}^#&')


# ---------------------------------------------------------------------------------------------------- FAT --

def fat_datetime(mtime):
    t = time.localtime(max(mtime, 315532800))   # FAT dates start in 1980
    return (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2), ((t.tm_year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday


def short_name(name, taken):
    """8.3 alias: the name itself if it is a valid upper-case 8.3 name, else BASIS~N.EXT (Windows style)."""
    base, _, ext = name.rpartition('.') if '.' in name.lstrip('.') else (name, '', '')
    clean = lambda s: bytes(c for c in s.upper().encode('ascii', 'replace') if c in SHORT_CHARS)
    b, e = clean(base), clean(ext)[:3]
    if name.encode('ascii', 'replace') == (b + (b'.' + e if e else b'')) and 0 < len(b) <= 8 and len(ext) <= 3:
        sn = b.ljust(8) + e.ljust(3)
        if sn not in taken:
            return sn, False
    for n in range(1, 1000000):
        tail = b'~%d' % n
        sn = (b[:8 - len(tail)] + tail).ljust(8) + e.ljust(3)
        if sn not in taken:
            return sn, True
    raise ValueError('no short name for %s' % name)


def lfn_entries(name, sn):
    checksum = 0
    for c in sn:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + c) & 0xFF
    utf16 = name.encode('utf-16-le')
    units = list(struct.unpack('<%dH' % (len(utf16) // 2), utf16))
    count = (len(units) + 12) // 13
    if len(units) % 13:                                 # NUL-terminated, 0xFFFF-padded
        units += [0x0000] + [0xFFFF] * (count * 13 - len(units) - 1)
    out = []
    for seq in range(count, 0, -1):
        part = units[(seq - 1) * 13:seq * 13]
        e = bytearray(32)
        e[0] = seq | (0x40 if seq == count else 0)
        e[1:11] = struct.pack('<5H', *part[0:5])
        e[11], e[12], e[13] = 0x0F, 0, checksum
        e[14:26] = struct.pack('<6H', *part[5:11])
        e[28:32] = struct.pack('<2H', *part[11:13])
        out.append(bytes(e))
    return out


def dir_entry(sn, attr, cluster, size, mtime):
    t, d = fat_datetime(mtime)
    return struct.pack('<11sBBBHHHHHHHI', sn, attr, 0, 0, t, d, d, cluster >> 16, t, d, cluster & 0xFFFF, size)


class Node:
    def __init__(self, path, is_dir, size=0, mtime=0, parent=None):
        self.path, self.is_dir, self.size, self.mtime, self.parent = path, is_dir, size, mtime, parent
        self.name, self.children, self.cluster, self.blob = os.path.basename(path), [], 0, b''


class FatSynth:
    """Plaintext view of a FAT12/FAT32 volume made from a host folder (read-only snapshot of the tree)."""

    def __init__(self, name, root_dir, size, tmp_dir):
        self.name, self.size = name, size
        tmpl = os.path.join(tmp_dir, name + '.tmpl')
        with open(tmpl, 'wb') as f:
            f.truncate(size)
        subprocess.run(['mkfs.fat', '--invariant', '-S', '512', '-n', name[:11]] + FAT_OPTS[name] + [tmpl],
                       check=True, stdout=subprocess.DEVNULL)
        with open(tmpl, 'rb') as f:
            bpb = f.read(512)
            bps, spc, reserved, nfats, root_entries, total16, _, fat16 = struct.unpack_from('<HBHBHHBH', bpb, 11)
            self.fat32 = fat16 == 0
            fat_size = fat16 or struct.unpack_from('<I', bpb, 36)[0]
            self.bps, self.cs = bps, bps * spc
            self.reserved_bytes = reserved * bps
            self.fat_bytes = fat_size * bps
            self.nfats = nfats
            self.root_bytes = root_entries * 32
            self.data_start = self.reserved_bytes + nfats * self.fat_bytes + self.root_bytes
            f.seek(0)
            self.reserved = bytearray(f.read(self.reserved_bytes))
            f.seek(self.reserved_bytes)
            fat_head = f.read(8)
            f.seek(self.reserved_bytes + nfats * self.fat_bytes if not self.fat32 else self.data_start)
            root0 = f.read(32)                          # FAT32: cluster 2 = root; both hold the volume label
        os.unlink(tmpl)
        total_sectors = total16 or struct.unpack_from('<I', bpb, 32)[0]
        self.clusters = (total_sectors * bps - self.data_start) // self.cs
        self.label = root0 if root0[11] == 0x08 else b''
        self.root = self._scan(root_dir)
        self.runs = []                                  # (first cluster, clusters, node)
        self._allocate()
        self.fat = self._build_fat(fat_head)
        self.run_starts = [r[0] for r in self.runs]
        if self.fat32:                                  # FSInfo (and its backup copy): free count, next free
            used = sum(n for _, n, _ in self.runs)
            next_free = max((f + n for f, n, _ in self.runs), default=2)
            fsinfo, backup = struct.unpack_from('<HH', self.reserved, 48)
            for sector in (fsinfo, backup + fsinfo if backup else None):
                if sector and (sector + 1) * bps <= len(self.reserved):
                    struct.pack_into('<II', self.reserved, sector * bps + 488, self.clusters - used, next_free)

    def _scan(self, path, parent=None):
        node = Node(path, True, mtime=os.stat(path).st_mtime if os.path.isdir(path) else 0, parent=parent)
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                p = os.path.join(path, name)
                st = os.stat(p)
                node.children.append(self._scan(p, node) if os.path.isdir(p)
                                     else Node(p, False, st.st_size, st.st_mtime, node))
        return node

    def _entries(self, node):
        """Directory entries of a node (needs its children's clusters)."""
        out, taken = [], set()
        is_root = node is self.root
        if is_root and self.label:
            out.append(self.label)
        if not is_root:
            parent_cluster = 0 if node.parent is self.root else node.parent.cluster   # ".." of a root child is 0
            out.append(dir_entry(b'.'.ljust(11), 0x10, node.cluster, 0, node.mtime))
            out.append(dir_entry(b'..'.ljust(11), 0x10, parent_cluster, 0, node.mtime))
        for c in node.children:
            sn, needs_lfn = short_name(c.name, taken)
            taken.add(sn)
            if needs_lfn or c.name != c.name.upper():
                out += lfn_entries(c.name, sn)
            out.append(dir_entry(sn, 0x10 if c.is_dir else 0x20, c.cluster, 0 if c.is_dir else c.size, c.mtime))
        return out

    def _allocate(self):
        """Contiguous runs: directories and files breadth-first from cluster 2 (the FAT32 root)."""
        nxt = 2
        order, queue = [], [self.root]
        while queue:
            d = queue.pop(0)
            order.append(d)
            queue += [c for c in d.children if c.is_dir]

        def take(node, nbytes):
            nonlocal nxt
            n = max(1, -(-nbytes // self.cs)) if nbytes or node.is_dir else 0
            if n:
                node.cluster = nxt
                self.runs.append((nxt, n, node))
                nxt += n
            if nxt - 2 > self.clusters:
                raise ValueError('%s: folder does not fit in the partition' % self.name)

        for d in order:                                 # entry count does not depend on cluster numbers
            count = len(self._entries(d))
            if d is self.root and not self.fat32:
                if count * 32 > self.root_bytes:
                    raise ValueError('%s: too many root entries' % self.name)
                continue
            take(d, count * 32)
        for d in order:
            for c in d.children:
                if not c.is_dir:
                    take(c, c.size)
        for d in order:
            d.blob = b''.join(self._entries(d))
        self.runs.sort(key=lambda r: r[0])

    def _build_fat(self, head):
        eoc = 0x0FFFFFFF if self.fat32 else 0xFFF
        entries = [0] * (self.clusters + 2)
        for first, n, _ in self.runs:
            for c in range(first, first + n - 1):
                entries[c] = c + 1
            entries[first + n - 1] = eoc
        fat = bytearray(self.fat_bytes)
        if self.fat32:
            packed = array.array('I', entries).tobytes()
            fat[:len(packed)] = packed
            fat[0:8] = head                             # media descriptor and clean-shutdown bits from mkfs
        else:
            entries[0], entries[1] = head[0] | 0xF00, 0xFFF
            entries += [0] * (len(entries) % 2)
            for i in range(0, len(entries), 2):
                a, b = entries[i], entries[i + 1]
                fat[i * 3 // 2:i * 3 // 2 + 3] = bytes((a & 0xFF, (a >> 8) | ((b & 0xF) << 4), b >> 4))
        return bytes(fat)

    def _data(self, off, n):
        out = bytearray(n)
        pos = 0
        while pos < n:
            rel = off + pos - self.data_start
            cluster = 2 + rel // self.cs
            i = bisect.bisect_right(self.run_starts, cluster) - 1
            if i < 0 or cluster >= self.runs[i][0] + self.runs[i][1]:
                nxt = self.run_starts[i + 1] if i + 1 < len(self.runs) else self.clusters + 2
                pos += min(n - pos, (nxt - 2) * self.cs - rel)      # free clusters read as zeros
                continue
            first, count, node = self.runs[i]
            inner = rel - (first - 2) * self.cs
            take = min(n - pos, count * self.cs - inner)
            if node.is_dir:
                chunk = node.blob[inner:inner + take]
            else:
                with open(node.path, 'rb') as f:
                    f.seek(inner)
                    chunk = f.read(max(0, min(take, node.size - inner)))
            out[pos:pos + len(chunk)] = chunk
            pos += take
        return bytes(out)

    def read(self, off, n):
        """Plaintext bytes [off, off + n) of the volume."""
        out = bytearray()
        regions = [(0, self.reserved_bytes, lambda o, k: bytes(self.reserved[o:o + k]))]
        for i in range(self.nfats):
            regions.append((self.reserved_bytes + i * self.fat_bytes, self.fat_bytes, lambda o, k: self.fat[o:o + k]))
        if self.root_bytes:
            root = self.root.blob.ljust(self.root_bytes, b'\0')
            regions.append((self.reserved_bytes + self.nfats * self.fat_bytes, self.root_bytes,
                            lambda o, k, r=root: r[o:o + k]))
        regions.append((self.data_start, self.size - self.data_start, lambda o, k: self._data(self.data_start + o, k)))
        end = off + n
        for start, length, fn in regions:
            s, e = max(off, start), min(end, start + length)
            if s < e:
                out += fn(s - start, e - s)
        return bytes(out)

    def used_ranges(self):
        """Byte ranges that are not free space (metadata + allocated clusters)."""
        yield 0, self.data_start
        for first, n, _ in self.runs:
            yield self.data_start + (first - 2) * self.cs, self.data_start + (first - 2 + n) * self.cs


# ------------------------------------------------------------------------------------------------ the disk --

class VirtualEmmc:
    """BOOT0 + BOOT1 + user area (GPT + NX partitions) composed from the folder tree, as tegra_qemu expects."""

    def __init__(self, soc, tree, tmp_dir):
        self.keys = nand.load_bis_keys(soc)
        self.size = nand.IMAGE_SIZE
        user = 2 * nand.BOOT_PART_SIZE
        primary, backup = nand.build_gpt(*nand.disk_guids(soc))
        self.regions = []                               # (start, length, reader, bis key or None)
        for i, boot in enumerate(('BOOT0.bin', 'BOOT1.bin')):
            self.regions.append((i * nand.BOOT_PART_SIZE, nand.BOOT_PART_SIZE, self._blob(os.path.join(tree, boot)), None))
        self.regions.append((user, len(primary), self._bytes(primary), None))
        self.regions.append((user + nand.USER_AREA_SIZE - len(backup), len(backup), self._bytes(backup), None))
        self.fats = {}
        for name, off, size, _, bis, fs in nand.PARTITIONS:
            if fs:
                self.fats[name] = FatSynth(name, os.path.join(tree, name), size, tmp_dir)
                reader = self.fats[name].read
            else:
                reader = self._blob(os.path.join(tree, name + '.bin'))
            self.regions.append((user + off, size, reader, None if bis is None else self.keys[bis]))
        self.regions.sort(key=lambda r: r[0])
        self.overlay = {}                               # 512-byte sector -> bytes written by the guest

    @staticmethod
    def _bytes(data):
        return lambda o, k: data[o:o + k].ljust(k, b'\0')

    @staticmethod
    def _blob(path):
        data = b''
        if os.path.exists(path):
            with open(path, 'rb') as f:
                data = f.read()
        return lambda o, k: data[o:o + k].ljust(k, b'\0')

    def _region_read(self, start, length, reader, key, off, n):
        if key is None:
            return reader(off, n)
        first = off // nand.XTS_SECTOR * nand.XTS_SECTOR
        last = min(length, -(-(off + n) // nand.XTS_SECTOR) * nand.XTS_SECTOR)
        plain = reader(first, last - first)
        return nand.xts(key, plain, first // nand.XTS_SECTOR, True)[off - first:off - first + n]

    def read(self, off, n):
        out = bytearray(n)
        for start, length, reader, key in self.regions:
            s, e = max(off, start), min(off + n, start + length)
            if s < e:
                out[s - off:e - off] = self._region_read(start, length, reader, key, s - start, e - s)
        if self.overlay:
            for sec in range(off // nand.LBA, -(-(off + n) // nand.LBA)):
                data = self.overlay.get(sec)
                if data is not None:
                    s, e = max(off, sec * nand.LBA), min(off + n, (sec + 1) * nand.LBA)
                    out[s - off:e - off] = data[s - sec * nand.LBA:e - sec * nand.LBA]
        return bytes(out)

    def write(self, off, data):
        pos = 0
        while pos < len(data):
            sec, inner = divmod(off + pos, nand.LBA)
            take = min(len(data) - pos, nand.LBA - inner)
            cur = self.overlay.get(sec)
            if cur is None or take < nand.LBA:
                cur = bytearray(cur if cur is not None else self.read(sec * nand.LBA, nand.LBA))
            cur = bytearray(cur)
            cur[inner:inner + take] = data[pos:pos + take]
            self.overlay[sec] = bytes(cur)
            pos += take


# -------------------------------------------------------------------------------------------------- NBD --

NBDMAGIC, IHAVEOPT, REPLY_MAGIC = 0x4E42444D41474943, 0x49484156454F5054, 0x3E889045565A9
REQUEST_MAGIC, SIMPLE_REPLY_MAGIC = 0x25609513, 0x67446698
OPT_EXPORT_NAME, OPT_ABORT, OPT_INFO, OPT_GO = 1, 2, 6, 7
REP_ACK, REP_INFO, REP_ERR_UNSUP = 1, 3, (1 << 31) | 1
CMD_READ, CMD_WRITE, CMD_DISC, CMD_FLUSH = 0, 1, 2, 3
FLAG_HAS_FLAGS, FLAG_SEND_FLUSH = 1 << 0, 1 << 2
EIO, EINVAL = 5, 22


def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return bytes(buf)


def serve_connection(conn, disk, log=lambda m: None):
    """Fixed-newstyle handshake, then simple replies to READ/WRITE/FLUSH until DISC or EOF."""
    tflags = FLAG_HAS_FLAGS | FLAG_SEND_FLUSH
    conn.sendall(struct.pack('>QQH', NBDMAGIC, IHAVEOPT, 1 | 2))    # FIXED_NEWSTYLE | NO_ZEROES
    client_flags = struct.unpack('>I', recv_exact(conn, 4))[0]
    while True:
        magic, opt, length = struct.unpack('>QII', recv_exact(conn, 16))
        data = recv_exact(conn, length) if length else b''
        if magic != IHAVEOPT:
            return
        if opt == OPT_EXPORT_NAME:
            conn.sendall(struct.pack('>QH', disk.size, tflags) + (b'' if client_flags & 2 else bytes(124)))
            break
        if opt in (OPT_GO, OPT_INFO):
            info = struct.pack('>HQH', 0, disk.size, tflags)       # NBD_INFO_EXPORT
            conn.sendall(struct.pack('>QIII', REPLY_MAGIC, opt, REP_INFO, len(info)) + info)
            conn.sendall(struct.pack('>QIII', REPLY_MAGIC, opt, REP_ACK, 0))
            if opt == OPT_GO:
                break
            continue
        if opt == OPT_ABORT:
            conn.sendall(struct.pack('>QIII', REPLY_MAGIC, opt, REP_ACK, 0))
            return
        conn.sendall(struct.pack('>QIII', REPLY_MAGIC, opt, REP_ERR_UNSUP, 0))
    log('nbd: transmission started')
    while True:
        magic, _, cmd, handle, off, length = struct.unpack('>IHHQQI', recv_exact(conn, 28))
        if magic != REQUEST_MAGIC:
            return
        if cmd == CMD_DISC:
            return
        if cmd == CMD_WRITE:
            data = recv_exact(conn, length)
        err, payload = 0, b''
        if off + length > disk.size:
            err = EINVAL
        elif cmd == CMD_READ:
            try:
                payload = disk.read(off, length)
            except OSError:
                err, payload = EIO, b''
        elif cmd == CMD_WRITE:
            disk.write(off, data)
        elif cmd != CMD_FLUSH:
            err = EINVAL
        conn.sendall(struct.pack('>IIQ', SIMPLE_REPLY_MAGIC, err, handle) + (payload if not err else b''))


def serve(soc, tree, sock_path, accept_timeout=120):
    tmp_root = os.path.join(nand.HVM, 'tmp')
    os.makedirs(tmp_root, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tmp_root) as tmp:
        disk = VirtualEmmc(soc, tree, tmp)
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(sock_path)
    srv.listen(1)
    srv.settimeout(accept_timeout)
    try:
        conn, _ = srv.accept()                          # one client (QEMU); exit when it goes away
    except socket.timeout:
        sys.exit('hvm_nbd: no client connected')
    finally:
        srv.close()
        os.unlink(sock_path)
    conn.settimeout(None)
    try:
        serve_connection(conn, disk)
    except (EOFError, ConnectionError):
        pass
    finally:
        conn.close()
    return disk


def export_partition(soc, tree, name, out):
    """Write the synthesized plaintext of one FAT partition to a sparse file (free clusters stay holes)."""
    tmp_root = os.path.join(nand.HVM, 'tmp')
    os.makedirs(tmp_root, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=tmp_root) as tmp:
        synth = FatSynth(name, os.path.join(tree, name), nand.PART[name][2], tmp)
    with open(out, 'wb') as f:
        f.truncate(synth.size)
        for s, e in synth.used_ranges():
            for o in range(s, e, 1 << 22):
                f.seek(o)
                f.write(synth.read(o, min(1 << 22, e - o)))
    return synth


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('serve', help='serve the eMMC to one NBD client (QEMU) on a unix socket')
    s.add_argument('--socket', required=True)
    e = sub.add_parser('export', help='write the synthesized plaintext of a FAT partition (for fsck/mtools)')
    e.add_argument('--part', required=True, choices=[p[0] for p in nand.PARTITIONS if p[5]])
    e.add_argument('-o', '--output', required=True)
    for p in (s, e):
        p.add_argument('--soc', required=True, choices=['erista', 'mariko'])
        p.add_argument('--tree', help='folder tree (default ~/.horizonvm/nand/<soc>/dir)')
    args = ap.parse_args()
    os.umask(0o077)
    tree = args.tree or nand.soc_paths(args.soc)['dir']
    if args.cmd == 'serve':
        serve(args.soc, tree, args.socket)
    else:
        export_partition(args.soc, tree, args.part, args.output)


if __name__ == '__main__':
    main()
