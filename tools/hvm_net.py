#!/usr/bin/env python3
"""Isolated network for the VM's USB Ethernet adapter (QEMU -netdev stream, unix socket).

A minimal responder stands in for the rest of the network, and nothing leaves the host: it only ever opens the unix
socket QEMU connects to. The subnet is slirp-like: the VM gets 10.0.2.15 by DHCP, 10.0.2.2 is the gateway and
10.0.2.3 the DNS server. ARP and ping are answered for those two; every DNS name is NXDOMAIN, TCP connections are
reset and other UDP gets ICMP port unreachable, so Horizon's clients fail fast (nifm's connection test included).
Each event goes to a private log (~/.horizonvm/logs/net-<soc>.log): the names Horizon looks up end up there.
"""
import argparse
import ipaddress
import os
import socket
import struct
import sys
import time

HVM = os.environ.get('HORIZONVM_HOME', os.path.expanduser('~/.horizonvm'))
GATEWAY_MAC = bytes.fromhex('020048564e01')      # locally administered
BROADCAST_MAC = b'\xff' * 6
NETMASK = ipaddress.IPv4Address('255.255.255.0')
GATEWAY = ipaddress.IPv4Address('10.0.2.2')
DNS = ipaddress.IPv4Address('10.0.2.3')
FIRST_LEASE = ipaddress.IPv4Address('10.0.2.15')
LEASE_TIME = 86400
ETH_IP, ETH_ARP = 0x0800, 0x0806
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17
DHCP_MAGIC = b'\x63\x82\x53\x63'
DHCP_DISCOVER, DHCP_OFFER, DHCP_REQUEST, DHCP_DECLINE, DHCP_ACK, DHCP_NAK, DHCP_RELEASE, DHCP_INFORM = range(1, 9)
DHCP_NAMES = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}
DNS_TYPES = {1: 'A', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS'}


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ether(dst, src, ethertype, payload):
    return dst + src + struct.pack('!H', ethertype) + payload


def ipv4(src, dst, proto, payload, ident=0):
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, 0, 64, proto, 0, src.packed, dst.packed)
    return hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:] + payload


def l4_checksum(src, dst, proto, segment):
    return checksum(src.packed + dst.packed + struct.pack('!BBH', 0, proto, len(segment)) + segment)


def udp(src, sport, dst, dport, payload):
    seg = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    return ipv4(src, dst, PROTO_UDP, seg[:6] + struct.pack('!H', l4_checksum(src, dst, PROTO_UDP, seg) or 0xFFFF)
                + seg[8:])


class Stack:
    """Answers one Ethernet frame at a time: handle(frame) -> list of reply frames."""

    def __init__(self, log=lambda event: None):
        self.log = log
        self.leases = {}                              # client MAC -> IPv4Address
        self.counts = {}

    def count(self, what):
        self.counts[what] = self.counts.get(what, 0) + 1

    def handle(self, frame):
        if len(frame) < 14:
            self.count('runt')
            return []
        dst, src, ethertype = frame[:6], frame[6:12], struct.unpack('!H', frame[12:14])[0]
        payload = frame[14:]
        if ethertype == ETH_ARP:
            return self.arp(src, payload)
        if ethertype == ETH_IP:
            return self.ip(src, payload)
        self.count('ethertype %#06x' % ethertype)
        return []

    def ours(self, ip):
        return ip in (GATEWAY, DNS)

    def arp(self, src, p):
        if len(p) < 28:
            return []
        htype, ptype, hlen, plen, op = struct.unpack('!HHBBH', p[:8])
        sha, spa, tpa = p[8:14], ipaddress.IPv4Address(p[14:18]), ipaddress.IPv4Address(p[24:28])
        if (htype, ptype, hlen, plen, op) != (1, ETH_IP, 6, 4, 1) or not self.ours(tpa):
            return []                                 # the VM's own address (probes, gratuitous ARP) stays unanswered
        reply = struct.pack('!HHBBH', 1, ETH_IP, 6, 4, 2) + GATEWAY_MAC + tpa.packed + sha + spa.packed
        return [ether(src, GATEWAY_MAC, ETH_ARP, reply)]

    def ip(self, src_mac, p):
        if len(p) < 20 or p[0] >> 4 != 4:
            self.count('bad ipv4')
            return []
        ihl = (p[0] & 0xF) * 4
        total = struct.unpack('!H', p[2:4])[0]
        proto = p[9]
        src, dst = ipaddress.IPv4Address(p[12:16]), ipaddress.IPv4Address(p[16:20])
        body = p[ihl:total]
        if proto == PROTO_UDP and len(body) >= 8:
            sport, dport = struct.unpack('!HH', body[:4])
            data = body[8:]
            if dport == 67:
                return self.dhcp(src_mac, data)
            if dport == 53 and dst == DNS:
                return self.dns(src_mac, src, sport, data)
            self.log('udp %s:%d -> %s:%d (port unreachable)' % (src, sport, dst, dport))
            return [self.icmp_error(src_mac, src, 3, 3, p[:ihl + 8])]
        if proto == PROTO_TCP and len(body) >= 20:
            return self.tcp(src_mac, src, dst, body)
        if proto == PROTO_ICMP and len(body) >= 8 and body[0] == 8 and self.ours(dst):
            reply = b'\0\0\0\0' + body[4:]
            reply = reply[:2] + struct.pack('!H', checksum(reply)) + reply[4:]
            self.log('icmp echo %s -> %s' % (src, dst))
            return [ether(src_mac, GATEWAY_MAC, ETH_IP, ipv4(dst, src, PROTO_ICMP, reply))]
        self.count('ipv4 proto %d' % proto)
        return []

    def icmp_error(self, mac, dst, kind, code, original):
        msg = struct.pack('!BBHI', kind, code, 0, 0) + original
        msg = msg[:2] + struct.pack('!H', checksum(msg)) + msg[4:]
        return ether(mac, GATEWAY_MAC, ETH_IP, ipv4(GATEWAY, dst, PROTO_ICMP, msg))

    def tcp(self, mac, src, dst, seg):
        sport, dport, seq, ack, off_flags = struct.unpack('!HHIIH', seg[:14])
        flags = off_flags & 0x3F
        if flags & 0x04:                              # RST: nothing to answer
            return []
        data_len = len(seg) - (off_flags >> 12) * 4
        if flags & 0x02:
            self.log('tcp %s:%d -> %s:%d (reset)' % (src, sport, dst, dport))
            rseq, rack, rflags = 0, (seq + data_len + 1) & 0xFFFFFFFF, 0x14    # RST|ACK
        else:
            rseq, rack, rflags = ack, 0, 0x04                                   # RST
        rst = struct.pack('!HHIIHHHH', dport, sport, rseq, rack, (5 << 12) | rflags, 0, 0, 0)
        rst = rst[:16] + struct.pack('!H', l4_checksum(dst, src, PROTO_TCP, rst)) + rst[18:]
        return [ether(mac, GATEWAY_MAC, ETH_IP, ipv4(dst, src, PROTO_TCP, rst))]

    def lease(self, mac):
        if mac not in self.leases:
            self.leases[mac] = FIRST_LEASE + len(self.leases)
        return self.leases[mac]

    def dhcp(self, mac, p):
        if len(p) < 240 or p[0] != 1 or p[236:240] != DHCP_MAGIC:
            return []
        xid, ciaddr, chaddr = p[4:8], ipaddress.IPv4Address(p[12:16]), p[28:34]
        opts, i = {}, 240
        while i < len(p) and p[i] != 255:
            if p[i] == 0:
                i += 1
                continue
            if i + 1 >= len(p):
                break
            opts[p[i]] = p[i + 2:i + 2 + p[i + 1]]
            i += 2 + p[i + 1]
        kind = opts.get(53, b'\0')[0]
        ip = self.lease(chaddr)
        requested = ipaddress.IPv4Address(opts[50]) if len(opts.get(50, b'')) == 4 else ciaddr
        self.log('dhcp %s from %s' % (DHCP_NAMES.get(kind, kind), chaddr.hex(':')))
        if kind == DHCP_DISCOVER:
            reply = DHCP_OFFER
        elif kind == DHCP_REQUEST:
            reply = DHCP_ACK if requested == ip else DHCP_NAK
        elif kind == DHCP_INFORM:
            reply, ip = DHCP_ACK, ciaddr
        else:                                          # RELEASE, DECLINE: no reply
            return []
        yiaddr = ip if reply == DHCP_ACK or reply == DHCP_OFFER else ipaddress.IPv4Address(0)
        if kind == DHCP_INFORM:
            yiaddr = ipaddress.IPv4Address(0)
        out = struct.pack('!BBBB4sHH4s4s4s4s16s64s128s', 2, 1, 6, 0, xid, 0, struct.unpack('!H', p[10:12])[0],
                          ciaddr.packed, yiaddr.packed, GATEWAY.packed, b'\0' * 4, chaddr.ljust(16, b'\0'),
                          b'', b'') + DHCP_MAGIC
        out += bytes([53, 1, reply, 54, 4]) + GATEWAY.packed
        if reply != DHCP_NAK:
            out += bytes([1, 4]) + NETMASK.packed + bytes([3, 4]) + GATEWAY.packed + bytes([6, 4]) + DNS.packed
            if kind != DHCP_INFORM:
                out += struct.pack('!BBI', 51, 4, LEASE_TIME) + struct.pack('!BBI', 58, 4, LEASE_TIME // 2) + \
                    struct.pack('!BBI', 59, 4, LEASE_TIME * 7 // 8)
            if 26 in opts.get(55, b''):
                out += struct.pack('!BBH', 26, 2, 1500)
        out += b'\xff'
        self.log('dhcp %s %s to %s' % (DHCP_NAMES[reply], yiaddr if reply != DHCP_NAK else requested,
                                       chaddr.hex(':')))
        return [ether(BROADCAST_MAC, GATEWAY_MAC, ETH_IP,
                      udp(GATEWAY, 67, ipaddress.IPv4Address('255.255.255.255'), 68, out))]

    def dns(self, mac, src, sport, q):
        if len(q) < 12:
            return []
        ident, flags, qdcount = struct.unpack('!HHH', q[:6])
        if flags & 0x8000 or qdcount < 1:
            return []
        labels, i = [], 12
        while i < len(q) and q[i]:
            labels.append(q[i + 1:i + 1 + q[i]].decode('ascii', 'replace'))
            i += 1 + q[i]
        if i + 5 > len(q):
            return []
        qtype = struct.unpack('!H', q[i + 1:i + 3])[0]
        question = q[12:i + 5]
        self.log('dns %s %s -> NXDOMAIN' % (DNS_TYPES.get(qtype, qtype), '.'.join(labels)))
        answer = struct.pack('!HHHHHH', ident, 0x8180 | (flags & 0x0100) | 3, 1, 0, 0, 0) + question
        return [ether(mac, GATEWAY_MAC, ETH_IP, udp(DNS, 53, src, sport, answer))]


def read_frames(conn):
    """QEMU -netdev stream framing: 4-byte big-endian length, then the frame."""
    buf = b''
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            return
        buf += chunk
        while len(buf) >= 4:
            n = struct.unpack('!I', buf[:4])[0]
            if len(buf) < 4 + n:
                break
            yield buf[4:4 + n]
            buf = buf[4 + n:]


def serve_connection(conn, stack, pcap=None):
    for frame in read_frames(conn):
        replies = stack.handle(frame)
        for f in [frame] + replies:
            if pcap:
                pcap_record(pcap, f)
        for r in replies:
            conn.sendall(struct.pack('!I', len(r)) + r)


def pcap_header(f):
    f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))


def pcap_record(f, frame):
    t = time.time()
    f.write(struct.pack('<IIII', int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame)


def serve(sock_path, log_path, pcap_path=None, accept_timeout=120):
    with open(log_path, 'a') as logf:
        def log(event):
            logf.write('%.3f %s\n' % (time.time(), event))
            logf.flush()
        stack = Stack(log)
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(sock_path)
        srv.listen(1)
        srv.settimeout(accept_timeout)
        try:
            conn, _ = srv.accept()                     # one client (QEMU); exit when it goes away
        except socket.timeout:
            sys.exit('hvm_net: no client connected')
        finally:
            srv.close()
            os.unlink(sock_path)
        conn.settimeout(None)
        log('link up')
        pcap = open(pcap_path, 'wb') if pcap_path else None
        if pcap:
            pcap_header(pcap)
        try:
            serve_connection(conn, stack, pcap)
        except ConnectionError:
            pass
        finally:
            conn.close()
            if pcap:
                pcap.close()
            log('link down; dropped %s' % (', '.join('%s x%d' % kv for kv in sorted(stack.counts.items()))
                                           or 'nothing'))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('serve', help='answer the adapter of one QEMU (-netdev stream client) on a unix socket')
    s.add_argument('--soc', required=True, choices=['erista', 'mariko'])
    s.add_argument('--socket', required=True)
    s.add_argument('--log', help='event log (default ~/.horizonvm/logs/net-<soc>.log, truncated)')
    s.add_argument('--pcap', help='also capture both directions to this pcap file')
    args = ap.parse_args()
    os.umask(0o077)
    log = args.log or os.path.join(HVM, 'logs', 'net-%s.log' % args.soc)
    os.makedirs(os.path.dirname(log), mode=0o700, exist_ok=True)
    open(log, 'w').close()
    serve(args.socket, log, args.pcap)


if __name__ == '__main__':
    main()
