#!/usr/bin/env python3
"""
Convert a tcpdump .pcap file to ipsc2hbp wire log format.

Output lines match what --wire produces:
    IPSC RECV <peer_ip> <len> <hex>
    IPSC SEND <peer_ip> <len> <hex>

Direction is determined by port:
    dst_port == ipsc_port  →  RECV  (arriving at us), peer_ip = src_ip
    src_port == ipsc_port  →  SEND  (sent by us),     peer_ip = dst_ip

Pipe directly into decode_ipsc.py:
    python tools/pcap_to_wire.py capture.pcap | python tools/decode_ipsc.py - -v

Usage:
    python tools/pcap_to_wire.py <pcap_file> [--port PORT] [--host IP] [--timestamps]
"""

import argparse
import socket
import struct
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# pcap / pcap-ng detection — compare raw bytes to avoid endian confusion
# ---------------------------------------------------------------------------
PCAP_MAGIC_LE    = b'\xd4\xc3\xb2\xa1'   # little-endian classic pcap
PCAP_MAGIC_BE    = b'\xa1\xb2\xc3\xd4'   # big-endian classic pcap
PCAPNG_MAGIC     = b'\x0a\x0d\x0d\x0a'   # pcap-ng section header block

# Link-layer types we handle
LINKTYPE_NULL        = 0    # BSD loopback
LINKTYPE_ETHERNET    = 1
LINKTYPE_RAW         = 101  # raw IP (no link header)
LINKTYPE_LINUX_SLL   = 113  # Linux cooked capture


def _ip_str(b: bytes) -> str:
    return socket.inet_ntoa(b)


# ---------------------------------------------------------------------------
# pcap-ng reader (minimal — SHB + IDB + EPB only)
# ---------------------------------------------------------------------------

def _read_pcapng(fh):
    """
    Yield (ts_sec, ts_usec, link_type, data) from a pcap-ng file.
    Handles Section Header Block, Interface Description Block, Enhanced Packet Block.
    """
    iface_link_types = []
    iface_ts_resol   = []   # timestamp resolution as divisor (default 1_000_000 = µs)

    while True:
        hdr = fh.read(8)
        if len(hdr) < 8:
            return
        block_type, block_len = struct.unpack_from('<II', hdr)

        # Read the rest of the block body (block_len includes the 8-byte header
        # and the trailing 4-byte length repeat)
        body_len = block_len - 12
        body     = fh.read(body_len)
        fh.read(4)   # trailing block_len repeat

        if len(body) < body_len:
            return

        if block_type == 0x0A0D0D0A:    # Section Header Block — resets interfaces
            iface_link_types = []
            iface_ts_resol   = []

        elif block_type == 0x00000001:   # Interface Description Block
            if len(body) >= 4:
                link_type = struct.unpack_from('<H', body, 0)[0]
            else:
                link_type = LINKTYPE_ETHERNET
            iface_link_types.append(link_type)
            # Default timestamp resolution is microseconds (10^-6)
            iface_ts_resol.append(1_000_000)

        elif block_type == 0x00000006:   # Enhanced Packet Block
            if len(body) < 20:
                continue
            iface_id   = struct.unpack_from('<I', body, 0)[0]
            ts_high    = struct.unpack_from('<I', body, 4)[0]
            ts_low     = struct.unpack_from('<I', body, 8)[0]
            cap_len    = struct.unpack_from('<I', body, 12)[0]
            pkt_data   = body[20 : 20 + cap_len]

            link_type  = iface_link_types[iface_id] if iface_id < len(iface_link_types) else LINKTYPE_ETHERNET
            resolution = iface_ts_resol[iface_id]   if iface_id < len(iface_ts_resol)   else 1_000_000

            ts_combined = (ts_high << 32) | ts_low
            ts_sec  = ts_combined // resolution
            ts_usec = (ts_combined % resolution) * (1_000_000 // resolution)

            yield ts_sec, ts_usec, link_type, pkt_data

        # All other block types: skip


# ---------------------------------------------------------------------------
# classic pcap reader
# ---------------------------------------------------------------------------

def _read_pcap(fh, endian: str):
    """Yield (ts_sec, ts_usec, link_type, data) from a classic pcap file."""
    # Read global header remainder (already consumed 4-byte magic)
    hdr = fh.read(20)
    if len(hdr) < 20:
        return
    _ver_maj, _ver_min, _tz, _sigfigs, _snaplen, network = \
        struct.unpack_from(endian + 'HHiIII', hdr)

    while True:
        rec = fh.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack_from(endian + 'IIII', rec)
        data = fh.read(incl_len)
        if len(data) < incl_len:
            return
        yield ts_sec, ts_usec, network, data


# ---------------------------------------------------------------------------
# Ethernet / IP / UDP extraction
# ---------------------------------------------------------------------------

def _extract_udp(link_type: int, data: bytes):
    """
    Return (src_ip, dst_ip, src_port, dst_port, payload) or None.
    Handles Ethernet, Linux cooked, BSD null/loopback, and raw IP frames.
    """
    if link_type == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack_from('>H', data, 12)[0]
        if ethertype == 0x8100:          # 802.1Q VLAN tag
            if len(data) < 18:
                return None
            ethertype = struct.unpack_from('>H', data, 16)[0]
            ip_start = 18
        else:
            ip_start = 14
        if ethertype != 0x0800:
            return None
        data = data[ip_start:]

    elif link_type == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        ethertype = struct.unpack_from('>H', data, 14)[0]
        if ethertype != 0x0800:
            return None
        data = data[16:]

    elif link_type == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        af = struct.unpack_from('<I', data)[0]   # BSD uses little-endian AF
        if af not in (2, 0x02000000):            # AF_INET = 2
            return None
        data = data[4:]

    elif link_type == LINKTYPE_RAW:
        pass   # data is already raw IP

    else:
        return None   # unsupported link type

    # IPv4
    if len(data) < 20:
        return None
    version = (data[0] >> 4) & 0x0F
    if version != 4:
        return None
    ihl     = (data[0] & 0x0F) * 4
    proto   = data[9]
    if proto != 17:              # UDP
        return None
    src_ip  = _ip_str(data[12:16])
    dst_ip  = _ip_str(data[16:20])
    udp     = data[ihl:]

    if len(udp) < 8:
        return None
    src_port, dst_port = struct.unpack_from('>HH', udp)
    payload = udp[8:]

    return src_ip, dst_ip, src_port, dst_port, payload


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='Convert tcpdump .pcap to ipsc2hbp wire log format')
    ap.add_argument('pcap', help='Input .pcap or .pcap-ng file')
    ap.add_argument('--port', type=int, default=50000,
                    help='IPSC UDP port to filter on (default: 50000)')
    ap.add_argument('--host', default=None,
                    help='Filter to packets involving this IP address only')
    ap.add_argument('--timestamps', action='store_true',
                    help='Prepend timestamps to output lines (needed for decode_ipsc.py to parse)')
    ap.add_argument('--raw', action='store_true',
                    help='Show full src_ip:port -> dst_ip:port flow instead of wire log format '
                         '(useful for direction analysis; cannot be piped to decode_ipsc.py)')
    args = ap.parse_args()

    try:
        fh = open(args.pcap, 'rb')
    except OSError as exc:
        print(f'error: {exc}', file=sys.stderr)
        sys.exit(1)

    magic = fh.read(4)
    if len(magic) < 4:
        print('error: file too short', file=sys.stderr)
        sys.exit(1)

    if magic == PCAPNG_MAGIC:
        fh.seek(0)
        packets = _read_pcapng(fh)
    elif magic == PCAP_MAGIC_LE:
        packets = _read_pcap(fh, '<')
    elif magic == PCAP_MAGIC_BE:
        packets = _read_pcap(fh, '>')
    else:
        print(f'error: unrecognised file format (magic {magic.hex()})', file=sys.stderr)
        sys.exit(1)

    count = 0
    for ts_sec, ts_usec, link_type, data in packets:
        result = _extract_udp(link_type, data)
        if result is None:
            continue
        src_ip, dst_ip, src_port, dst_port, payload = result

        if dst_port == args.port:
            direction = 'RECV'
            peer_ip   = src_ip
        elif src_port == args.port:
            direction = 'SEND'
            peer_ip   = dst_ip
        else:
            continue

        if args.host and peer_ip != args.host:
            continue

        if not payload:
            continue

        count += 1
        ts_str = ''
        if args.timestamps:
            dt = datetime.fromtimestamp(ts_sec, tz=timezone.utc)
            ts_str = f'{dt.strftime("%Y-%m-%d %H:%M:%S")},{ts_usec // 1000:03d} '

        if args.raw:
            opcode = f'op=0x{payload[0]:02x}' if payload else 'op=?'
            print(f'{ts_str}{src_ip}:{src_port} -> {dst_ip}:{dst_port}  {opcode}  len={len(payload)}  {payload.hex()}')
        else:
            print(f'{ts_str}IPSC {direction} {peer_ip} {len(payload)} {payload.hex()}')

    fh.close()
    print(f'# {count} UDP packets extracted', file=sys.stderr)


if __name__ == '__main__':
    main()
