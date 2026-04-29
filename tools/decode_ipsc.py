#!/usr/bin/env python3
"""
Decode IPSC wire log lines and display human-readable call analysis.

Reads lines containing:
    IPSC RECV <len> <hex>
    IPSC SEND <len> <hex>

from a log file (syslog, journald, or --wire output — the prefix before
the IPSC token is ignored).

Usage:
    python tools/decode_ipsc.py <logfile> [--direction RECV|SEND|BOTH]
"""

import argparse
import re
import struct
import sys

# ---------------------------------------------------------------------------
# IPSC constants (inlined so this script has no project dependencies)
# ---------------------------------------------------------------------------
GROUP_VOICE  = 0x80
VOICE_HEAD   = 0x01
VOICE_TERM   = 0x02
SLOT1_VOICE  = 0x0A
SLOT2_VOICE  = 0x8A

TS_CALL_MSK  = 0b00100000   # bit 5 of call_info → TS2
END_MSK      = 0b01000000   # bit 6 of call_info → call end

GV_PEER_ID_OFF    = 1
GV_IPSC_SEQ_OFF   = 5
GV_SRC_SUB_OFF    = 6
GV_DST_GROUP_OFF  = 9
GV_CALL_INFO_OFF  = 17
GV_BURST_TYPE_OFF = 30
GV_PAYLOAD_OFF    = 31
GV_LC_OFF         = 38   # LC word start in HEAD/TERM 54-byte packet

OPCODES = {
    0x70: 'XCMP_XNL',      0x80: 'GROUP_VOICE',
    0x81: 'PVT_VOICE',     0x83: 'GROUP_DATA',
    0x84: 'PVT_DATA',      0x85: 'RPT_WAKE_UP',
    0x86: 'UNKNOWN_COLLISION',
    0x90: 'MASTER_REG_REQ',  0x91: 'MASTER_REG_REPLY',
    0x92: 'PEER_LIST_REQ',   0x93: 'PEER_LIST_REPLY',
    0x96: 'MASTER_ALIVE_REQ',0x97: 'MASTER_ALIVE_REPLY',
    0x9A: 'DE_REG_REQ',      0x9B: 'DE_REG_REPLY',
    0xF0: '0xF0(observed/benign)',
}

BURST_NAMES = {
    VOICE_HEAD:  'VOICE_HEAD',
    VOICE_TERM:  'VOICE_TERM',
    SLOT1_VOICE: 'SLOT1_VOICE',
    SLOT2_VOICE: 'SLOT2_VOICE',
}

FLCO_NAMES = {0x00: 'Group', 0x03: 'Unit-to-Unit'}

_LINE_RE = re.compile(r'IPSC (RECV|SEND) (\d+) ([0-9a-f]+)', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _id3(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _id4(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _rtp_pt_name(pt: int) -> str:
    m = pt & 0x80
    p = pt & 0x7F
    label = {0x5D: 'voice', 0x5E: 'term', 0xDD: 'voice(M)', 0xDE: 'term(M)'}.get(pt, f'0x{pt:02x}')
    return label

def _ts_from_burst(data: bytes) -> int:
    burst_type = data[GV_BURST_TYPE_OFF]
    call_info  = data[GV_CALL_INFO_OFF]
    if burst_type in (VOICE_HEAD, VOICE_TERM):
        return 2 if (call_info & TS_CALL_MSK) else 1
    return 2 if (burst_type & 0x80) else 1

def _decode_lc(data: bytes) -> dict | None:
    """Extract 9-byte LC from a VOICE_HEAD or VOICE_TERM packet."""
    if len(data) < GV_LC_OFF + 9:
        return None
    lc = data[GV_LC_OFF : GV_LC_OFF + 9]
    return {
        'flco':     lc[0],
        'fid':      lc[1],
        'svc_opt':  lc[2],
        'dst':      _id3(lc[3:6]),
        'src':      _id3(lc[6:9]),
        'raw':      lc.hex(),
    }

def _decode_rtp(data: bytes) -> dict | None:
    """Parse 12-byte RTP header at bytes 18–29."""
    if len(data) < 30:
        return None
    hdr = data[18:30]
    return {
        'ver':   (hdr[0] >> 6) & 0x03,
        'pt':    hdr[1],
        'seq':   struct.unpack_from('>H', hdr, 2)[0],
        'ts':    struct.unpack_from('>I', hdr, 4)[0],
        'ssrc':  hdr[8:12].hex(),
    }

# ---------------------------------------------------------------------------
# Packet decoder
# ---------------------------------------------------------------------------

def decode_packet(data: bytes, frame_num: int, direction: str, stats: dict):
    if not data:
        print(f'  [frame {frame_num}] empty packet')
        return

    opcode = data[0]
    op_name = OPCODES.get(opcode, f'0x{opcode:02x}')

    if opcode != GROUP_VOICE:
        print(f'  [{frame_num:4d}] {direction}  {op_name:<22s}  len={len(data)}')
        stats.setdefault('other', []).append(op_name)
        return

    # --- GROUP_VOICE ---
    if len(data) < GV_BURST_TYPE_OFF + 1:
        print(f'  [{frame_num:4d}] {direction}  GROUP_VOICE  TOO SHORT ({len(data)} bytes)')
        return

    peer_id    = _id4(data[GV_PEER_ID_OFF : GV_PEER_ID_OFF + 4])
    stream_id  = data[GV_IPSC_SEQ_OFF]
    src        = _id3(data[GV_SRC_SUB_OFF  : GV_SRC_SUB_OFF  + 3])
    dst        = _id3(data[GV_DST_GROUP_OFF : GV_DST_GROUP_OFF + 3])
    call_info  = data[GV_CALL_INFO_OFF]
    burst_type = data[GV_BURST_TYPE_OFF]
    ts         = _ts_from_burst(data)
    burst_name = BURST_NAMES.get(burst_type, f'0x{burst_type:02x}')
    end_flag   = bool(call_info & END_MSK)
    rtp        = _decode_rtp(data)

    # Track per-stream RTP seq continuity
    stream_key = (direction, stream_id, ts)
    if rtp:
        prev_seq = stats.get(('rtp_seq', stream_key))
        if prev_seq is not None and burst_type in (SLOT1_VOICE, SLOT2_VOICE):
            gap = (rtp['seq'] - prev_seq - 1) & 0xFFFF
            if gap:
                print(f'  *** WARNING: RTP seq gap of {gap} on stream {stream_id:02x} TS{ts}')
        stats[('rtp_seq', stream_key)] = rtp['seq']
        prev_ts = stats.get(('rtp_ts', stream_key))
        ts_delta = (rtp['ts'] - prev_ts) if prev_ts is not None else 0
        stats[('rtp_ts', stream_key)] = rtp['ts']
    else:
        ts_delta = 0

    # Track burst counts
    stats.setdefault('burst_counts', {})
    stats['burst_counts'][burst_name] = stats['burst_counts'].get(burst_name, 0) + 1

    # --- Header line ---
    ts_delta_str = f' Δts={ts_delta}' if rtp and ts_delta else ''
    print(f'  [{frame_num:4d}] {direction}  {burst_name:<12s}  TS{ts}  '
          f'len={len(data):<3d}  '
          f'peer={peer_id}  stream={stream_id:02x}  '
          f'src={src}  dst={dst}{"  [END]" if end_flag else ""}')

    # --- RTP line ---
    if rtp:
        print(f'         RTP: seq={rtp["seq"]:<5d}  ts={rtp["ts"]:<12d}{ts_delta_str}  '
              f'ssrc={rtp["ssrc"]}  pt={_rtp_pt_name(rtp["pt"])}')

    # --- Burst-specific detail ---
    if burst_type in (VOICE_HEAD, VOICE_TERM):
        lc = _decode_lc(data)
        if lc:
            flco_name = FLCO_NAMES.get(lc['flco'], f'0x{lc["flco"]:02x}')
            print(f'         LC:  flco={flco_name}  fid=0x{lc["fid"]:02x}  '
                  f'svc=0x{lc["svc_opt"]:02x}  dst={lc["dst"]}  src={lc["src"]}  '
                  f'raw={lc["raw"]}')
        else:
            print(f'         LC:  (packet too short to decode)')

    elif burst_type in (SLOT1_VOICE, SLOT2_VOICE):
        if len(data) >= 52:
            ambe = data[33:52]
            ambe_hex = ambe.hex()
            # Check for null AMBE (silence/comfort noise / all zeros)
            null = all(b == 0 for b in ambe)
            print(f'         AMBE({len(ambe)}B): {ambe_hex}{"  [NULL]" if null else ""}')
        else:
            print(f'         AMBE: packet too short ({len(data)} bytes)')
        if len(data) > 52:
            ext = data[52:]
            print(f'         EMB/ext({len(ext)}B): {ext.hex()}')

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='Decode IPSC wire log')
    ap.add_argument('logfile', help='Wire log file (or - for stdin)')
    ap.add_argument('--direction', choices=['RECV', 'SEND', 'BOTH'], default='BOTH',
                    help='Which packets to show (default: BOTH)')
    args = ap.parse_args()

    direction_filter = None if args.direction == 'BOTH' else args.direction

    src = open(args.logfile) if args.logfile != '-' else sys.stdin

    stats  = {}
    frames = 0
    shown  = 0

    print(f'IPSC wire decoder  — direction={args.direction}\n{"="*72}')

    for line in src:
        m = _LINE_RE.search(line)
        if not m:
            continue
        frames += 1
        direction = m.group(1).upper()
        length    = int(m.group(2))
        hex_data  = m.group(3)

        if direction_filter and direction != direction_filter:
            continue

        try:
            data = bytes.fromhex(hex_data)
        except ValueError:
            print(f'  [frame {frames}] hex parse error: {hex_data[:40]}…')
            continue

        if len(data) != length:
            print(f'  *** WARNING frame {frames}: declared len={length} actual={len(data)}')

        shown += 1
        decode_packet(data, shown, direction, stats)

    if args.logfile != '-':
        src.close()

    # --- Summary ---
    print(f'\n{"="*72}')
    print(f'SUMMARY: {frames} IPSC lines scanned, {shown} shown')
    burst_counts = stats.get('burst_counts', {})
    if burst_counts:
        print('  Burst counts:')
        for name, count in sorted(burst_counts.items(), key=lambda x: -x[1]):
            print(f'    {name:<14s} {count}')
    other = stats.get('other', [])
    if other:
        from collections import Counter
        print('  Other opcodes:')
        for op, cnt in Counter(other).most_common():
            print(f'    {op:<22s} {cnt}')

if __name__ == '__main__':
    main()
