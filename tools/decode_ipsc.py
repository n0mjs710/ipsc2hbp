#!/usr/bin/env python3
"""
Decode IPSC wire log lines and display human-readable call analysis.

Reads lines containing:
    IPSC RECV <ip> <len> <hex>
    IPSC SEND <ip> <len> <hex>

from a log file (syslog, journald, or --wire output — the prefix before
the IPSC token is ignored).

Usage:
    python tools/decode_ipsc.py <logfile> [--direction RECV|SEND|BOTH] [-v]
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

_LINE_RE = re.compile(r'IPSC (RECV|SEND) (\S+) (\d+) ([0-9a-f]+)', re.IGNORECASE)

# ---------------------------------------------------------------------------
# MODE byte and FLAGS word decode (from DMRlink ipsc/ipsc_mask.py)
# ---------------------------------------------------------------------------
PEER_OP_MSK       = 0b01000000
PEER_MODE_MSK     = 0b00110000
PEER_MODE_ANALOG  = 0b00010000
PEER_MODE_DIGITAL = 0b00100000
IPSC_TS1_MSK      = 0b00001100
IPSC_TS2_MSK      = 0b00000011

CSBK_MSK      = 0b10000000
RPT_MON_MSK   = 0b01000000
CON_APP_MSK   = 0b00100000
XNL_STAT_MSK  = 0b10000000
XNL_MSTR_MSK  = 0b01000000
XNL_SLAVE_MSK = 0b00100000
PKT_AUTH_MSK  = 0b00010000
DATA_CALL_MSK = 0b00001000
VOICE_CALL_MSK= 0b00000100
MSTR_PEER_MSK = 0b00000001

def _fmt_ver(raw: bytes) -> str:
    """Format 4-byte IPSC version as decimal integer + hex: '67043329 (0x04020401)'."""
    val = int.from_bytes(raw, 'big')
    return f'{val} (0x{raw.hex()})'

def _yn(val) -> str:
    return 'yes' if val else 'no'

def _print_mode(mode_byte: int, pfx: str = '         '):
    """Print full MODE byte decode — all fields explicit, unknown bits flagged."""
    op_bits  = (mode_byte >> 6) & 0x03
    mm_bits  = (mode_byte >> 4) & 0x03
    ts1_bits = (mode_byte >> 2) & 0x03
    ts2_bits = (mode_byte       & 0x03)

    op_str   = 'yes' if op_bits == 0b01 else f'NO  (raw bits={op_bits:02b} — expected 01)'
    mode_str = {0b00: 'NO_RADIO', 0b01: 'ANALOG', 0b10: 'DIGITAL', 0b11: 'UNKNOWN'}[mm_bits]
    ts1_str  = ('on'  if ts1_bits == 0b10 else
                'off' if ts1_bits == 0b01 else
                f'?   (raw bits={ts1_bits:02b} — expected 10=on or 01=off)')
    ts2_str  = ('on'  if ts2_bits == 0b10 else
                'off' if ts2_bits == 0b01 else
                f'?   (raw bits={ts2_bits:02b} — expected 10=on or 01=off)')

    print(f'{pfx}MODE (0x{mode_byte:02x}):')
    print(f'{pfx}  operational: {op_str}')
    print(f'{pfx}  radio_mode:  {mode_str}')
    print(f'{pfx}  TS1_linked:  {ts1_str}')
    print(f'{pfx}  TS2_linked:  {ts2_str}')

def _print_flags(flags: bytes, pfx: str = '         '):
    """
    Print full FLAGS word decode — all four bytes, all known bits explicit,
    unknown bytes and bits flagged when non-zero.
    """
    if len(flags) < 4:
        print(f'{pfx}FLAGS: (too short — {flags.hex()})')
        return

    b0, b1, b2, b3 = flags[0], flags[1], flags[2], flags[3]

    # bytes 0-1 are fully undocumented
    b0_note = '  *** NON-ZERO — unknown field ***' if b0 else ''
    b1_note = '  *** NON-ZERO — unknown field ***' if b1 else ''

    # byte 2: known bits 7-5; bits 4-0 undocumented
    b2_unknown = b2 & 0x1F
    b2_unk_note = f'  *** unknown bits 4-0 = 0x{b2_unknown:02x} ***' if b2_unknown else ''

    # byte 3: bit 1 undocumented (sits between VOICE and MASTER)
    b3_unknown = b3 & 0x02
    b3_unk_note = f'  *** unknown bit 1 set ***' if b3_unknown else ''

    print(f'{pfx}FLAGS (raw 0x{flags.hex()}):')
    print(f'{pfx}  byte[0] unknown:  0x{b0:02x}{b0_note}')
    print(f'{pfx}  byte[1] unknown:  0x{b1:02x}{b1_note}')
    print(f'{pfx}  CSBK:             {_yn(b2 & CSBK_MSK)}')
    print(f'{pfx}  RPT_MON:          {_yn(b2 & RPT_MON_MSK)}')
    print(f'{pfx}  CON_APP:          {_yn(b2 & CON_APP_MSK)}'
          + ('  (3rd-party console)' if b2 & CON_APP_MSK else ''))
    print(f'{pfx}  byte[2] unk[4:0]: 0x{b2_unknown:02x}{b2_unk_note}')
    print(f'{pfx}  XNL_CON:          {_yn(b3 & XNL_STAT_MSK)}')
    print(f'{pfx}  XNL_MASTER:       {_yn(b3 & XNL_MSTR_MSK)}')
    print(f'{pfx}  XNL_SLAVE:        {_yn(b3 & XNL_SLAVE_MSK)}')
    print(f'{pfx}  AUTH:             {_yn(b3 & PKT_AUTH_MSK)}')
    print(f'{pfx}  DATA:             {_yn(b3 & DATA_CALL_MSK)}')
    print(f'{pfx}  VOICE:            {_yn(b3 & VOICE_CALL_MSK)}')
    print(f'{pfx}  byte[3] unk[1]:   {_yn(b3_unknown)}{b3_unk_note}')
    print(f'{pfx}  MASTER:           {_yn(b3 & MSTR_PEER_MSK)}')

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _id3(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _id4(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _rtp_pt_name(pt: int) -> str:
    return {0x5D: 'voice', 0x5E: 'term', 0xDD: 'voice(M)', 0xDE: 'term(M)'}.get(pt, f'0x{pt:02x}')

def _ts_from_burst(data: bytes) -> int:
    burst_type = data[GV_BURST_TYPE_OFF]
    call_info  = data[GV_CALL_INFO_OFF]
    if burst_type in (VOICE_HEAD, VOICE_TERM):
        return 2 if (call_info & TS_CALL_MSK) else 1
    return 2 if (burst_type & 0x80) else 1

def _decode_lc(data: bytes) -> dict | None:
    if len(data) < GV_LC_OFF + 9:
        return None
    lc = data[GV_LC_OFF : GV_LC_OFF + 9]
    return {
        'flco':    lc[0],
        'fid':     lc[1],
        'svc_opt': lc[2],
        'dst':     _id3(lc[3:6]),
        'src':     _id3(lc[6:9]),
        'raw':     lc.hex(),
    }

def _decode_rtp(data: bytes) -> dict | None:
    if len(data) < 30:
        return None
    hdr = data[18:30]
    return {
        'ver':  (hdr[0] >> 6) & 0x03,
        'pt':   hdr[1],
        'seq':  struct.unpack_from('>H', hdr, 2)[0],
        'ts':   struct.unpack_from('>I', hdr, 4)[0],
        'ssrc': hdr[8:12].hex(),
    }

# ---------------------------------------------------------------------------
# Control packet detail decoder (verbose mode only)
# ---------------------------------------------------------------------------

def _decode_control(opcode: int, data: bytes, direction: str):
    """
    Print per-field detail for control packets.
    MODE/FLAGS capabilities are only decoded for RECV — we already know what we send.
    """
    recv = (direction == 'RECV')

    pfx = '         '

    # MASTER_REG_REQ (0x90) / MASTER_ALIVE_REQ (0x96): peer → us
    #   opcode(1) + peer_id(4) + MODE(1) + FLAGS(4) [+ IPSC_VER(4)]
    if opcode in (0x90, 0x96):
        if len(data) < 10:
            return
        peer_id = int.from_bytes(data[1:5], 'big')
        ver_raw = data[10:14] if len(data) >= 14 else None
        print(f'{pfx}peer_id={peer_id}')
        print(f'{pfx}IPSC_VER: {_fmt_ver(ver_raw) if ver_raw else "n/a"}')
        _print_mode(data[5], pfx)
        _print_flags(data[6:10], pfx)

    # MASTER_REG_REPLY (0x91): us → peer
    #   opcode(1) + master_id(4) + MODE(1) + FLAGS(4) + num_peers(2) + IPSC_VER(4) = 16 bytes
    elif opcode == 0x91:
        if len(data) < 10:
            return
        master_id = int.from_bytes(data[1:5], 'big')
        num_peers = int.from_bytes(data[10:12], 'big') if len(data) >= 12 else '?'
        ver_raw   = data[12:16] if len(data) >= 16 else None
        print(f'{pfx}master_id={master_id}  num_peers={num_peers}')
        print(f'{pfx}IPSC_VER: {_fmt_ver(ver_raw) if ver_raw else "n/a"}')
        if recv:
            _print_mode(data[5], pfx)
            _print_flags(data[6:10], pfx)

    # MASTER_ALIVE_REPLY (0x97): us → peer
    #   opcode(1) + master_id(4) + MODE(1) + FLAGS(4) + IPSC_VER(4) = 14 bytes (no num_peers)
    elif opcode == 0x97:
        if len(data) < 10:
            return
        master_id = int.from_bytes(data[1:5], 'big')
        ver_raw   = data[10:14] if len(data) >= 14 else None
        print(f'{pfx}master_id={master_id}')
        print(f'{pfx}IPSC_VER: {_fmt_ver(ver_raw) if ver_raw else "n/a"}')
        if recv:
            _print_mode(data[5], pfx)
            _print_flags(data[6:10], pfx)

    # PEER_LIST_REPLY (0x93): us → peer
    #   opcode(1) + master_id(4) + data_len(2) + [peer_id(4)+ip(4)+port(2)+mode(1)] × N
    elif opcode == 0x93:
        if len(data) < 7:
            return
        master_id = int.from_bytes(data[1:5], 'big')
        data_len  = int.from_bytes(data[5:7], 'big')
        n_peers   = data_len // 11
        print(f'{pfx}master_id={master_id}  peer_entries={n_peers}')
        offset = 7
        for i in range(n_peers):
            if offset + 11 > len(data):
                break
            pid  = int.from_bytes(data[offset:offset+4], 'big')
            ip   = '.'.join(str(b) for b in data[offset+4:offset+8])
            port = int.from_bytes(data[offset+8:offset+10], 'big')
            print(f'{pfx}  peer[{i}]: id={pid}  {ip}:{port}')
            _print_mode(data[offset+10], pfx + '    ')
            offset += 11

    # DE_REG_REQ (0x9A): peer sends peer_id
    elif opcode == 0x9A:
        if len(data) >= 5:
            print(f'{pfx}peer_id={int.from_bytes(data[1:5], "big")}')

    # DE_REG_REPLY (0x9B): we send master_id
    elif opcode == 0x9B:
        if len(data) >= 5:
            print(f'{pfx}master_id={int.from_bytes(data[1:5], "big")}')


# ---------------------------------------------------------------------------
# Packet decoder
# ---------------------------------------------------------------------------

def decode_packet(data: bytes, frame_num: int, direction: str, peer_ip: str,
                  verbose: bool, stats: dict):
    if not data:
        print(f'  [frame {frame_num}] empty packet')
        return

    opcode  = data[0]
    op_name = OPCODES.get(opcode, f'0x{opcode:02x}')

    if opcode != GROUP_VOICE:
        print(f'  [{frame_num:4d}] {direction}  {op_name:<22s}  len={len(data)}  ip={peer_ip}')
        stats.setdefault('other', []).append(op_name)
        if verbose:
            _decode_control(opcode, data, direction)
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

    # Track per-stream RTP seq continuity (always, regardless of verbose)
    stream_key = (direction, stream_id, ts)
    if rtp:
        prev_seq = stats.get(('rtp_seq', stream_key))
        if prev_seq is not None and burst_type in (SLOT1_VOICE, SLOT2_VOICE):
            gap = (rtp['seq'] - prev_seq - 1) & 0xFFFF
            if gap:
                print(f'  *** WARNING: RTP seq gap of {gap} on stream {stream_id:02x} TS{ts}')
        stats[('rtp_seq', stream_key)] = rtp['seq']
        prev_ts  = stats.get(('rtp_ts', stream_key))
        ts_delta = (rtp['ts'] - prev_ts) if prev_ts is not None else 0
        stats[('rtp_ts', stream_key)] = rtp['ts']
    else:
        ts_delta = 0

    stats.setdefault('burst_counts', {})
    stats['burst_counts'][burst_name] = stats['burst_counts'].get(burst_name, 0) + 1

    # Summary line — always printed
    print(f'  [{frame_num:4d}] {direction}  {burst_name:<12s}  TS{ts}  '
          f'len={len(data):<3d}  ip={peer_ip}  '
          f'peer={peer_id}  stream={stream_id:02x}  '
          f'src={src}  dst={dst}{"  [END]" if end_flag else ""}')

    if not verbose:
        return

    # Verbose: RTP detail
    if rtp:
        ts_delta_str = f'  Δts={ts_delta}' if ts_delta else ''
        print(f'         RTP: seq={rtp["seq"]:<5d}  ts={rtp["ts"]:<12d}{ts_delta_str}  '
              f'ssrc={rtp["ssrc"]}  pt={_rtp_pt_name(rtp["pt"])}')

    # Verbose: burst-specific payload detail
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
            null = all(b == 0 for b in ambe)
            print(f'         AMBE({len(ambe)}B): {ambe.hex()}{"  [NULL]" if null else ""}')
        else:
            print(f'         AMBE: packet too short ({len(data)} bytes)')
        if len(data) > 52:
            print(f'         EMB/ext({len(data)-52}B): {data[52:].hex()}')

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='Decode IPSC wire log')
    ap.add_argument('logfile', help='Wire log file (or - for stdin)')
    ap.add_argument('--direction', choices=['RECV', 'SEND', 'BOTH'], default='BOTH',
                    help='Which packets to show (default: BOTH)')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='Full per-field decode of every packet')
    args = ap.parse_args()

    direction_filter = None if args.direction == 'BOTH' else args.direction

    src = open(args.logfile) if args.logfile != '-' else sys.stdin

    stats  = {}
    frames = 0
    shown  = 0

    print(f'IPSC wire decoder  — direction={args.direction}  verbose={args.verbose}\n{"="*72}')

    for line in src:
        m = _LINE_RE.search(line)
        if not m:
            continue
        frames += 1
        direction = m.group(1).upper()
        peer_ip   = m.group(2)
        length    = int(m.group(3))
        hex_data  = m.group(4)

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
        decode_packet(data, shown, direction, peer_ip, args.verbose, stats)

    if args.logfile != '-':
        src.close()

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
