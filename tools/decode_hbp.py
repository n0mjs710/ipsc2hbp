#!/usr/bin/env python3
"""
Decode HBP (HomeBrew Protocol) wire log lines and display human-readable
call analysis.

Reads lines containing:
    HBP RECV <len> <hex>
    HBP SEND <len> <hex>

from a log file (syslog, journald, or --wire output — the prefix before
the HBP token is ignored).

Usage:
    python tools/decode_hbp.py <logfile> [--direction RECV|SEND|BOTH]

Requires dmr_utils3 (available in the project venv).
"""

import argparse
import re
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

try:
    from bitarray import bitarray
    from dmr_utils3 import bptc as _bptc
    _HAVE_BPTC = True
except ImportError:
    _HAVE_BPTC = False

# ---------------------------------------------------------------------------
# HBP / DMRD constants (inlined)
# ---------------------------------------------------------------------------
DMRD_LEN         = 55
DMRD_SEQ_OFF     = 4
DMRD_SRC_OFF     = 5
DMRD_DST_OFF     = 8
DMRD_RPTR_OFF    = 11
DMRD_FLAGS_OFF   = 15
DMRD_STREAM_OFF  = 16
DMRD_PAYLOAD_OFF = 20
DMRD_BER_OFF     = 53
DMRD_RSSI_OFF    = 54

HBPF_TGID_TS2         = 0x80
HBPF_TGID_CALL_P      = 0x40
HBPF_FRAMETYPE_VOICE     = 0x00
HBPF_FRAMETYPE_VOICESYNC = 0x10
HBPF_FRAMETYPE_DATASYNC  = 0x20
HBPF_FRAMETYPE_MASK      = 0x30
HBPF_DTYPE_MASK          = 0x0F
HBPF_SLT_VHEAD           = 0x01
HBPF_SLT_VTERM           = 0x02

FLCO_NAMES = {0x00: 'Group', 0x03: 'Unit-to-Unit'}

# Known magic-string prefixes for non-DMRD packets
_MAGIC = {
    b'RPTL': 'RPTL (login)',
    b'RPTK': 'RPTK (auth)',
    b'RPTC': 'RPTC (config)',
    b'RPTO': 'RPTO (options)',
    b'RPTP': 'RPTPING',
    b'RPTC': 'RPTCL',
    b'RPTA': 'RPTACK',
    b'MSTN': 'MSTNAK',
    b'MSTP': 'MSTPONG',
    b'MSTC': 'MSTCL',
}

_LINE_RE = re.compile(r'HBP (RECV|SEND) (\d+) ([0-9a-f]+)', re.IGNORECASE)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _id3(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _id4(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def _decode_lc(payload_33: bytes) -> dict | None:
    """BPTC-decode LC from a 33-byte DMRD HEAD or TERM payload."""
    if not _HAVE_BPTC or len(payload_33) < 33:
        return None
    try:
        ba = bitarray(endian='big')
        ba.frombytes(payload_33)
        bptc_bits = ba[0:98] + ba[166:264]   # 196-bit BPTC codeword
        lc_bits   = _bptc.decode_full_lc(bptc_bits)
        lc        = lc_bits.tobytes()
        return {
            'flco':    lc[0],
            'fid':     lc[1],
            'svc_opt': lc[2],
            'dst':     _id3(lc[3:6]),
            'src':     _id3(lc[6:9]),
            'raw':     lc.hex(),
        }
    except Exception as e:
        return {'error': str(e)}

def _frame_type_name(flags: int) -> str:
    ts        = 2 if (flags & HBPF_TGID_TS2) else 1
    call_type = 'P' if (flags & HBPF_TGID_CALL_P) else 'G'
    ft        = flags & HBPF_FRAMETYPE_MASK
    dtype     = flags & HBPF_DTYPE_MASK

    if ft == HBPF_FRAMETYPE_DATASYNC:
        if dtype == HBPF_SLT_VHEAD:
            return f'TS{ts} {call_type} VOICE_LC_HEAD'
        elif dtype == HBPF_SLT_VTERM:
            return f'TS{ts} {call_type} VOICE_LC_TERM'
        else:
            return f'TS{ts} {call_type} DATASYNC dtype=0x{dtype:02x}'
    elif ft == HBPF_FRAMETYPE_VOICESYNC:
        return f'TS{ts} {call_type} VOICESYNC (Burst A)'
    elif ft == HBPF_FRAMETYPE_VOICE:
        burst_names = {0: 'Burst B', 1: 'Burst C', 2: 'Burst D',
                       3: 'Burst E', 4: 'Burst F', 5: 'Burst F+1'}
        burst = burst_names.get(dtype, f'dtype={dtype}')
        note  = '  *** dtype=5: BM sends as last superframe burst (handled as Burst F)' if dtype == 5 else ''
        return f'TS{ts} {call_type} VOICE {burst}{note}'
    else:
        return f'TS{ts} {call_type} flags=0x{flags:02x}'

# ---------------------------------------------------------------------------
# Packet decoder
# ---------------------------------------------------------------------------

def decode_packet(data: bytes, frame_num: int, direction: str, stats: dict):
    if len(data) < 4:
        print(f'  [{frame_num:4d}] {direction}  (too short: {len(data)} bytes)')
        return

    magic = data[:4]

    # --- Non-DMRD ---
    if magic != b'DMRD':
        label = 'UNKNOWN'
        for prefix, name in _MAGIC.items():
            if data[:len(prefix)] == prefix:
                label = name
                break
        if label == 'UNKNOWN':
            try:
                label = data[:4].decode('ascii', errors='replace')
            except Exception:
                label = data[:4].hex()
        print(f'  [{frame_num:4d}] {direction}  {label:<20s}  len={len(data)}  '
              f'raw={data[:16].hex()}{"…" if len(data) > 16 else ""}')
        stats.setdefault('other', []).append(label)
        return

    # --- DMRD ---
    if len(data) < DMRD_FLAGS_OFF + 1:
        print(f'  [{frame_num:4d}] {direction}  DMRD  TOO SHORT ({len(data)} bytes)')
        return

    seq        = data[DMRD_SEQ_OFF]
    src        = _id3(data[DMRD_SRC_OFF  : DMRD_SRC_OFF  + 3])
    dst        = _id3(data[DMRD_DST_OFF  : DMRD_DST_OFF  + 3])
    rptr       = _id4(data[DMRD_RPTR_OFF : DMRD_RPTR_OFF + 4])
    flags      = data[DMRD_FLAGS_OFF]
    stream_id  = data[DMRD_STREAM_OFF : DMRD_STREAM_OFF + 4].hex()
    ber        = data[DMRD_BER_OFF]  if len(data) > DMRD_BER_OFF  else 0
    rssi       = data[DMRD_RSSI_OFF] if len(data) > DMRD_RSSI_OFF else 0
    payload_33 = data[DMRD_PAYLOAD_OFF : DMRD_PAYLOAD_OFF + 33] if len(data) >= DMRD_PAYLOAD_OFF + 33 else b''

    ts         = 2 if (flags & HBPF_TGID_TS2) else 1
    ft         = flags & HBPF_FRAMETYPE_MASK
    dtype      = flags & HBPF_DTYPE_MASK
    ft_name    = _frame_type_name(flags)

    # Sequence gap detection per-stream
    stream_key = (direction, stream_id, ts)
    prev_seq   = stats.get(('seq', stream_key))
    seq_note   = ''
    if prev_seq is not None and ft not in (HBPF_FRAMETYPE_DATASYNC,):
        gap = (seq - prev_seq - 1) & 0xFF
        if gap:
            seq_note = f'  *** SEQ GAP {gap}'
    stats[('seq', stream_key)] = seq

    # Stream ID continuity
    prev_stream = stats.get(('stream', (direction, ts)))
    if prev_stream is not None and prev_stream != stream_id and ft == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VHEAD:
        print(f'  *** New stream: {prev_stream} → {stream_id} on TS{ts}')
    if ft == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VHEAD:
        stats[('stream', (direction, ts))] = stream_id

    # Track burst counts
    stats.setdefault('burst_counts', {})
    bc_key = ft_name.split('  ***')[0].strip()
    stats['burst_counts'][bc_key] = stats['burst_counts'].get(bc_key, 0) + 1

    ber_str  = f'  BER={ber}' if ber else ''
    rssi_str = f'  RSSI={rssi}' if rssi else ''

    print(f'  [{frame_num:4d}] {direction}  {ft_name}')
    print(f'         seq={seq:3d}{seq_note}  src={src}  dst={dst}  '
          f'rptr={rptr}  stream={stream_id}{ber_str}{rssi_str}')

    # --- Frame-type detail ---
    if ft == HBPF_FRAMETYPE_DATASYNC and dtype in (HBPF_SLT_VHEAD, HBPF_SLT_VTERM):
        lc = _decode_lc(payload_33)
        if lc is None:
            if not _HAVE_BPTC:
                print(f'         LC:  (dmr_utils3 not available — run from venv)')
            else:
                print(f'         LC:  (payload too short)')
        elif 'error' in lc:
            print(f'         LC:  (decode error: {lc["error"]})')
        else:
            flco_name = FLCO_NAMES.get(lc['flco'], f'0x{lc["flco"]:02x}')
            print(f'         LC:  flco={flco_name}  fid=0x{lc["fid"]:02x}  '
                  f'svc=0x{lc["svc_opt"]:02x}  dst={lc["dst"]}  src={lc["src"]}  '
                  f'raw={lc["raw"]}')

    elif ft in (HBPF_FRAMETYPE_VOICE, HBPF_FRAMETYPE_VOICESYNC):
        if payload_33:
            ambe_hex = payload_33.hex()
            null = all(b == 0 for b in payload_33)
            print(f'         payload(33B): {ambe_hex}{"  [NULL]" if null else ""}')
        else:
            print(f'         payload: (missing or short)')

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description='Decode HBP wire log')
    ap.add_argument('logfile', help='Wire log file (or - for stdin)')
    ap.add_argument('--direction', choices=['RECV', 'SEND', 'BOTH'], default='BOTH',
                    help='Which packets to show (default: BOTH)')
    args = ap.parse_args()

    if not _HAVE_BPTC:
        print('WARNING: dmr_utils3 not found — LC decode unavailable. '
              'Run from the project venv.\n', file=sys.stderr)

    direction_filter = None if args.direction == 'BOTH' else args.direction

    src = open(args.logfile) if args.logfile != '-' else sys.stdin

    stats  = {}
    frames = 0
    shown  = 0

    print(f'HBP wire decoder  — direction={args.direction}\n{"="*72}')

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
    print(f'SUMMARY: {frames} HBP lines scanned, {shown} shown')
    burst_counts = stats.get('burst_counts', {})
    if burst_counts:
        print('  Frame counts:')
        for name, count in sorted(burst_counts.items(), key=lambda x: -x[1]):
            print(f'    {name:<50s} {count}')
    other = stats.get('other', [])
    if other:
        from collections import Counter
        print('  Non-DMRD:')
        for op, cnt in Counter(other).most_common():
            print(f'    {op:<22s} {cnt}')

if __name__ == '__main__':
    main()
