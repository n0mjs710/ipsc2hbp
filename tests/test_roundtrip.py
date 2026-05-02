#!/usr/bin/env python3
"""
Round-trip test: IPSC GROUP_VOICE → HBP DMRD → IPSC GROUP_VOICE

Feed real IPSC GROUP_VOICE frames from a --wire capture through the outbound
translation (ipsc_voice_received) and back through inbound (hbp_voice_received).
For each SLOT_VOICE burst, compare the original 19-byte AMBE block with the
round-tripped one.

Capture procedure:
  1. Run: python ipsc2hbp.py --wire 2>wire.txt
  2. Make a voice call from the IPSC repeater side
  3. Ctrl-C to stop
  4. Run: python tests/test_roundtrip.py wire.txt

Exit code: 0 if all AMBE blocks survive the round trip, 1 if any differ.
"""

import os
import re
import sys
from bitarray import bitarray

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load as load_config
from ipsc.const import (
    GROUP_VOICE, VOICE_HEAD, VOICE_TERM, SLOT1_VOICE, SLOT2_VOICE,
    GV_CALL_INFO_OFF, GV_BURST_TYPE_OFF,
    GV_SRC_SUB_OFF, GV_DST_GROUP_OFF,
    TS_CALL_MSK,
)
from translate.translator import CallTranslator

AMBE_OFF = 33   # first byte of 19-byte AMBE block in IPSC SLOT_VOICE
AMBE_END = 52


class _MockIPSC:
    def __init__(self):
        self.sent = []
    def has_peers(self):
        return True
    def send_voice(self, pkt):
        self.sent.append(bytes(pkt))


class _MockHBP:
    def __init__(self):
        self.sent = []
    def is_connected(self):
        return True
    def send_dmrd(self, dmrd):
        self.sent.append(bytes(dmrd))
    def activate(self):
        pass
    def deactivate(self):
        pass


def parse_wire(path):
    pattern = re.compile(r'RECV \d+ ([0-9a-f]+)')
    packets = []
    with open(path) as f:
        for line in f:
            m = pattern.search(line)
            if m:
                raw = bytes.fromhex(m.group(1))
                if len(raw) > 0 and raw[0] == GROUP_VOICE:
                    packets.append(raw)
    return packets


def decode_burst(data):
    """Return (ts, burst_type) from a GROUP_VOICE packet."""
    burst_type = data[GV_BURST_TYPE_OFF]
    call_info  = data[GV_CALL_INFO_OFF]
    if burst_type in (VOICE_HEAD, VOICE_TERM):
        ts = 2 if (call_info & TS_CALL_MSK) else 1
    else:
        ts = 2 if (burst_type & 0x80) else 1
    return ts, burst_type


def burst_label(bt):
    return {VOICE_HEAD: 'HEAD', VOICE_TERM: 'TERM',
            SLOT1_VOICE: 'TS1_V', SLOT2_VOICE: 'TS2_V'}.get(bt, f'0x{bt:02x}')


def bit_diffs(a: bytes, b: bytes):
    ba = bitarray(endian='big'); ba.frombytes(a)
    bb = bitarray(endian='big'); bb.frombytes(b)
    return [i for i in range(min(len(ba), len(bb))) if ba[i] != bb[i]]


def run(wire_path):
    cfg = load_config(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), 'ipsc2hbp.toml'))

    fwd_hbp   = _MockHBP()
    fwd_ipsc  = _MockIPSC()
    fwd_trans = CallTranslator(cfg)
    fwd_trans.set_protocols(fwd_ipsc, fwd_hbp)

    back_ipsc  = _MockIPSC()
    back_hbp   = _MockHBP()
    back_trans = CallTranslator(cfg)
    back_trans.set_protocols(back_ipsc, back_hbp)

    packets = parse_wire(wire_path)
    print(f'Loaded {len(packets)} GROUP_VOICE RECV packets\n')

    total_voice = 0
    mismatches  = 0

    for i, orig in enumerate(packets):
        if len(orig) < GV_BURST_TYPE_OFF + 1:
            continue
        ts, bt = decode_burst(orig)
        label  = burst_label(bt)
        src    = orig[GV_SRC_SUB_OFF : GV_SRC_SUB_OFF + 3].hex()
        dst    = orig[GV_DST_GROUP_OFF : GV_DST_GROUP_OFF + 3].hex()

        # ---- forward: IPSC → HBP ----
        fwd_hbp.sent.clear()
        fwd_trans.ipsc_voice_received(orig, ts, bt)
        dmrd_frames = list(fwd_hbp.sent)

        if not dmrd_frames:
            print(f'[{i:3d}] {label:6s}  src={src} dst={dst}  → no DMRD produced')
            continue

        # ---- backward: HBP → IPSC ----
        for dmrd in dmrd_frames:
            back_ipsc.sent.clear()
            back_trans.hbp_voice_received(dmrd)
            rt_packets = list(back_ipsc.sent)

            if bt not in (SLOT1_VOICE, SLOT2_VOICE):
                # HEAD/TERM: just show the LC bytes for manual inspection
                for rt in rt_packets:
                    if len(rt) >= 54:
                        orig_lc = orig[31:40] if len(orig) >= 40 else b'?'
                        rt_lc   = rt[31:40]   if len(rt)   >= 40 else b'?'
                        lc_ok   = '✓' if orig_lc == rt_lc else '✗'
                        print(f'[{i:3d}] {label:6s}  LC {lc_ok}  '
                              f'orig={orig_lc.hex()}  rt={rt_lc.hex()}')
                        break
                continue

            # SLOT_VOICE: compare the 19-byte AMBE block
            total_voice += 1
            if not rt_packets:
                print(f'[{i:3d}] {label:6s}  → no IPSC produced from back-translator')
                mismatches += 1
                continue

            # The round-trip should produce exactly one IPSC SLOT_VOICE
            rt = rt_packets[0]
            if len(rt) < AMBE_END or len(orig) < AMBE_END:
                print(f'[{i:3d}] {label:6s}  packet too short (orig={len(orig)} rt={len(rt)})')
                mismatches += 1
                continue

            orig_ambe = orig[AMBE_OFF:AMBE_END]
            rt_ambe   = rt[AMBE_OFF:AMBE_END]

            if orig_ambe == rt_ambe:
                print(f'[{i:3d}] {label:6s}  AMBE ✓  {orig_ambe.hex()}')
            else:
                diffs = bit_diffs(orig_ambe, rt_ambe)
                print(f'[{i:3d}] {label:6s}  AMBE ✗  ({len(diffs)} bit diffs at {diffs[:16]}{"…" if len(diffs)>16 else ""})')
                print(f'         orig: {orig_ambe.hex()}')
                print(f'         rt:   {rt_ambe.hex()}')
                mismatches += 1

    print(f'\n--- {total_voice} SLOT_VOICE bursts, {mismatches} AMBE mismatches ---')
    return mismatches


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python tests/test_roundtrip.py <wire.txt>')
        sys.exit(1)
    sys.exit(0 if run(sys.argv[1]) == 0 else 1)
