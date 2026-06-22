#!/usr/bin/env python3
"""Generate IPSC voice frames, run them through the Python CallTranslator,
and emit both the input frames and the reference DMRD output (stream-id masked)
so the C port can be compared byte-for-byte.

Outputs:
  /tmp/parity_in.txt   lines: "<ts> <burst_type> <input_hex>"
  /tmp/parity_ref.txt  lines: "<dmrd_hex_masked>"  (one per DMRD emitted)
"""
import asyncio
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import load as load_config
from translate.translator import CallTranslator
from ipsc.const import (GROUP_VOICE, VOICE_HEAD, VOICE_TERM, SLOT1_VOICE,
                        GV_CALL_INFO_OFF, GV_BURST_TYPE_OFF, TS_CALL_MSK)


class MockIPSC:
    def has_peers(self): return True
    def send_voice(self, pkt): pass
class MockHBP:
    def __init__(self): self.sent = []
    def is_connected(self): return True
    def send_dmrd(self, d): self.sent.append(bytes(d))
    def activate(self): pass
    def deactivate(self): pass


def build_frame(call_seq, src, dst, ts, burst_type, ambe=b'', byte32=0x00):
    f = bytearray(54)
    f[0] = GROUP_VOICE
    f[1:5] = (0x0004c317).to_bytes(4, 'big')       # peer id
    f[5] = call_seq
    f[6:9] = src.to_bytes(3, 'big')
    f[9:12] = dst.to_bytes(3, 'big')
    f[12] = 0x02                                    # call type
    f[13:17] = bytes([0x00, 0x00, 0x43, 0xe2])      # call ctrl
    f[17] = TS_CALL_MSK if ts == 2 else 0x00        # call_info
    f[22:26] = (0x1000).to_bytes(4, 'big')          # rtp ts (debug only)
    f[30] = burst_type
    f[32] = byte32
    if ambe:
        f[33:52] = ambe
    return bytes(f)


def main():
    # The inbound (HBP→IPSC) path clocks frames out via asyncio timers, so a
    # loop must exist for call_at()/loop.time(); we drive the clock manually below.
    asyncio.set_event_loop(asyncio.new_event_loop())
    cfg = load_config(os.path.join(os.path.dirname(__file__), '..', 'tests', 'test.toml'))
    tr = CallTranslator(cfg)
    hbp = MockHBP()
    tr.set_protocols(MockIPSC(), hbp)

    frames = []
    # one clean call on TS1, constant call_seq = 0x05
    cs = 0x05
    frames.append((1, VOICE_HEAD, build_frame(cs, 3120001, 91, 1, VOICE_HEAD)))
    for i in range(6):
        # deterministic AMBE pattern per burst
        ambe = bytes(((i * 19 + k) * 7) & 0xFF for k in range(19))
        b32 = 0x16 if i == 4 else 0x00     # burst E marker
        frames.append((1, SLOT1_VOICE, build_frame(cs, 3120001, 91, 1, SLOT1_VOICE, ambe, b32)))
    frames.append((1, VOICE_TERM, build_frame(cs, 3120001, 91, 1, VOICE_TERM)))

    # second call on TS1 with a CHANGING call_seq to force the stream-change ->
    # Burst-E late-entry path (the path the constant-call_seq case never hits).
    frames.append((1, VOICE_HEAD, build_frame(0x10, 3120101, 9, 1, VOICE_HEAD)))
    seqs = [0x11, 0x11, 0x12, 0x12, 0x13, 0x13]   # changes mid-stream
    for i in range(6):
        ambe = bytes(((i * 23 + k) * 5) & 0xFF for k in range(19))
        b32 = 0x16 if i == 4 else 0x00
        frames.append((1, SLOT1_VOICE, build_frame(seqs[i], 3120101, 9, 1, SLOT1_VOICE, ambe, b32)))
    frames.append((1, VOICE_TERM, build_frame(0x13, 3120101, 9, 1, VOICE_TERM)))

    with open('/tmp/parity_in.txt', 'w') as fi:
        for ts, bt, raw in frames:
            fi.write(f"{ts} {bt} {raw.hex()}\n")

    for ts, bt, raw in frames:
        tr.ipsc_voice_received(raw, ts, bt)

    def mask(d):
        b = bytearray(d)
        b[16:20] = b'\x00\x00\x00\x00'   # stream_id is random
        return bytes(b)

    with open('/tmp/parity_ref.txt', 'w') as fo:
        for d in hbp.sent:
            fo.write(mask(d).hex() + "\n")

    # ---- inbound parity (HBP -> IPSC), HEAD + TERM (immediate, deterministic) ----
    # Build real 55-byte DMRD from the outbound HEAD/TERM (pad masked stream to 55).
    head_dmrd = hbp.sent[0] + b''          # already 55 bytes
    term_dmrd = hbp.sent[-1]
    in_frames = [head_dmrd, term_dmrd]

    tr2 = CallTranslator(cfg)
    cap = []
    class MockIPSC2:
        def has_peers(self): return True
        def send_voice(self, pkt): cap.append(bytes(pkt))
    tr2.set_protocols(MockIPSC2(), MockHBP())
    for d in in_frames:
        tr2.hbp_voice_received(d)
    # HEAD/TERM are now clocked out via the delivery timer — fire slots until the
    # call clears so the reference captures the emitted GROUP_VOICE frames.
    for _ in range(12):
        if (tr2._in_lc[1] is None and not tr2._in_head_queue[1]
                and not tr2._in_term_pending[1]):
            break
        tr2._deliver_slot(1)

    with open('/tmp/parity_in_dmrd.txt', 'w') as fo:
        for d in in_frames:
            fo.write(d.hex() + "\n")
    with open('/tmp/parity_ref_gv.txt', 'w') as fo:
        for g in cap:
            fo.write(g.hex() + "\n")

    print(f"frames={len(frames)} dmrd_out={len(hbp.sent)} inbound_gv_out={len(cap)}")


if __name__ == '__main__':
    main()
