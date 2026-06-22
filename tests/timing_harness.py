#!/usr/bin/env python3
"""Offline HBP->IPSC timing harness.

Feeds a synthetic, perfectly-clean 60 ms HBP DMRD stream (headers, voice bursts,
terminator) through the real CallTranslator and records the wall-clock emit time
of every GROUP_VOICE packet we send to IPSC.  Reports the header->voice gap, the
inter-burst cadence, voice-in vs voice-out (tail clipping), and the
last-voice->TERM gap.

This measures OUR output shape so we can (a) demonstrate the ~300 ms void / tail
clip in the current design and (b) prove the uniform-delay rewrite produces the
native 60 ms grid.

    cd /home/cort/ipsc2hbp && source venv/bin/activate
    python -m tests.timing_harness
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load as load_config
from ipsc.const import GROUP_VOICE, VOICE_HEAD, VOICE_TERM, SLOT1_VOICE, SLOT2_VOICE
from hbp.const import (HBPF_DMRD, HBPF_TGID_TS2,
                       HBPF_FRAMETYPE_VOICE, HBPF_FRAMETYPE_VOICESYNC)
from translate.translator import CallTranslator
from tests.test_timeslot import _dmrd_head, _dmrd_term, _SRC_SUB, _DST_GROUP


def _dmrd_voice_pos(ts: int, pos: int) -> bytes:
    """DMRD voice burst for superframe position 0-5 (A-F).

    The translator maps VOICESYNC→0 and VOICE|dtype where dtype==pos for 1-5,
    so build the flags to land on each distinct position."""
    if pos == 0:
        flags = HBPF_FRAMETYPE_VOICESYNC
    else:
        flags = HBPF_FRAMETYPE_VOICE | pos
    if ts == 2:
        flags |= HBPF_TGID_TS2
    return (HBPF_DMRD + b'\x00' + _SRC_SUB + _DST_GROUP + b'\x00\x00\x00\x00'
            + bytes([flags]) + b'\x00\x00\x00\x00' + b'\x00' * 33 + b'\x00\x00')

_CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test.toml')
SLOT = 0.060


class RecordingIPSC:
    """Mock IPSC peer that timestamps every emitted GROUP_VOICE packet."""
    def __init__(self, loop):
        self._loop = loop
        self.events = []   # (t_rel, burst_byte)
        self._t0 = None
    def has_peers(self):
        return True
    def send_voice(self, pkt):
        t = self._loop.time()
        if self._t0 is None:
            self._t0 = t
        b = bytes(pkt)
        burst = b[30] if len(b) > 30 and b[0] == GROUP_VOICE else None
        self.events.append(((t - self._t0) * 1000.0, burst))


class _MockHBP:
    def is_connected(self): return True
    def send_dmrd(self, d): pass
    def activate(self): pass
    def deactivate(self): pass


def _name(b):
    return {VOICE_HEAD: 'HEAD', VOICE_TERM: 'TERM',
            SLOT1_VOICE: 'voice', SLOT2_VOICE: 'voice'}.get(b, f'0x{b:02x}')


async def _drive(n_headers=2, n_superframes=2):
    loop = asyncio.get_event_loop()
    cfg = load_config(_CFG)
    tr = CallTranslator(cfg)
    ipsc = RecordingIPSC(loop)
    tr.set_protocols(ipsc, _MockHBP())

    voice_in = 0
    # clean 60 ms cadence: headers, then voice superframes, then terminator
    for _ in range(n_headers):
        tr.hbp_voice_received(_dmrd_head(ts=1))
        await asyncio.sleep(SLOT)
    for _ in range(n_superframes):
        for pos in range(6):
            tr.hbp_voice_received(_dmrd_voice_pos(ts=1, pos=pos))
            voice_in += 1
            await asyncio.sleep(SLOT)
    tr.hbp_voice_received(_dmrd_term(ts=1))
    # let any buffered tail drain
    await asyncio.sleep(SLOT * 6)
    return ipsc.events, voice_in


def _report(events, voice_in):
    print(f'\nemitted {len(events)} GROUP_VOICE packets:')
    for t, b in events:
        print(f'  t={t:7.1f} ms   {_name(b)}')
    heads = [t for t, b in events if b == VOICE_HEAD]
    voices = [t for t, b in events if b in (SLOT1_VOICE, SLOT2_VOICE)]
    terms = [t for t, b in events if b == VOICE_TERM]
    print('\n--- metrics ---')
    if heads and voices:
        print(f'  last HEAD -> first voice : {voices[0] - heads[-1]:7.1f} ms   '
              '(native ~60; current design inflates by jitter depth)')
    if len(voices) > 1:
        deltas = [voices[i] - voices[i - 1] for i in range(1, len(voices))]
        print(f'  voice cadence            : '
              f'min {min(deltas):.1f}  max {max(deltas):.1f}  (nominal 60.0)')
    print(f'  voice bursts  in / out   : {voice_in} / {len(voices)}'
          f'   {"<-- TAIL CLIPPED" if len(voices) < voice_in else "(none dropped)"}')
    if terms and voices:
        print(f'  last voice -> TERM       : {terms[0] - voices[-1]:7.1f} ms   '
              '(native ~60; TERM should trail the last buffered burst)')


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    events, voice_in = loop.run_until_complete(_drive())
    loop.close()
    _report(events, voice_in)


if __name__ == '__main__':
    main()
