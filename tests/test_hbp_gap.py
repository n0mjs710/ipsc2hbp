#!/usr/bin/env python3
"""
HBP→IPSC: a pause inside a network call is jitter, not the end of the call.  The
delivery clock fills a missing burst with silence; it ends the call (synthesized
VOICE_TERM) only after the network has been quiet for the watchdog time, as
MMDVMHost does for network voice (silence after 360 ms of lost audio, call end
when m_networkWatchdog, 1500 ms, expires).  Same cases as the C port's
tests/test_hbp_gap.c:

  1. a 600 ms pause mid-call: one call to the repeater (one IPSC call id, one
     VOICE_TERM, at the end), every burst delivered;
  2. the stream stops with no VOICE_TERM: the call is ended 1.5 s after the
     buffered bursts drain, not sooner, and only once.

The VOICE_HEAD / VOICE_TERM come from parity_in_dmrd.txt (group call
3120000 -> TG 91); the voice bursts between them are built here.

Run with:
    cd /home/cort/ipsc2hbp && python -m pytest tests/test_hbp_gap.py -v
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load as load_config
from ipsc.const import VOICE_HEAD, VOICE_TERM
from translate.translator import CallTranslator

_DIR      = os.path.dirname(os.path.abspath(__file__))
_CFG_PATH = os.path.join(_DIR, 'test.toml')

GV_CALL_ID = 5     # GROUP_VOICE: IPSC call id
GV_BURST   = 30    # GROUP_VOICE: burst type


class _MockHBP:
    def is_connected(self):  return True
    def send_dmrd(self, dmrd): pass
    def activate(self):  pass
    def deactivate(self): pass


class _MockIPSC:
    def __init__(self):
        self.sent = []     # (loop time, packet)
    def has_peers(self):
        return True
    def send_voice(self, pkt):
        self.sent.append((asyncio.get_event_loop().time(), bytes(pkt)))


def _head_term():
    with open(os.path.join(_DIR, 'parity_in_dmrd.txt')) as f:
        head, term = [bytes.fromhex(l.strip()) for l in f if l.strip()][:2]
    return head, term


def _burst(head, idx):
    """Voice burst idx (1-based) of the head's stream: A..F by position."""
    d = bytearray(head[:20]) + bytes((idx * 13 + i) & 0xFF for i in range(33)) + b'\x00\x00'
    d[4] = idx & 0xFF
    pos = (idx - 1) % 6
    d[15] = (head[15] & 0xC0) | (0x10 if pos == 0 else pos)
    return bytes(d)


def _play(script, run_s):
    """Feed (offset_s, dmrd) items at their offsets inside a running loop; return
    (IPSC frames sent, loop time of the last item, jitter_buffer_depth)."""
    cfg = load_config(_CFG_PATH)
    tr = CallTranslator(cfg)
    ip = _MockIPSC()
    tr.set_protocols(ip, _MockHBP())
    last = [0.0]

    async def go():
        loop = asyncio.get_event_loop()
        base = loop.time()
        for at, pkt in script:
            await asyncio.sleep(max(0.0, base + at - loop.time()))
            tr.hbp_voice_received(pkt)
            last[0] = loop.time()
        await asyncio.sleep(max(0.0, base + run_s - loop.time()))
    asyncio.run(go())
    return ip.sent, last[0], cfg.jitter_buffer_depth


class TestHbpGap(unittest.TestCase):

    def setUp(self):
        self.head, self.term = _head_term()

    def test_pause_mid_call_is_one_call(self):
        """A 600 ms pause mid-call reaches the repeater as one call with one VOICE_TERM."""
        script, t = [(0.0, self.head)], 0.06
        for i in range(1, 61):
            script.append((t, _burst(self.head, i)))
            t += 0.60 if i == 30 else 0.06
        script.append((t, self.term))
        sent, _, _ = _play(script, t + 1.0)
        frames = [p for _, p in sent]
        terms = [p for p in frames if p[GV_BURST] == VOICE_TERM]
        voice = [p for p in frames if p[GV_BURST] not in (VOICE_HEAD, VOICE_TERM)]
        self.assertEqual(len(terms), 1, 'the call was cut at the pause')
        self.assertEqual(frames[-1][GV_BURST], VOICE_TERM)
        self.assertEqual({p[GV_CALL_ID] for p in frames}, {frames[0][GV_CALL_ID]},
                         'the call reached the repeater as more than one IPSC call')
        self.assertGreaterEqual(len(voice), 60)

    def test_lost_term_ends_the_call_after_the_watchdog(self):
        """A lost VOICE_TERM ends the call 1.5 s after the buffered bursts drain."""
        script = [(0.0, self.head)] + [(0.06 * i, _burst(self.head, i)) for i in range(1, 21)]
        sent, last, depth = _play(script, 3.0)
        terms = [(t, p) for t, p in sent if p[GV_BURST] == VOICE_TERM]
        self.assertEqual(len(terms), 1)
        want = 1.5 + depth * 0.060
        self.assertAlmostEqual(terms[0][0] - last, want, delta=0.15)


if __name__ == '__main__':
    unittest.main()
