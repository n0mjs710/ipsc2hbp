#!/usr/bin/env python3
"""
Regression test for the Talker-Alias "ghost stream" bug (fix/ta-ghost-streams).

Current XPR8400 firmware, when a radio transmits with Talker Alias enabled,
chops a single continuous OTA voice call into a new IPSC stream every superframe:
the call-seq byte (5) increments per superframe and, on the TA superframes, the
embedded LC carries Talker Alias (FLCO 0x04-0x08 at burst-E byte 56) with the
alias text bytes stuffed into the common-header src/dst fields. The RTP timestamp
stays continuous throughout — it is one call.

The translator must therefore:
  * NOT treat a call-seq change as a call boundary (anchor on RTP continuity),
  * anchor identity to a GVCU (FLCO 0x00) burst E, never a TA superframe,
  * forward every voice frame under one stable HBP stream ID and the GVCU identity.

Captured live as 1 PTT -> 30 IPSC streams (15 of them the phantom alias identity).
After the fix it must collapse to a single HBP call with the real identity.

Run with:
    cd /home/cort/ipsc2hbp && python -m pytest tests/test_ta_ghost_streams.py -v
"""

import asyncio
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import load as load_config
from ipsc.const import (
    GROUP_VOICE, VOICE_HEAD, VOICE_TERM, SLOT1_VOICE,
    GV_BE_FLAG, GV_BE_LC_FLCO_OFF,
)
from translate.translator import CallTranslator

_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test.toml')

# Real call identity vs. the Talker-Alias bytes observed on the wire ("N0MJS\x00").
_REAL_SRC  = b'\x2f\x9b\x65'    # radio ID 3120101
_REAL_DST  = b'\x00\x00\x09'    # TG 9
_ALIAS_DST = b'\x4e\x30\x4d'    # "N0M"  — alias text, NOT an address
_ALIAS_SRC = b'\x4a\x53\x00'    # "JS\0"

_PEER_ID   = b'\x00\x30\x12\x00'
_CALL_CTRL = b'\x00\x00\x43\xe2'
_AMBE19    = bytes(range(1, 20))   # arbitrary non-null AMBE payload

# DMRD layout: sig(4) seq(1) src(3) dst(3) rptr(4) flags(1) streamid(4) ...
_D_SRC, _D_DST, _D_SID = slice(5, 8), slice(8, 11), slice(16, 20)


class _MockHBP:
    def __init__(self):
        self.sent = []
    def is_connected(self):
        return True
    def send_dmrd(self, dmrd):
        self.sent.append(bytes(dmrd))
    def activate(self):  pass
    def deactivate(self): pass


class _MockIPSC:
    def has_peers(self): return True
    def send_voice(self, pkt): pass


def _hdr(burst_type, callseq, rtp_ts, src, dst):
    """GROUP_VOICE common header (bytes 0-30) with RTP timestamp at 22-25."""
    b = bytearray(31)
    b[0] = GROUP_VOICE
    b[1:5] = _PEER_ID
    b[5] = callseq
    b[6:9] = src
    b[9:12] = dst
    b[12] = 0x02
    b[13:17] = _CALL_CTRL
    b[17] = 0x00                       # call_info: TS1
    b[22:26] = struct.pack('>I', rtp_ts & 0xFFFFFFFF)
    b[30] = burst_type
    return b


def _gv_head(callseq, rtp_ts, src=_REAL_SRC, dst=_REAL_DST):
    return bytes(_hdr(VOICE_HEAD, callseq, rtp_ts, src, dst)) + b'\x00' * (54 - 31)


def _gv_term(callseq, rtp_ts, src=_REAL_SRC, dst=_REAL_DST):
    return bytes(_hdr(VOICE_TERM, callseq, rtp_ts, src, dst)) + b'\x00' * (54 - 31)


def _gv_burst_e(callseq, rtp_ts, hdr_src, hdr_dst, flco, lc_src, lc_dst):
    """66-byte burst-E SLOT_VOICE frame carrying a reassembled LC repeat."""
    b = _hdr(SLOT1_VOICE, callseq, rtp_ts, hdr_src, hdr_dst)
    b += bytes([0x22])                 # length to follow (byte 31)
    b += bytes([GV_BE_FLAG])           # byte 32 = 0x16 (burst E)
    b += _AMBE19                       # bytes 33-51
    b += b'\x00\x00\x00\x00'           # bytes 52-55 embedded LC fragment 4
    b += bytes([flco, 0x00, 0x00])     # bytes 56-58 FLCO + FID + SVC_OPT
    b += lc_dst                        # bytes 59-61
    b += lc_src                        # bytes 62-64
    b += bytes([0x14])                 # byte 65 EMB
    assert len(b) == 66, len(b)
    return bytes(b)


class TestTalkerAliasGhostStreams(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._cfg = load_config(_CFG_PATH)
        asyncio.set_event_loop(asyncio.new_event_loop())

    def _make_tr(self):
        tr = CallTranslator(self._cfg)
        hbp = _MockHBP()
        tr.set_protocols(_MockIPSC(), hbp)
        return tr, hbp

    def _feed(self, tr, frame):
        bt = frame[30]
        tr.ipsc_voice_received(frame, ts=1, burst_type=bt)

    def test_ta_call_collapses_to_one_stream_with_real_identity(self):
        """HEAD then alternating GVCU/TA superframes (call-seq churning, alias
        bytes in header) must forward as ONE HBP stream with the real identity."""
        tr, hbp = self._make_tr()
        rtp = 1000
        self._feed(tr, _gv_head(0x10, rtp))
        # 10 superframes, alternating GVCU (real id) and TA (alias id), call-seq++.
        for i in range(10):
            rtp += 480
            seq = 0x11 + i
            if i % 2 == 0:
                self._feed(tr, _gv_burst_e(seq, rtp, _REAL_SRC, _REAL_DST,
                                           0x00, _REAL_SRC, _REAL_DST))
            else:
                self._feed(tr, _gv_burst_e(seq, rtp, _ALIAS_SRC, _ALIAS_DST,
                                           0x04, _ALIAS_SRC, _ALIAS_DST))
        rtp += 480
        self._feed(tr, _gv_term(0x1c, rtp))

        self.assertEqual(len(hbp.sent), 12, 'every frame forwarded, none dropped')
        sids = {d[_D_SID] for d in hbp.sent}
        self.assertEqual(len(sids), 1, f'exactly one HBP stream, got {len(sids)}')
        srcs = {d[_D_SRC] for d in hbp.sent}
        dsts = {d[_D_DST] for d in hbp.sent}
        self.assertEqual(srcs, {_REAL_SRC}, 'all frames carry the real source ID')
        self.assertEqual(dsts, {_REAL_DST}, 'all frames carry the real TGID')
        self.assertNotIn(_ALIAS_SRC, srcs, 'alias bytes never forwarded as identity')

    def test_late_entry_defers_until_gvcu_burst_e(self):
        """Late entry that first sees a TA burst E must wait for a GVCU burst E
        before establishing — never anchoring to the alias identity."""
        tr, hbp = self._make_tr()
        rtp = 5000
        # First burst E seen is Talker Alias -> must be ignored (no output).
        self._feed(tr, _gv_burst_e(0x40, rtp, _ALIAS_SRC, _ALIAS_DST,
                                   0x04, _ALIAS_SRC, _ALIAS_DST))
        self.assertEqual(len(hbp.sent), 0, 'TA burst E must not establish a call')
        # Next GVCU burst E establishes the call with the real identity.
        rtp += 480
        self._feed(tr, _gv_burst_e(0x41, rtp, _REAL_SRC, _REAL_DST,
                                   0x00, _REAL_SRC, _REAL_DST))
        # A following TA superframe is still forwarded under the locked identity.
        rtp += 480
        self._feed(tr, _gv_burst_e(0x42, rtp, _ALIAS_SRC, _ALIAS_DST,
                                   0x04, _ALIAS_SRC, _ALIAS_DST))

        self.assertEqual(len(hbp.sent), 2, 'GVCU + following frame forwarded')
        self.assertTrue(all(d[_D_SRC] == _REAL_SRC for d in hbp.sent),
                        'late-entry identity is the GVCU source, never the alias')
        self.assertEqual(len({d[_D_SID] for d in hbp.sent}), 1, 'single stream')


if __name__ == '__main__':
    unittest.main()
