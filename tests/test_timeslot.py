#!/usr/bin/env python3
"""
Unit tests for per-timeslot call state isolation and hung-call timeout.

Tests the fixes for:
  - Dual-timeslot blocking: all call state is now keyed by timeslot (1 or 2)
    so TS1 and TS2 calls are fully independent in both directions.
  - Hung-call timeout: if a stream goes silent for >10 s without VOICE_TERM,
    check_call_timeouts() clears the slot so it can accept new calls.

Run with:
    cd /home/cort/ipsc2hbp
    source venv/bin/activate
    python -m pytest tests/test_timeslot.py -v
      -- or --
    python -m unittest tests.test_timeslot -v
"""

import os
import sys
import unittest
from unittest.mock import patch
from bitarray import bitarray

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dmr_utils3 import bptc
from dmr_utils3.const import LC_OPT
from config import load as load_config
from ipsc.const import (
    GROUP_VOICE, VOICE_HEAD, VOICE_TERM, SLOT1_VOICE, SLOT2_VOICE,
    TS_CALL_MSK,
    GV_SRC_SUB_OFF, GV_DST_GROUP_OFF,
)
from hbp.const import (
    HBPF_DMRD,
    HBPF_TGID_TS2,
    HBPF_FRAMETYPE_VOICE, HBPF_FRAMETYPE_VOICESYNC, HBPF_FRAMETYPE_DATASYNC,
    HBPF_SLT_VHEAD, HBPF_SLT_VTERM,
    DMRD_LEN,
)
from translate.translator import CallTranslator

# ---------------------------------------------------------------------------
# Constants used across all tests
# ---------------------------------------------------------------------------

_SRC_SUB   = b'\x00\x31\x5a'    # radio ID 3219802 — arbitrary
_DST_GROUP = b'\x00\x00\x01'    # TGID 1
_PEER_ID   = b'\x00\x30\x12\x00'
_CALL_CTRL = b'\x00\x00\x43\xe2'

_CFG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test.toml')

# ---------------------------------------------------------------------------
# Mock protocol objects
# ---------------------------------------------------------------------------

class _MockIPSC:
    def __init__(self):
        self.sent = []
    def is_peer_registered(self):
        return True
    def send_to_peer(self, pkt):
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


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def _ipsc_gv(ts: int, burst_type: int,
             src_sub: bytes = _SRC_SUB,
             dst_group: bytes = _DST_GROUP) -> bytes:
    """
    Minimal GROUP_VOICE packet.  The translator reads:
      bytes[6:9]   = src_sub
      bytes[9:12]  = dst_group
      bytes[12:13] = call_type
      bytes[13:17] = call_ctrl
      bytes[33:52] = AMBE (only for SLOT1/SLOT2_VOICE)
    burst_type and ts are passed as explicit args to ipsc_voice_received(),
    not read from the packet, so the rest of the bytes are padding.
    """
    if burst_type in (VOICE_HEAD, VOICE_TERM):
        call_info = TS_CALL_MSK if ts == 2 else 0x00
    else:
        call_info = 0x00
    hdr = (
        bytes([GROUP_VOICE])        # opcode (byte 0)
        + _PEER_ID                  # peer radio ID (bytes 1-4)
        + b'\x01'                   # call stream ID (byte 5)
        + src_sub                   # bytes 6-8
        + dst_group                 # bytes 9-11
        + b'\x02'                   # call_type (byte 12)
        + _CALL_CTRL                # bytes 13-16
        + bytes([call_info])        # bytes 17
        + b'\x00' * 13              # bytes 18-30 (RTP header + padding)
    )
    # Must reach byte 51 so SLOT_VOICE AMBE extraction doesn't short-circuit
    return hdr + b'\x00' * max(0, 52 - len(hdr))


def _dmrd_head(ts: int,
               src_sub: bytes = _SRC_SUB,
               dst_group: bytes = _DST_GROUP) -> bytes:
    """
    DMRD VOICE_LC_HEAD with a valid BPTC payload.
    Positions [98:108] and [156:166] (slot-type) and [108:156] (sync)
    are zero-padded — the BPTC decoder only reads positions [0:98]+[166:264].
    """
    lc = LC_OPT + dst_group + src_sub
    full_lc = bptc.encode_header_lc(lc)          # bitarray(196)
    pad68 = bitarray(68, endian='big')
    pad68.setall(0)
    frame_bits = full_lc[0:98] + pad68 + full_lc[98:]   # 264 bits = 33 bytes
    flags = HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VHEAD
    if ts == 2:
        flags |= HBPF_TGID_TS2
    return (
        HBPF_DMRD
        + b'\x00'                   # seq
        + src_sub                   # bytes 5-7
        + dst_group                 # bytes 8-10
        + b'\x00\x00\x00\x00'      # repeater_id
        + bytes([flags])            # flags byte
        + b'\x00\x00\x00\x00'      # stream_id
        + frame_bits.tobytes()      # 33-byte payload
        + b'\x00\x00'               # BER + RSSI
    )


def _dmrd_voice(ts: int, voice_seq: int = 0,
                src_sub: bytes = _SRC_SUB,
                dst_group: bytes = _DST_GROUP) -> bytes:
    """
    DMRD VOICESYNC (voice_seq=0) or VOICE burst (voice_seq=1..5) with a
    zeroed 33-byte payload.  Zero AMBE bits are valid for conversion purposes.
    """
    if voice_seq == 0:
        flags = HBPF_FRAMETYPE_VOICESYNC
    else:
        flags = HBPF_FRAMETYPE_VOICE | (voice_seq - 1)
    if ts == 2:
        flags |= HBPF_TGID_TS2
    return (
        HBPF_DMRD
        + b'\x00'
        + src_sub
        + dst_group
        + b'\x00\x00\x00\x00'
        + bytes([flags])
        + b'\x00\x00\x00\x00'
        + b'\x00' * 33              # zeroed DMR payload
        + b'\x00\x00'
    )


def _dmrd_term(ts: int,
               src_sub: bytes = _SRC_SUB,
               dst_group: bytes = _DST_GROUP) -> bytes:
    """DMRD VOICE_LC_TERM with a valid BPTC payload."""
    lc = LC_OPT + dst_group + src_sub
    full_lc = bptc.encode_terminator_lc(lc)
    pad68 = bitarray(68, endian='big')
    pad68.setall(0)
    frame_bits = full_lc[0:98] + pad68 + full_lc[98:]
    flags = HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VTERM
    if ts == 2:
        flags |= HBPF_TGID_TS2
    return (
        HBPF_DMRD
        + b'\x00'
        + src_sub
        + dst_group
        + b'\x00\x00\x00\x00'
        + bytes([flags])
        + b'\x00\x00\x00\x00'
        + frame_bits.tobytes()
        + b'\x00\x00'
    )


# ---------------------------------------------------------------------------
# Test fixture factory
# ---------------------------------------------------------------------------

_cfg = None


def setUpModule():
    global _cfg
    _cfg = load_config(_CFG_PATH)


def _make_tr():
    """Return (translator, mock_ipsc, mock_hbp) with protocols wired up."""
    tr   = CallTranslator(_cfg)
    ipsc = _MockIPSC()
    hbp  = _MockHBP()
    tr.set_protocols(ipsc, hbp)
    return tr, ipsc, hbp


# ===========================================================================
# 1. Outbound (IPSC→HBP) per-timeslot isolation
# ===========================================================================

class TestOutboundTimeslotIsolation(unittest.TestCase):
    """IPSC→HBP call state is independent per timeslot."""

    def test_ts1_head_does_not_open_ts2_stream(self):
        tr, _, _ = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        self.assertIsNotNone(tr._out_stream_id[1], 'TS1 stream should be open')
        self.assertIsNone(tr._out_stream_id[2],    'TS2 stream must stay None')

    def test_ts2_head_does_not_open_ts1_stream(self):
        tr, _, _ = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        self.assertIsNotNone(tr._out_stream_id[2], 'TS2 stream should be open')
        self.assertIsNone(tr._out_stream_id[1],    'TS1 stream must stay None')

    def test_both_ts_can_be_simultaneously_active(self):
        tr, _, _ = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        self.assertIsNotNone(tr._out_stream_id[1], 'TS1 stream should be open')
        self.assertIsNotNone(tr._out_stream_id[2], 'TS2 stream should be open')
        self.assertNotEqual(tr._out_stream_id[1], tr._out_stream_id[2],
                            'Each call gets a unique stream ID')

    def test_ts1_term_closes_only_ts1(self):
        tr, _, _ = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_TERM), ts=1, burst_type=VOICE_TERM)
        self.assertIsNone(tr._out_stream_id[1],    'TS1 stream should be closed')
        self.assertIsNotNone(tr._out_stream_id[2], 'TS2 stream must stay open')

    def test_ts2_term_closes_only_ts2(self):
        tr, _, _ = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_TERM), ts=2, burst_type=VOICE_TERM)
        self.assertIsNone(tr._out_stream_id[2],    'TS2 stream should be closed')
        self.assertIsNotNone(tr._out_stream_id[1], 'TS1 stream must stay open')

    def test_slot_voice_before_head_produces_no_output(self):
        tr, _, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, SLOT1_VOICE), ts=1, burst_type=SLOT1_VOICE)
        self.assertEqual(hbp.sent, [], 'SLOT_VOICE with no active call must be dropped')
        self.assertIsNone(tr._out_stream_id[1])

    def test_ts2_slot_voice_before_head_produces_no_output(self):
        tr, _, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(2, SLOT2_VOICE), ts=2, burst_type=SLOT2_VOICE)
        self.assertEqual(hbp.sent, [], 'TS2 SLOT_VOICE with no active call must be dropped')

    def test_ts1_voice_bursts_delivered_while_ts2_inactive(self):
        tr, _, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD),   ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(1, SLOT1_VOICE),  ts=1, burst_type=SLOT1_VOICE)
        self.assertEqual(len(hbp.sent), 2, 'Both HEAD and VOICE burst should reach HBP')

    def test_ts1_and_ts2_bursts_all_delivered(self):
        tr, _, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD),  ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD),  ts=2, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(1, SLOT1_VOICE), ts=1, burst_type=SLOT1_VOICE)
        tr.ipsc_voice_received(_ipsc_gv(2, SLOT2_VOICE), ts=2, burst_type=SLOT2_VOICE)
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_TERM),  ts=1, burst_type=VOICE_TERM)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_TERM),  ts=2, burst_type=VOICE_TERM)
        self.assertEqual(len(hbp.sent), 6, 'All 6 packets must reach HBP')

    def test_ts1_frame_pos_independent_of_ts2(self):
        tr, _, _ = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        # Advance TS1 frame position by sending 3 SLOT_VOICE bursts
        for _ in range(3):
            tr.ipsc_voice_received(_ipsc_gv(1, SLOT1_VOICE), ts=1, burst_type=SLOT1_VOICE)
        self.assertEqual(tr._out_frame_pos[1], 3)
        # TS2 frame position must be untouched
        self.assertEqual(tr._out_frame_pos[2], 0)


# ===========================================================================
# 2. Inbound (HBP→IPSC) per-timeslot isolation
# ===========================================================================

class TestInboundTimeslotIsolation(unittest.TestCase):
    """HBP→IPSC call state is independent per timeslot."""

    def test_ts1_head_does_not_open_ts2_lc(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        self.assertIsNotNone(tr._in_lc[1], 'TS1 LC should be populated')
        self.assertIsNone(tr._in_lc[2],    'TS2 LC must stay None')

    def test_ts2_head_does_not_open_ts1_lc(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=2))
        self.assertIsNotNone(tr._in_lc[2], 'TS2 LC should be populated')
        self.assertIsNone(tr._in_lc[1],    'TS1 LC must stay None')

    def test_both_ts_can_be_simultaneously_active(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))
        self.assertIsNotNone(tr._in_lc[1])
        self.assertIsNotNone(tr._in_lc[2])

    def test_ts1_term_clears_only_ts1(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))
        tr.hbp_voice_received(_dmrd_term(ts=1))
        self.assertIsNone(tr._in_lc[1],    'TS1 LC should be cleared by TERM')
        self.assertIsNotNone(tr._in_lc[2], 'TS2 LC must survive')

    def test_ts2_term_clears_only_ts2(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))
        tr.hbp_voice_received(_dmrd_term(ts=2))
        self.assertIsNone(tr._in_lc[2],    'TS2 LC should be cleared by TERM')
        self.assertIsNotNone(tr._in_lc[1], 'TS1 LC must survive')

    def test_stream_ids_are_independent(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        id1 = tr._in_stream_id[1]
        tr.hbp_voice_received(_dmrd_head(ts=2))
        id2 = tr._in_stream_id[2]
        self.assertNotEqual(id1, id2, 'Each call gets a unique stream ID byte')

    def test_ts1_voice_delivered_to_ipsc_while_ts2_inactive(self):
        tr, ipsc, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))
        self.assertEqual(len(ipsc.sent), 2)

    def test_ts1_and_ts2_bursts_all_delivered(self):
        tr, ipsc, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))
        tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))
        tr.hbp_voice_received(_dmrd_voice(ts=2, voice_seq=0))
        tr.hbp_voice_received(_dmrd_term(ts=1))
        tr.hbp_voice_received(_dmrd_term(ts=2))
        self.assertEqual(len(ipsc.sent), 6)

    def test_rtp_seq_tracked_per_ts(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))
        tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))
        tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))
        # After 2 voice bursts on TS1, TS1 seq should be 3 (HEAD + 2 voices)
        # TS2 seq should be 1 (HEAD only)
        self.assertEqual(tr._in_rtp_seq[1], 3)
        self.assertEqual(tr._in_rtp_seq[2], 1)

    def test_rtp_ts_tracked_per_ts(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))
        tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))
        # TS1: 2 packets at 480/packet = 960 total
        self.assertEqual(tr._in_rtp_ts[1], 960)
        # TS2: 1 packet = 480 total
        self.assertEqual(tr._in_rtp_ts[2], 480)


# ===========================================================================
# 3. Mixed directions: simultaneous calls in different directions / timeslots
# ===========================================================================

class TestMixedDirections(unittest.TestCase):
    """Cross-direction, cross-timeslot combinations."""

    def test_out_ts1_and_in_ts2_simultaneously(self):
        """IPSC→HBP on TS1 while HBP→IPSC on TS2 — both active at once."""
        tr, ipsc, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.hbp_voice_received(_dmrd_head(ts=2))
        self.assertIsNotNone(tr._out_stream_id[1], 'outbound TS1 active')
        self.assertIsNone(tr._out_stream_id[2],    'outbound TS2 inactive')
        self.assertIsNone(tr._in_lc[1],            'inbound TS1 inactive')
        self.assertIsNotNone(tr._in_lc[2],         'inbound TS2 active')

    def test_out_ts2_and_in_ts1_simultaneously(self):
        """IPSC→HBP on TS2 while HBP→IPSC on TS1."""
        tr, ipsc, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        tr.hbp_voice_received(_dmrd_head(ts=1))
        self.assertIsNotNone(tr._out_stream_id[2])
        self.assertIsNone(tr._out_stream_id[1])
        self.assertIsNotNone(tr._in_lc[1])
        self.assertIsNone(tr._in_lc[2])

    def test_all_four_streams_simultaneously(self):
        """IPSC→HBP on TS1+TS2 and HBP→IPSC on TS1+TS2 all at once."""
        tr, ipsc, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))
        self.assertIsNotNone(tr._out_stream_id[1])
        self.assertIsNotNone(tr._out_stream_id[2])
        self.assertIsNotNone(tr._in_lc[1])
        self.assertIsNotNone(tr._in_lc[2])

    def test_all_four_streams_terminate_independently(self):
        """Each of the 4 streams can close without affecting the others."""
        tr, ipsc, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))

        # Close outbound TS1 — other 3 streams unaffected
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_TERM), ts=1, burst_type=VOICE_TERM)
        self.assertIsNone(tr._out_stream_id[1])
        self.assertIsNotNone(tr._out_stream_id[2])
        self.assertIsNotNone(tr._in_lc[1])
        self.assertIsNotNone(tr._in_lc[2])

        # Close inbound TS2 — outbound TS2 and inbound TS1 unaffected
        tr.hbp_voice_received(_dmrd_term(ts=2))
        self.assertIsNone(tr._in_lc[2])
        self.assertIsNotNone(tr._out_stream_id[2])
        self.assertIsNotNone(tr._in_lc[1])

    def test_out_ts1_voice_reaches_hbp_while_in_ts2_active(self):
        """Outbound voice bursts are forwarded even while inbound call is live."""
        tr, ipsc, hbp = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.hbp_voice_received(_dmrd_head(ts=2))
        hbp.sent.clear()
        ipsc.sent.clear()
        tr.ipsc_voice_received(_ipsc_gv(1, SLOT1_VOICE), ts=1, burst_type=SLOT1_VOICE)
        tr.hbp_voice_received(_dmrd_voice(ts=2, voice_seq=0))
        self.assertEqual(len(hbp.sent),  1, 'IPSC→HBP burst should reach HBP')
        self.assertEqual(len(ipsc.sent), 1, 'HBP→IPSC burst should reach IPSC')


# ===========================================================================
# 4. Outbound (IPSC→HBP) call timeout
# ===========================================================================

class TestOutboundCallTimeout(unittest.TestCase):
    """Hung outbound stream (no VOICE_TERM) is cleared by the watchdog."""

    def test_ts1_stream_cleared_after_silence(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 1000.0
            tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
            self.assertIsNotNone(tr._out_stream_id[1])

            mock_time.return_value = 1011.0   # 11 s later — beyond 10 s threshold
            tr.check_call_timeouts()

        self.assertIsNone(tr._out_stream_id[1], 'TS1 stream should be cleared')
        self.assertIsNone(tr._out_lc[1])
        self.assertIsNone(tr._out_emb_lc[1])

    def test_ts2_stream_cleared_after_silence(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 1000.0
            tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
            self.assertIsNotNone(tr._out_stream_id[2])

            mock_time.return_value = 1011.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._out_stream_id[2], 'TS2 stream should be cleared')

    def test_no_timeout_with_recent_activity(self):
        """Stream should NOT time out if packets arrived within the threshold."""
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 1000.0
            tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD),  ts=1, burst_type=VOICE_HEAD)
            mock_time.return_value = 1005.0
            tr.ipsc_voice_received(_ipsc_gv(1, SLOT1_VOICE), ts=1, burst_type=SLOT1_VOICE)
            mock_time.return_value = 1008.0   # only 3 s since last packet
            tr.check_call_timeouts()

        self.assertIsNotNone(tr._out_stream_id[1],
                             'Stream should survive — last packet was recent')

    def test_ts1_timeout_does_not_affect_ts2(self):
        """Only the silent TS times out; the active one is unaffected."""
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 1000.0
            tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
            tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)

            # Keep TS2 alive; let TS1 go silent
            mock_time.return_value = 1005.0
            tr.ipsc_voice_received(_ipsc_gv(2, SLOT2_VOICE), ts=2, burst_type=SLOT2_VOICE)

            mock_time.return_value = 1012.0   # TS1 silent 12 s; TS2 last packet 7 s ago
            tr.check_call_timeouts()

        self.assertIsNone(tr._out_stream_id[1],    'TS1 should time out')
        self.assertIsNotNone(tr._out_stream_id[2], 'TS2 should still be active')

    def test_ts2_timeout_does_not_affect_ts1(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 1000.0
            tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
            tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)

            mock_time.return_value = 1005.0
            tr.ipsc_voice_received(_ipsc_gv(1, SLOT1_VOICE), ts=1, burst_type=SLOT1_VOICE)

            mock_time.return_value = 1012.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._out_stream_id[2],    'TS2 should time out')
        self.assertIsNotNone(tr._out_stream_id[1], 'TS1 should still be active')

    def test_exact_threshold_does_not_trigger(self):
        """Exactly at threshold (elapsed == timeout) must not fire."""
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 1000.0
            tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
            mock_time.return_value = 1010.0   # exactly 10.0 s — not strictly > 10
            tr.check_call_timeouts()

        self.assertIsNotNone(tr._out_stream_id[1],
                             'Exactly at threshold should not trigger timeout')

    def test_no_crash_when_no_active_streams(self):
        """check_call_timeouts() on an idle translator must not raise."""
        tr, _, _ = _make_tr()
        tr.check_call_timeouts()   # no exception expected

    def test_normal_term_still_works_after_timeout_logic_added(self):
        """A properly-terminated call still clears stream ID the normal way."""
        tr, _, _ = _make_tr()
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_TERM), ts=1, burst_type=VOICE_TERM)
        self.assertIsNone(tr._out_stream_id[1])
        tr.check_call_timeouts()   # should be a no-op; nothing to time out


# ===========================================================================
# 5. Inbound (HBP→IPSC) call timeout
# ===========================================================================

class TestInboundCallTimeout(unittest.TestCase):
    """Hung inbound stream (no VOICE_LC_TERM) is cleared by the watchdog."""

    def test_ts1_lc_cleared_after_silence(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 2000.0
            tr.hbp_voice_received(_dmrd_head(ts=1))
            self.assertIsNotNone(tr._in_lc[1])

            mock_time.return_value = 2011.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._in_lc[1],     'TS1 inbound LC should be cleared')
        self.assertIsNone(tr._in_emb_lc[1])

    def test_ts2_lc_cleared_after_silence(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 2000.0
            tr.hbp_voice_received(_dmrd_head(ts=2))

            mock_time.return_value = 2011.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._in_lc[2], 'TS2 inbound LC should be cleared')

    def test_no_timeout_with_recent_inbound_activity(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 2000.0
            tr.hbp_voice_received(_dmrd_head(ts=1))
            mock_time.return_value = 2005.0
            tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))
            mock_time.return_value = 2008.0
            tr.check_call_timeouts()

        self.assertIsNotNone(tr._in_lc[1], 'Active stream should not time out')

    def test_ts1_timeout_does_not_affect_ts2_inbound(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 2000.0
            tr.hbp_voice_received(_dmrd_head(ts=1))
            tr.hbp_voice_received(_dmrd_head(ts=2))

            mock_time.return_value = 2006.0
            tr.hbp_voice_received(_dmrd_voice(ts=2, voice_seq=0))

            mock_time.return_value = 2013.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._in_lc[1],    'TS1 should time out')
        self.assertIsNotNone(tr._in_lc[2], 'TS2 should still be active')

    def test_ts2_timeout_does_not_affect_ts1_inbound(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 2000.0
            tr.hbp_voice_received(_dmrd_head(ts=1))
            tr.hbp_voice_received(_dmrd_head(ts=2))

            mock_time.return_value = 2006.0
            tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))

            mock_time.return_value = 2013.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._in_lc[2],    'TS2 should time out')
        self.assertIsNotNone(tr._in_lc[1], 'TS1 should still be active')

    def test_exact_threshold_does_not_trigger_inbound(self):
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 2000.0
            tr.hbp_voice_received(_dmrd_head(ts=1))
            mock_time.return_value = 2010.0
            tr.check_call_timeouts()

        self.assertIsNotNone(tr._in_lc[1],
                             'Exactly at threshold should not trigger timeout')

    def test_normal_term_still_works_inbound(self):
        tr, _, _ = _make_tr()
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_term(ts=1))
        self.assertIsNone(tr._in_lc[1])
        tr.check_call_timeouts()   # no-op; should not raise


# ===========================================================================
# 6. Cross-direction timeout independence
# ===========================================================================

class TestCrossDirectionTimeout(unittest.TestCase):
    """Timeout in one direction/TS does not disturb other direction/TS."""

    def test_out_ts1_timeout_leaves_in_ts1_intact(self):
        """Outbound TS1 times out; inbound TS1 is a separate stream and survives."""
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 3000.0
            tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
            tr.hbp_voice_received(_dmrd_head(ts=1))

            mock_time.return_value = 3006.0
            tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))   # keep inbound alive

            mock_time.return_value = 3013.0   # outbound silent 13 s; inbound 7 s ago
            tr.check_call_timeouts()

        self.assertIsNone(tr._out_stream_id[1], 'outbound TS1 timed out')
        self.assertIsNotNone(tr._in_lc[1],      'inbound TS1 unaffected')

    def test_in_ts2_timeout_leaves_out_ts2_intact(self):
        """Inbound TS2 times out; outbound TS2 is a separate stream and survives."""
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 3000.0
            tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
            tr.hbp_voice_received(_dmrd_head(ts=2))

            mock_time.return_value = 3006.0
            tr.ipsc_voice_received(_ipsc_gv(2, SLOT2_VOICE), ts=2, burst_type=SLOT2_VOICE)

            mock_time.return_value = 3013.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._in_lc[2],            'inbound TS2 timed out')
        self.assertIsNotNone(tr._out_stream_id[2], 'outbound TS2 unaffected')

    def test_all_four_streams_can_timeout_independently(self):
        """Start all 4 streams; stagger their last activity; verify each times out
        in the right order without cascading to the others."""
        tr, _, _ = _make_tr()
        with patch('translate.translator.time') as mock_time:
            mock_time.return_value = 4000.0
            tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
            tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
            tr.hbp_voice_received(_dmrd_head(ts=1))
            tr.hbp_voice_received(_dmrd_head(ts=2))

            # Stagger refreshes: out-ts2 and in-ts1 get a mid-point refresh
            mock_time.return_value = 4005.0
            tr.ipsc_voice_received(_ipsc_gv(2, SLOT2_VOICE), ts=2, burst_type=SLOT2_VOICE)
            tr.hbp_voice_received(_dmrd_voice(ts=1, voice_seq=0))

            # At t=4012: out-ts1 and in-ts2 have been silent 12 s → time out
            #             out-ts2 and in-ts1 have been silent 7 s  → survive
            mock_time.return_value = 4012.0
            tr.check_call_timeouts()

        self.assertIsNone(tr._out_stream_id[1],    'out-TS1 timed out (12 s)')
        self.assertIsNotNone(tr._out_stream_id[2], 'out-TS2 active (7 s)')
        self.assertIsNone(tr._in_lc[2],            'in-TS2 timed out (12 s)')
        self.assertIsNotNone(tr._in_lc[1],         'in-TS1 active (7 s)')


# ===========================================================================
# 7. State reset on peer_lost() and hbp_disconnected()
# ===========================================================================

class TestStateReset(unittest.TestCase):
    """peer_lost() and hbp_disconnected() clear all per-TS state."""

    def _start_all_streams(self, tr):
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        tr.ipsc_voice_received(_ipsc_gv(2, VOICE_HEAD), ts=2, burst_type=VOICE_HEAD)
        tr.hbp_voice_received(_dmrd_head(ts=1))
        tr.hbp_voice_received(_dmrd_head(ts=2))

    def test_peer_lost_clears_outbound_both_ts(self):
        tr, _, _ = _make_tr()
        self._start_all_streams(tr)
        tr.peer_lost()
        self.assertIsNone(tr._out_stream_id[1])
        self.assertIsNone(tr._out_stream_id[2])
        self.assertIsNone(tr._out_lc[1])
        self.assertIsNone(tr._out_lc[2])
        self.assertIsNone(tr._out_emb_lc[1])
        self.assertIsNone(tr._out_emb_lc[2])

    def test_peer_lost_clears_inbound_both_ts(self):
        tr, _, _ = _make_tr()
        self._start_all_streams(tr)
        tr.peer_lost()
        self.assertIsNone(tr._in_lc[1])
        self.assertIsNone(tr._in_lc[2])
        self.assertIsNone(tr._in_emb_lc[1])
        self.assertIsNone(tr._in_emb_lc[2])

    def test_peer_lost_resets_timestamps(self):
        tr, _, _ = _make_tr()
        self._start_all_streams(tr)
        tr.peer_lost()
        self.assertEqual(tr._out_last_pkt[1], 0.0)
        self.assertEqual(tr._out_last_pkt[2], 0.0)
        self.assertEqual(tr._in_last_pkt[1],  0.0)
        self.assertEqual(tr._in_last_pkt[2],  0.0)

    def test_hbp_disconnected_clears_outbound_both_ts(self):
        tr, _, _ = _make_tr()
        self._start_all_streams(tr)
        tr.hbp_disconnected()
        self.assertIsNone(tr._out_stream_id[1])
        self.assertIsNone(tr._out_stream_id[2])

    def test_hbp_disconnected_clears_inbound_both_ts(self):
        tr, _, _ = _make_tr()
        self._start_all_streams(tr)
        tr.hbp_disconnected()
        self.assertIsNone(tr._in_lc[1])
        self.assertIsNone(tr._in_lc[2])

    def test_hbp_disconnected_resets_timestamps(self):
        tr, _, _ = _make_tr()
        self._start_all_streams(tr)
        tr.hbp_disconnected()
        self.assertEqual(tr._out_last_pkt[1], 0.0)
        self.assertEqual(tr._out_last_pkt[2], 0.0)
        self.assertEqual(tr._in_last_pkt[1],  0.0)
        self.assertEqual(tr._in_last_pkt[2],  0.0)

    def test_no_timeout_after_peer_lost(self):
        """After peer_lost(), all streams are gone — timeout checker is a no-op."""
        tr, _, _ = _make_tr()
        self._start_all_streams(tr)
        tr.peer_lost()
        tr.check_call_timeouts()   # must not raise or misfire

    def test_new_call_accepted_after_peer_lost(self):
        """After peer_lost() + new registration, calls can start fresh."""
        tr, ipsc, hbp = _make_tr()
        self._start_all_streams(tr)
        tr.peer_lost()
        # Simulate re-registration — translator now accepts new calls
        tr.ipsc_voice_received(_ipsc_gv(1, VOICE_HEAD), ts=1, burst_type=VOICE_HEAD)
        self.assertIsNotNone(tr._out_stream_id[1], 'New call should start cleanly')


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == '__main__':
    unittest.main(verbosity=2)
