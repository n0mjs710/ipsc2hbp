#!/usr/bin/env python3
"""
Regression tests for the RF handling shared with the C port (ipsc2hbpc), using the
same captured fixtures:

  parity_in.txt          synthetic IPSC call (first frames used for bad-voice flags)
  parity_in_dmrd.txt     one TS1 HBP VOICE_HEAD + VOICE_TERM (55 bytes, byte 54 = 0)
  pvt_ipsc_in.txt        PVT_VOICE call 3120999 -> 3120101, TS1, from a MOTOTRBO repeater
  pvt_hbp_in.txt         HBP private-call DMRD 3120101 -> 3120999, TS1, from HBlink3
  lateentry_ipsc_in.txt  weak-signal group call 3120101 -> TG 2 (corrupt burst E LCs)
  synclost_ipsc_in.txt   weak-signal call where the repeater lost a burst (0x13)

Run with:
    cd /home/cort/ipsc2hbp && python -m pytest tests/test_rf_features.py -v
"""

import asyncio
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bitarray import bitarray
from dmr_utils3 import bptc

from config import load as load_config
from ipsc.const import SYNC_UNDETECT
from hbp.const import HBPF_FRAMETYPE_VOICESYNC
from translate.translator import CallTranslator

_DIR      = os.path.dirname(os.path.abspath(__file__))
_CFG_PATH = os.path.join(_DIR, 'test.toml')
_SILENCE  = bytes.fromhex('B9E881526173002A6B')   # MMDVMHost DMR_SILENCE_DATA


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
    def __init__(self):
        self.sent = []
    def has_peers(self):
        return True
    def send_voice(self, pkt):
        self.sent.append(bytes(pkt))


def _translator(cfg_path=_CFG_PATH):
    tr  = CallTranslator(load_config(cfg_path))
    ip  = _MockIPSC()
    hb  = _MockHBP()
    tr.set_protocols(ip, hb)
    return tr, ip, hb


def _ipsc_lines(name):
    """(ts, burst_type, raw) for each line of an IPSC fixture."""
    out = []
    with open(os.path.join(_DIR, name)) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3:
                out.append((int(parts[0]), int(parts[1]), bytes.fromhex(parts[2])))
    return out


def _hbp_lines(name):
    with open(os.path.join(_DIR, name)) as f:
        return [bytes.fromhex(l.strip()) for l in f if l.strip()]


def _id3(b):
    return int.from_bytes(b[:3], 'big')


def _dmrd_lc(dmrd):
    """LC carried in a DMRD voice header / terminator (BPTC full LC)."""
    fb = bitarray(endian='big')
    fb.frombytes(dmrd[20:53])
    return bptc.decode_full_lc(fb[0:98] + fb[166:264]).tobytes()


def _run_hbp(tr, packets, settle=0.1):
    """Feed HBP DMRD packets inside a running loop so the delivery clock fires."""
    async def go():
        for pkt in packets:
            tr.hbp_voice_received(pkt)
        await asyncio.sleep(settle)
    asyncio.run(go())


class TestIpscToHbp(unittest.TestCase):

    def test_bad_voice_flags_become_mmdvm_silence(self):
        """AMBE frames the repeater flags uncorrectable go out as MMDVMHost silence."""
        want = [(1, 1, 1), (0, 1, 0)]   # per voice frame: flagged?
        tr, _, hb = _translator()
        for k, (ts, bt, raw) in enumerate(_ipsc_lines('parity_in.txt')[:3]):
            raw = bytearray(raw)
            if k >= 1:
                w = want[k - 1]
                if w[0]: raw[32] |= 0x01
                if w[1]: raw[33 + 49 // 8] |= 0x80 >> (49 % 8)
                if w[2]: raw[33 + 99 // 8] |= 0x80 >> (99 % 8)
            tr.ipsc_voice_received(bytes(raw), ts, bt)
        self.assertEqual(len(hb.sent), 3)
        sil = bitarray(endian='big')
        sil.frombytes(_SILENCE)
        for v in range(2):
            b = bitarray(endian='big')
            b.frombytes(hb.sent[v + 1][20:53])
            frames = (b[0:72], b[72:108] + b[156:192], b[192:264])
            for i in range(3):
                self.assertEqual(frames[i] == sil, bool(want[v][i]), f'voice {v} frame {i + 1}')

    def test_burst_a_resyncs_superframe(self):
        """After the repeater loses a burst, the next burst A restarts the superframe."""
        tr, _, hb = _translator()
        want_sync = []
        for ts, bt, raw in _ipsc_lines('synclost_ipsc_in.txt'):
            if (bt & 0x7F) == SYNC_UNDETECT:
                continue   # dropped by the IPSC protocol layer
            want_sync.append(None if bt in (1, 2) else bool(raw[32] & 0x40))
            tr.ipsc_voice_received(raw, ts, bt)
        self.assertEqual(len(hb.sent), len(want_sync))
        seen, expect_pos = 0, -1
        for d, ws in zip(hb.sent, want_sync):
            if ws is None:
                continue
            fl = d[15]
            is_sync = (fl & 0x30) == HBPF_FRAMETYPE_VOICESYNC
            if ws:
                seen += 1
                self.assertTrue(is_sync, f'burst A sent as flags 0x{fl:02x}')
                expect_pos = 1
            elif expect_pos > 0:
                self.assertFalse(is_sync)
                self.assertEqual(fl & 0x0F, expect_pos)
                expect_pos += 1
        self.assertEqual(seen, 7)

    def test_late_entry_skips_corrupt_burst_e_lc(self):
        """Late entry anchors on a burst E whose LC passed its check, not the first one.
        Joining at packet 4, burst E at packet 8 (ctrl 0x96) has a corrupt LC; anchor on
        packet 14.  Joining at packet 33, burst E at packet 38 (ctrl 0x17: voice frame bad,
        LC good) is usable.  The last case gives packet 8's corrupt LC a group FLCO, so only
        the LC-error bit can reject it."""
        lines = _ipsc_lines('lateentry_ipsc_in.txt')
        forged = list(lines)
        ts8, bt8, raw8 = forged[8]
        forged[8] = (ts8, bt8, raw8[:56] + b'\x00' + raw8[57:])
        for join, want_anchor, lines in ((4, 14, lines), (33, 38, lines), (4, 14, forged)):
            tr, _, hb = _translator()
            anchor = None
            for idx, (ts, bt, raw) in enumerate(lines):
                if idx < join or bt == 1 or (bt & 0x7F) == SYNC_UNDETECT:
                    continue
                before = len(hb.sent)
                tr.ipsc_voice_received(raw, ts, bt)
                if anchor is None and len(hb.sent) > before:
                    anchor = idx
            self.assertEqual(anchor, want_anchor, f'joined at {join}')
            for d in hb.sent:
                self.assertEqual((_id3(d[5:8]), _id3(d[8:11])), (3120101, 2))

    def test_rssi_from_voice_head_and_term(self):
        """Repeater RSSI goes out in DMRD byte 54 of head/term; 0 on voice bursts.
        pvt_ipsc_in.txt raw 40a7 40b8 40bd 40c2 (heads), 3f4e (term);
        lateentry_ipsc_in.txt raw 705d 6fff 70a2 70f0 (heads), no term."""
        cases = (('pvt_ipsc_in.txt', [65, 65, 65, 65, 63]),
                 ('lateentry_ipsc_in.txt', [112, 112, 113, 113]))
        for name, want in cases:
            tr, _, hb = _translator()
            for ts, bt, raw in _ipsc_lines(name):
                if (bt & 0x7F) != SYNC_UNDETECT:
                    tr.ipsc_voice_received(raw, ts, bt)
            got = [d[54] for d in hb.sent if (d[15] & 0x30) == 0x20]
            self.assertEqual(got, want, name)
            self.assertTrue(all(d[54] == 0 for d in hb.sent if (d[15] & 0x30) != 0x20), name)

    def test_private_call(self):
        """PVT_VOICE becomes private-call DMRD with a UU_V_Ch_Usr LC, full and late entry."""
        lines = _ipsc_lines('pvt_ipsc_in.txt')
        for late in (False, True):
            tr, _, hb = _translator()
            fed = 0
            for ts, bt, raw in lines:
                if late and bt == 1:
                    continue
                tr.ipsc_voice_received(raw, ts, bt)
                fed += 1
            self.assertTrue(hb.sent)
            hdr = term = 0
            for d in hb.sent:
                fl = d[15]
                self.assertTrue(fl & 0x40, 'private-call bit')
                self.assertFalse(fl & 0x80, 'TS1')
                self.assertEqual((_id3(d[5:8]), _id3(d[8:11])), (3120999, 3120101))
                if (fl & 0x30) == 0x20:
                    self.assertEqual(_dmrd_lc(d)[0] & 0x3F, 3)
                    hdr  += (fl & 0x0F) == 1
                    term += (fl & 0x0F) == 2
            self.assertEqual(term, 1)
            if late:
                self.assertEqual(hdr, 0)
            else:
                self.assertEqual((hdr, len(hb.sent)), (4, fed))


class TestHbpToIpsc(unittest.TestCase):

    def setUp(self):
        self.head, self.term = _hbp_lines('parity_in_dmrd.txt')
        self.assertEqual((len(self.head), len(self.term)), (55, 55))

    def test_private_call(self):
        """Private-call DMRD becomes PVT_VOICE with a UU_V_Ch_Usr LC, full and late entry."""
        pkts = [p for p in _hbp_lines('pvt_hbp_in.txt') if len(p) >= 55]
        for late in (False, True):
            tr, ip, _ = _translator()
            _run_hbp(tr, [p for p in pkts if not (late and (p[15] & 0x3F) == 0x21)], settle=0.5)
            self.assertTrue(ip.sent)
            term = 0
            for g in ip.sent:
                self.assertEqual(g[0], 0x81)
                self.assertEqual((_id3(g[6:9]), _id3(g[9:12])), (3120101, 3120999))
                if g[30] in (1, 2):
                    self.assertEqual(g[38] & 0x3F, 3)
                    term += g[30] == 2
            self.assertEqual(term, 1)

    def test_53_and_55_byte_dmrd_rssi_and_slot(self):
        """53- and 55-byte DMRD are both accepted; byte 54 of a voice header / terminator
        becomes the RSSI of the VOICE_HEAD / VOICE_TERM; byte 31 bit 7 follows the slot.
        Each HEAD/TERM fed back through the IPSC->HBP decoder returns the original byte 54."""
        for mags in ((0, 0), (60, 63), (85, 112), (113, 57), (255, 1)):
            for ts in (1, 2):
                for length in (53, 55):
                    tr, ip, hb = _translator()
                    pkts = []
                    for k, base in enumerate((self.head, self.term)):
                        d = bytearray(base)
                        if ts == 2:
                            d[15] |= 0x80
                        d[54] = mags[k]
                        pkts.append(bytes(d[:length]))
                    _run_hbp(tr, pkts)
                    self.assertEqual(len(ip.sent), 2)
                    for k, g in enumerate(ip.sent):
                        mag = mags[k] if length == 55 else 0
                        label = f'mags={mags} ts={ts} len={length} {"TERM" if k else "HEAD"}'
                        self.assertEqual(g[31], 0x80 if ts == 2 else 0x00, label)
                        self.assertEqual(g[34], 0x80, label)
                        self.assertEqual(int.from_bytes(g[52:54], 'big'), mag << 8, label)
                        tr.ipsc_voice_received(g, ts, g[30])
                        self.assertEqual(hb.sent[k][54], mag, label)
                        self.assertEqual(bool(hb.sent[k][15] & 0x80), ts == 2, label)

    def test_term_reading_does_not_carry_into_next_call(self):
        """A terminator's RSSI must not appear on the next call's synthesized TERM."""
        tr, ip, _ = _translator()
        term = bytearray(self.term)
        term[54] = 90
        head2 = bytearray(self.head)
        head2[16] ^= 0x0F
        burst = bytearray(head2)
        burst[15] = (burst[15] & 0xC0) | HBPF_FRAMETYPE_VOICESYNC
        _run_hbp(tr, [self.head, bytes(term), bytes(head2), bytes(burst)], settle=2.0)  # stream timeout 1.5 s
        self.assertGreaterEqual(len(ip.sent), 4)
        self.assertEqual(ip.sent[1][30], 0x02)
        self.assertEqual(int.from_bytes(ip.sent[1][52:54], 'big'), 90 << 8)
        self.assertEqual(ip.sent[-1][30], 0x02)
        self.assertEqual(ip.sent[-1][52:54], b'\x00\x00')


class TestConfig(unittest.TestCase):

    def test_retired_rssi_encoding_key_is_ignored(self):
        """A config still carrying the C port's retired [ipsc] rssi_encoding_new key loads."""
        with open(_CFG_PATH) as f:
            text = f.read()
        self.assertIn('[ipsc]\n', text)
        text = text.replace('[ipsc]\n', '[ipsc]\nrssi_encoding_new = false\n', 1)
        with tempfile.NamedTemporaryFile('w', suffix='.toml', delete=False) as f:
            f.write(text)
        try:
            tr, _, hb = _translator(f.name)
            for ts, bt, raw in _ipsc_lines('pvt_ipsc_in.txt'):
                tr.ipsc_voice_received(raw, ts, bt)
            self.assertEqual([d[54] for d in hb.sent if (d[15] & 0x30) == 0x20], [65, 65, 65, 65, 63])
        finally:
            os.unlink(f.name)


if __name__ == '__main__':
    unittest.main()
