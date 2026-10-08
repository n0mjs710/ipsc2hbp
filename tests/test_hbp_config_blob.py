#!/usr/bin/env python
#
# The RPTC config blob and the RPTO options string as they go on the wire:
# field widths, and the three padding conventions taken from DMRGateway's
# config-blob sprintf. NUL fill is the failure these pin against -- it connects
# (the blob is sliced positionally) but leaves NULs in fields consumers read as
# text, where str.strip() does not remove them.
#
# Run from the repo root:   venv/bin/python -m unittest discover -s tests

import dataclasses
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, _HERE)

from config import load as load_config
from hbp.const import (
    HBPF_RPTC, HBPF_RPTO, RPTC_LEN,
    RPTC_CALLSIGN, RPTC_RX_FREQ, RPTC_TX_POWER, RPTC_COLORCODE,
    RPTC_LATITUDE, RPTC_LONGITUDE, RPTC_HEIGHT, RPTC_LOCATION, RPTC_PACKAGE_ID,
)
from hbp.protocol import _build_rptc


def _cfg():
    return load_config(os.path.join(_HERE, 'test.toml'))


class TestRPTCBlob(unittest.TestCase):
    def setUp(self):
        self.cfg = _cfg()
        self.blob = _build_rptc(self.cfg)

    def test_length_and_magic(self):
        self.assertEqual(len(self.blob), RPTC_LEN)
        self.assertEqual(self.blob[:4], HBPF_RPTC)

    def test_no_nul_anywhere_in_the_blob(self):
        # The 4-byte radio ID is binary and legitimately contains NUL; every
        # byte after it is ASCII text.
        self.assertNotIn(0, self.blob[8:])

    def test_numeric_fields_are_zero_filled_on_the_left(self):
        # "%02u"/"%03d": colour code 1 is "01", height 10 is "010".
        # test.toml carries tx_power "25", colorcode "1", height "10".
        self.assertEqual(self.blob[RPTC_TX_POWER], b'25')
        self.assertEqual(self.blob[RPTC_COLORCODE], b'01')
        self.assertEqual(self.blob[RPTC_HEIGHT], b'010')

    def test_lat_long_are_space_filled_on_the_left(self):
        # "%8.8s"/"%9.9s" right-justify; visible only on a value shorter than
        # the field, as DMRGateway's "%08f"/"%09f" output always fills it.
        self.assertEqual(self.blob[RPTC_LATITUDE], b' 38.8500')
        self.assertEqual(self.blob[RPTC_LONGITUDE], b'-097.6114')

    def test_short_fields_are_space_padded(self):
        self.assertEqual(self.blob[RPTC_CALLSIGN], b'W1ABC   ')
        self.assertEqual(self.blob[RPTC_LOCATION], b'Test' + b' ' * 16)
        self.assertEqual(self.blob[RPTC_PACKAGE_ID], b'duplex' + b' ' * 34)

    def test_exact_width_fields_are_untouched(self):
        self.assertEqual(self.blob[RPTC_RX_FREQ], b'444000000')

    def test_padded_numeric_field_parses_after_a_plain_strip(self):
        # What a master actually does with the field it sliced out.
        self.assertEqual(float(self.blob[RPTC_LATITUDE].decode().strip()), 38.85)

    def test_blob_matches_dmrgateway_format_string(self):
        # DMRGateway.cpp's format string verbatim. Python's % implements these
        # conversions as C's printf does, pinning every field in one assertion.
        cfg = self.cfg
        expected = (
            "%-8.8s%09u%09u%02u%02u%8.8s%9.9s%03d%-20.20s%-19.19s%c"
            "%-124.124s%-40.40s%-40.40s" % (
                cfg.callsign, int(cfg.rx_freq), int(cfg.tx_freq),
                int(cfg.tx_power), int(cfg.colorcode), cfg.latitude,
                cfg.longitude, int(cfg.height), cfg.location, cfg.description,
                '3', cfg.url, cfg.software_id, cfg.package_id,
            )
        ).encode()
        self.assertEqual(self.blob[8:], expected)
        self.assertEqual(len(expected), RPTC_LEN - 8)

    def test_overlong_field_is_truncated_not_overrun(self):
        cfg = dataclasses.replace(_cfg(), callsign='WAYTOOLONGCALLSIGN')
        blob = _build_rptc(cfg)
        self.assertEqual(len(blob), RPTC_LEN)
        self.assertEqual(blob[RPTC_CALLSIGN], b'WAYTOOLO')


class TestRPTOOptions(unittest.TestCase):
    # Mirrors the construction inlined in the RPTACK handler, pinning the wire
    # shape without driving the handshake (test_resilience.py covers that).
    def _rpto(self, options):
        cfg = dataclasses.replace(_cfg(), options=options)
        return (HBPF_RPTO
                + cfg.hbp_repeater_id.to_bytes(4, 'big')
                + cfg.options.encode()[:300])

    def test_datagram_is_exactly_the_string_with_no_padding(self):
        pkt = self._rpto('TS1=2,9;TS2=3120')
        self.assertEqual(len(pkt), 8 + len('TS1=2,9;TS2=3120'))
        self.assertNotIn(0, pkt[8:])   # radio ID at [4:8] is binary; options are text
        self.assertEqual(pkt[8:], b'TS1=2,9;TS2=3120')

    def test_last_talkgroup_survives_an_int_conversion(self):
        # Padding this field would put the fill bytes on the final talkgroup.
        pkt = self._rpto('TS1=2,9;TS2=3120')
        last = pkt[8:].decode().split(';')[-1].split('=')[1].split(',')[-1]
        self.assertEqual(int(last), 3120)

    def test_overlong_options_are_truncated_to_the_field_width(self):
        pkt = self._rpto('TS1=' + ','.join(['3120'] * 100))
        self.assertEqual(len(pkt), 308)


if __name__ == '__main__':
    unittest.main()
