"""
CallTranslator — bidirectional IPSC ↔ HBP translation.

Outbound (IPSC → HBP): ipsc_voice_received()
  VOICE_HEAD:       Build DMRD VOICE_LC_HEAD frame from BPTC-encoded LC.
  SLOT1/SLOT2_VOICE: Convert 3×49-bit AMBE from IPSC to 3×72-bit, assemble
                    264-bit DMR voice frame with proper EMBED/SYNC field.
  VOICE_TERM:       Build DMRD VOICE_LC_TERM frame from BPTC-encoded LC.

Inbound (HBP → IPSC): hbp_voice_received()
  VOICE_HEAD/TERM:  Reconstruct IPSC header/terminator packet with LC payload.
  VOICE/VOICESYNC:  Extract 3×72-bit AMBE from DMRD, convert to 3×49-bit,
                    pack into 19-byte IPSC AMBE format, send burst-type-specific payload.

AMBE layout in IPSC SLOT_VOICE (bytes 33–51, 19 bytes = 152 bits):
  bits[0:49]    = AMBE frame a (49 bits)
  bit[49]       = bad data bit for frame a (1 = AMBE decode error; always 0 on transmit)
  bits[50:99]   = AMBE frame b (49 bits)
  bit[99]       = bad data bit for frame b (always 0 on transmit)
  bits[100:149] = AMBE frame c (49 bits)
  bit[149]      = bad data bit for frame c (always 0 on transmit)
  bits[150:152] = pad (0)

DMR voice frame layout (264 bits = 33 bytes):
  frame_a[72] | frame_b_first[36] | EMBED[48] | frame_b_second[36] | frame_c[72]
  (frame b straddles the EMBED/SYNC field; reassembled by concatenating the two halves)

Superframe mapping (6-frame cycle, position resets on each VOICE_HEAD):
  position 0   → HBPF_FRAMETYPE_VOICESYNC, EMBED = BS_VOICE_SYNC
  position 1   → HBPF_FRAMETYPE_VOICE | 0, EMBED = BURST_B + EMB_LC[1]
  position 2   → HBPF_FRAMETYPE_VOICE | 1, EMBED = BURST_C + EMB_LC[2]
  position 3   → HBPF_FRAMETYPE_VOICE | 2, EMBED = BURST_D + EMB_LC[3]
  position 4   → HBPF_FRAMETYPE_VOICE | 3, EMBED = BURST_E + EMB_LC[4]
  position 5   → HBPF_FRAMETYPE_VOICE | 4, EMBED = BURST_F + NULL_EMB_LC
"""

import logging
import os
import struct
from time import time

from bitarray import bitarray

from dmr_utils3 import bptc
from dmr_utils3.ambe_utils import convert49BitTo72BitAMBE, convert72BitTo49BitAMBE
from dmr_utils3.const import EMB, SLOT_TYPE, BS_VOICE_SYNC, BS_DATA_SYNC, LC_OPT

from config import Config
from ipsc.const import (
    GROUP_VOICE,
    VOICE_HEAD, VOICE_TERM, SLOT1_VOICE, SLOT2_VOICE,
    TS_CALL_MSK, END_MSK,
    GV_SRC_SUB_OFF, GV_DST_GROUP_OFF,
)
from hbp.const import (
    HBPF_DMRD,
    HBPF_TGID_TS2,
    HBPF_FRAMETYPE_VOICE, HBPF_FRAMETYPE_VOICESYNC, HBPF_FRAMETYPE_DATASYNC,
    HBPF_FRAMETYPE_MASK, HBPF_DTYPE_MASK,
    HBPF_SLT_VHEAD, HBPF_SLT_VTERM,
    DMRD_LEN,
    DMRD_SRC_OFF, DMRD_DST_OFF,
    DMRD_FLAGS_OFF, DMRD_PAYLOAD_OFF,
)

log = logging.getLogger(__name__)

# 32-bit zero bitarray for voice frame F (null embedded LC)
_NULL_EMB_LC = bitarray(32, endian='big')
_NULL_EMB_LC.setall(0)

_EMB_BURST_NAMES = ('BURST_B', 'BURST_C', 'BURST_D', 'BURST_E', 'BURST_F')


def _ambe49_to_72(ba49: bitarray) -> bitarray:
    """Convert 49-bit raw AMBE to 72-bit interleaved, returning bitarray(72)."""
    raw = convert49BitTo72BitAMBE(ba49)
    out = bitarray(endian='big')
    out.frombytes(bytes(raw))
    return out


def _extract_ambe_from_dmrd(payload_33: bytes) -> bytes:
    """
    Extract 3×72-bit AMBE from a 33-byte DMR voice frame payload, convert each
    to 49-bit raw AMBE, and pack into the 19-byte IPSC AMBE format.
    """
    burst = bitarray(endian='big')
    burst.frombytes(payload_33)
    # DMR voice frame: AMBE1[0:72] | AMBE2_half1[72:108] | EMB[108:156] | AMBE2_half2[156:192] | AMBE3[192:264]
    a1_72 = burst[0:72]
    a2_72 = burst[72:108] + burst[156:192]
    a3_72 = burst[192:264]

    a1_49 = convert72BitTo49BitAMBE(a1_72)
    a2_49 = convert72BitTo49BitAMBE(a2_72)
    a3_49 = convert72BitTo49BitAMBE(a3_72)

    # IPSC 19-byte (152-bit) AMBE: [a1(49)] [0] [a2(49)] [0] [a3(49)] [000]
    ipsc_bits = bitarray(152, endian='big')
    ipsc_bits.setall(0)
    ipsc_bits[0:49]   = a1_49
    ipsc_bits[50:99]  = a2_49
    ipsc_bits[100:149] = a3_49
    return ipsc_bits.tobytes()


def _build_ipsc_voice_payload(lc: bytes, burst_type: int) -> bytes:
    """
    Build the MOTOTRBO-format payload bytes (after the burst_type byte) for
    VOICE_HEAD or VOICE_TERM.  Both produce 23-byte payloads → 54-byte total
    GROUP_VOICE packet (confirmed from voice_packets.txt and wire captures).

    Byte layout:
      byte 0:    RSSI_THRESH_PARITY     (0x80, confirmed from wire captures)
      bytes 1–2: length_to_follow       (10 words = (54-34)/2)
      byte 3:    RSSI status            (0x80)
      byte 4:    slot type / sync       (0x0a)
      bytes 5–6: data size in bits      (0x0060 = 96)
      bytes 7–15: LC word (9 bytes)
      bytes 16–18: RS(12,9) FEC (3 bytes, mask differs HEAD vs TERM)
      bytes 19–22: type indicator + zeros (0x00, 0x11 or 0x12, 0x00, 0x00)
    """
    if burst_type == VOICE_HEAD:
        fec      = bptc.rs129.lc_header_encode(lc[:9])
        type_tag = b'\x11'
    else:  # VOICE_TERM
        fec      = bptc.rs129.lc_terminator_encode(lc[:9])
        type_tag = b'\x12'
    return (
        b'\x80'                    # RSSI_THRESH_PARITY — 0x80 confirmed from wire captures
        + struct.pack('>H', 10)    # length_to_follow = 10 words
        + b'\x80'                  # RSSI status
        + b'\x0a'                  # slot type / sync
        + struct.pack('>H', 0x60)  # data size = 96 bits
        + lc[:9]                   # full LC word (FLCO + FID + opts + dst + src)
        + fec                      # RS(12,9) parity: 3 bytes
        + b'\x00' + type_tag + b'\x00\x00'   # 4 bytes: 0x00, 0x11/0x12, 0x00, 0x00
    )


class CallTranslator:
    """
    Wires IPSCProtocol and HBPClient together.

    Instantiate first, then pass to both protocol objects, then call
    set_protocols() so the translator can reach back into each stack.
    """

    def __init__(self, cfg: Config):
        self._cfg           = cfg
        self._ipsc          = None
        self._hbp           = None
        self._repeater_id_b = cfg.hbp_repeater_id.to_bytes(4, 'big')
        self._master_id_b   = cfg.ipsc_master_id.to_bytes(4, 'big')

        # Outbound call state (IPSC → HBP) — keyed by timeslot (1 or 2)
        self._out_stream_id = {1: None, 2: None}  # 4 random bytes, new per call
        self._out_seq       = 0                   # DMRD sequence byte, wraps at 256 (shared)
        self._out_frame_pos = {1: 0, 2: 0}        # superframe position (0–5, cycles)
        self._out_lc        = {1: None, 2: None}  # 9-byte LC for embedded LC generation
        self._out_emb_lc    = {1: None, 2: None}  # dict {1–4: bitarray(32)} embedded LC

        # Inbound call state (HBP → IPSC) — keyed by timeslot (1 or 2)
        self._in_lc         = {1: None, 2: None}  # 9-byte LC decoded from HBP VOICE_HEAD
        self._in_emb_lc     = {1: None, 2: None}  # dict {1–4: bitarray(32)} from bptc.encode_emblc
        self._in_stream_id  = {1: 0, 2: 0}        # byte 5: call stream ID, constant per call
        self._in_stream_ctr = 0                   # increments once per call (shared across TS)
        self._in_rtp_seq    = {1: 0, 2: 0}        # RTP sequence in GV header
        self._in_rtp_ts     = {1: 0, 2: 0}        # RTP timestamp; increments 480/frame

        # Last-packet timestamps for hung-call detection (seconds since epoch)
        self._out_last_pkt  = {1: 0.0, 2: 0.0}
        self._in_last_pkt   = {1: 0.0, 2: 0.0}

        # Call metadata learned from the IPSC peer and echoed back inbound
        self._peer_call_type = b'\x02'               # group voice (Motorola default)
        self._peer_call_ctrl = b'\x00\x00\x43\xe2'  # Motorola repeater default

    def set_protocols(self, ipsc_proto, hbp_client):
        self._ipsc = ipsc_proto
        self._hbp  = hbp_client

    # ------------------------------------------------------------------
    # IPSC callbacks
    # ------------------------------------------------------------------

    def peer_joined(self):
        if self._cfg.hbp_mode == 'TRACKING':
            self._hbp.activate()

    def peer_lost(self):
        log.warning('IPSC peer lost')
        self._out_stream_id  = {1: None, 2: None}
        self._out_lc         = {1: None, 2: None}
        self._out_emb_lc     = {1: None, 2: None}
        self._out_last_pkt   = {1: 0.0, 2: 0.0}
        self._in_lc          = {1: None, 2: None}
        self._in_emb_lc      = {1: None, 2: None}
        self._in_stream_id   = {1: 0, 2: 0}
        self._in_last_pkt    = {1: 0.0, 2: 0.0}
        self._peer_call_type = b'\x02'
        self._peer_call_ctrl = b'\x00\x00\x43\xe2'
        if self._cfg.hbp_mode == 'TRACKING':
            self._hbp.deactivate()

    def ipsc_voice_received(self, data: bytes, ts: int, burst_type: int):
        if not self._hbp.is_connected():
            return
        self._out_last_pkt[ts] = time()

        src_sub   = data[GV_SRC_SUB_OFF   : GV_SRC_SUB_OFF   + 3]
        dst_group = data[GV_DST_GROUP_OFF  : GV_DST_GROUP_OFF + 3]
        flags     = HBPF_TGID_TS2 if ts == 2 else 0x00

        # Learn call metadata so we echo the same values back inbound
        if len(data) >= 17:
            self._peer_call_type = data[12:13]
            self._peer_call_ctrl = data[13:17]

        if burst_type == VOICE_HEAD:
            if self._out_stream_id[ts] is None:
                self._out_stream_id[ts] = os.urandom(4)
                log.info('IPSC call start: src=%d  tg=%d  ts=%d  stream=%s',
                         int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'),
                         ts, self._out_stream_id[ts].hex())
            else:
                # Motorola radios fire VOICE_HEAD twice at call start — once on LC
                # detection, once confirmed. MMDVMHost absorbs this at the driver
                # layer; we see it raw over IPSC. Reuse the existing stream_id so
                # HBlink doesn't flag stream contention.
                log.debug('Duplicate VOICE_HEAD ts=%d — keeping stream=%s',
                          ts, self._out_stream_id[ts].hex())
            self._out_frame_pos[ts] = 0
            lc = LC_OPT + dst_group + src_sub
            self._out_lc[ts]     = lc
            self._out_emb_lc[ts] = bptc.encode_emblc(lc)
            full_lc = bptc.encode_header_lc(lc)
            frame_bits = (
                full_lc[0:98]
                + SLOT_TYPE['VOICE_LC_HEAD'][:10]
                + BS_DATA_SYNC
                + SLOT_TYPE['VOICE_LC_HEAD'][-10:]
                + full_lc[98:]
            )
            payload_33 = frame_bits.tobytes()
            flags |= HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VHEAD

        elif burst_type == VOICE_TERM:
            if self._out_stream_id[ts] is None:
                return
            lc = self._out_lc[ts] if self._out_lc[ts] else LC_OPT + dst_group + src_sub
            full_lc = bptc.encode_terminator_lc(lc)
            frame_bits = (
                full_lc[0:98]
                + SLOT_TYPE['VOICE_LC_TERM'][:10]
                + BS_DATA_SYNC
                + SLOT_TYPE['VOICE_LC_TERM'][-10:]
                + full_lc[98:]
            )
            payload_33 = frame_bits.tobytes()
            flags |= HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VTERM

        else:  # SLOT1_VOICE or SLOT2_VOICE
            if self._out_stream_id[ts] is None:
                return
            if len(data) < 52:
                log.warning('SLOT_VOICE too short for AMBE: %d bytes', len(data))
                return

            # Extract 3×49-bit AMBE from IPSC bytes 33–51
            raw_ba = bitarray(endian='big')
            raw_ba.frombytes(data[33:52])
            a1_72 = _ambe49_to_72(raw_ba[0:49])
            a2_72 = _ambe49_to_72(raw_ba[50:99])
            a3_72 = _ambe49_to_72(raw_ba[100:149])

            pos   = self._out_frame_pos[ts] % 6
            embed = self._build_embed(pos, self._out_emb_lc[ts])
            frame_bits = a1_72 + a2_72[:36] + embed + a2_72[36:] + a3_72
            payload_33 = frame_bits.tobytes()
            flags |= HBPF_FRAMETYPE_VOICESYNC if pos == 0 else (HBPF_FRAMETYPE_VOICE | pos)
            self._out_frame_pos[ts] += 1

        dmrd = (
            HBPF_DMRD
            + bytes([self._out_seq])
            + src_sub
            + dst_group
            + self._repeater_id_b
            + bytes([flags])
            + self._out_stream_id[ts]
            + payload_33
            + b'\x00\x00'   # BER + RSSI (synthesised, no RF measurement)
        )
        self._out_seq = (self._out_seq + 1) & 0xFF
        self._hbp.send_dmrd(dmrd)
        log.debug('→ HBP DMRD  burst=0x%02x  ts=%d  flags=0x%02x', burst_type, ts, flags)

        if burst_type == VOICE_TERM:
            log.info('IPSC call end:   src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
            self._out_stream_id[ts] = None
            self._out_lc[ts]        = None
            self._out_emb_lc[ts]    = None

    def _build_embed(self, pos: int, emb_lc) -> bitarray:
        """Build the 48-bit EMBED field for superframe position 0–5."""
        if pos == 0:
            return BS_VOICE_SYNC
        name    = _EMB_BURST_NAMES[pos - 1]
        lc_bits = emb_lc.get(pos, _NULL_EMB_LC) if emb_lc and pos <= 4 else _NULL_EMB_LC
        return EMB[name][:8] + lc_bits + EMB[name][-8:]

    # ------------------------------------------------------------------
    # HBP callbacks
    # ------------------------------------------------------------------

    def hbp_connected(self):
        log.info('HBP connected')

    def hbp_disconnected(self):
        log.warning('HBP disconnected')
        self._out_stream_id = {1: None, 2: None}
        self._out_lc        = {1: None, 2: None}
        self._out_emb_lc    = {1: None, 2: None}
        self._out_last_pkt  = {1: 0.0, 2: 0.0}
        self._in_lc         = {1: None, 2: None}
        self._in_emb_lc     = {1: None, 2: None}
        self._in_stream_id  = {1: 0, 2: 0}
        self._in_last_pkt   = {1: 0.0, 2: 0.0}

    def hbp_voice_received(self, dmrd: bytes):
        """Inbound HBP → IPSC."""
        if not self._ipsc.has_peers():
            return
        if len(dmrd) < DMRD_LEN:
            return

        src_sub    = dmrd[DMRD_SRC_OFF  : DMRD_SRC_OFF  + 3]
        dst_group  = dmrd[DMRD_DST_OFF  : DMRD_DST_OFF  + 3]
        flags      = dmrd[DMRD_FLAGS_OFF]
        payload_33 = dmrd[DMRD_PAYLOAD_OFF : DMRD_PAYLOAD_OFF + 33]

        ts         = 2 if (flags & HBPF_TGID_TS2) else 1
        self._in_last_pkt[ts] = time()
        frame_type = flags & HBPF_FRAMETYPE_MASK
        dtype      = flags & HBPF_DTYPE_MASK
        call_info  = TS_CALL_MSK if ts == 2 else 0x00
        slot_burst = SLOT2_VOICE if ts == 2 else SLOT1_VOICE

        if frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VHEAD:
            # Decode actual LC from the BPTC-encoded DMRD VOICE_HEAD payload.
            # encode_header_lc / decode_full_lc both operate on the 196-bit BPTC
            # codeword, NOT the 264-bit full DMR frame.  The full frame has 10 slot-type
            # bits at [98:108] and 48 sync bits at [108:156] inserted in the middle, so
            # the BPTC second half lives at frame[166:264], not frame[98:196].
            frame_bits = bitarray(endian='big')
            frame_bits.frombytes(payload_33)
            bptc_bits = frame_bits[0:98] + frame_bits[166:264]   # 196-bit BPTC only
            lc = bptc.decode_full_lc(bptc_bits).tobytes()
            self._in_lc[ts]     = lc
            self._in_emb_lc[ts] = bptc.encode_emblc(lc)
            # Assign a new stream ID for this call — byte 5 in GROUP_VOICE is a
            # per-call constant (stream identifier), not a per-packet counter.
            # Real Motorola equipment uses the same value for every packet of a call.
            self._in_stream_ctr    = (self._in_stream_ctr + 1) & 0xFF
            self._in_stream_id[ts] = self._in_stream_ctr
            gv_payload = bytes([VOICE_HEAD]) + _build_ipsc_voice_payload(lc, VOICE_HEAD)
            rtp_pt = 0xdd  # M=1 (call-start marker)

        elif frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VTERM:
            lc = self._in_lc[ts] if self._in_lc[ts] else LC_OPT + dst_group + src_sub
            call_info |= END_MSK
            gv_payload = bytes([VOICE_TERM]) + _build_ipsc_voice_payload(lc, VOICE_TERM)
            rtp_pt = 0x5e

        else:  # VOICESYNC (burst A) or VOICE (bursts B-F)
            ambe_19 = _extract_ambe_from_dmrd(payload_33)

            if frame_type == HBPF_FRAMETYPE_VOICESYNC:
                # Burst A: 52 bytes total.  byte31=0x14 (len=20), byte32=0x40 (???)
                gv_payload = bytes([slot_burst]) + b'\x14\x40' + ambe_19

            elif dtype == 4:
                # Burst E (HBLink4 dtype=4): 66 bytes total.  byte31=0x22 (len=34), byte32=0x16
                # bytes 52-55: embedded LC fragment 4 from encode_emblc
                # bytes 56-58: LC[0:3]  (FLCO, FID, SVC_OPT)
                # bytes 59-61: dst_group
                # bytes 62-64: src_sub
                # byte  65:    0x14 (constant)
                emb_frag = (self._in_emb_lc[ts][4].tobytes()
                            if self._in_emb_lc[ts] and 4 in self._in_emb_lc[ts]
                            else _NULL_EMB_LC.tobytes())
                lc_prefix = self._in_lc[ts][0:3] if self._in_lc[ts] else b'\x00\x00\x00'
                gv_payload = (bytes([slot_burst]) + b'\x22\x16' + ambe_19
                              + emb_frag + lc_prefix + dst_group + src_sub + b'\x14')

            elif dtype >= 5:
                # Burst F (HBLink4 dtype=5): null embedded LC, 57 bytes.
                # byte  56:    0x10  (EMB header for BURST_F = 0x11, & 0xFE = 0x10)
                gv_payload = bytes([slot_burst]) + b'\x19\x06' + ambe_19 + b'\x00\x00\x00\x00\x10'

            else:
                # Bursts B/C/D (HBLink4 dtype=1/2/3; dtype=0 handled as B for compatibility).
                # 57 bytes total.  byte31=0x19 (len=25), byte32=0x06
                # bytes 52-55: embedded LC fragment at encode_emblc position 1/2/3
                # byte  56:    EMB header byte for this burst position, masked & 0xFE
                pos      = max(dtype, 1)          # encode_emblc positions: 1=B, 2=C, 3=D
                emb_frag = (self._in_emb_lc[ts][pos].tobytes()
                            if self._in_emb_lc[ts] and pos in self._in_emb_lc[ts]
                            else _NULL_EMB_LC.tobytes())
                emb_hdr  = EMB[_EMB_BURST_NAMES[pos - 1]][:8].tobytes()[0] & 0xFE
                gv_payload = (bytes([slot_burst]) + b'\x19\x06' + ambe_19
                              + emb_frag + bytes([emb_hdr]))

            rtp_pt = 0x5d

        rtp_seq_b = struct.pack('>H', self._in_rtp_seq[ts] & 0xFFFF)
        rtp_ts_b  = struct.pack('>I', self._in_rtp_ts[ts]  & 0xFFFFFFFF)
        self._in_rtp_seq[ts] += 1
        self._in_rtp_ts[ts]  += 480
        rtp_hdr = b'\x80' + bytes([rtp_pt]) + rtp_seq_b + rtp_ts_b + b'\x00\x00\x00\x00'
        self._ipsc.send_voice(
            self._build_gv(src_sub, dst_group, call_info, rtp_hdr, gv_payload, self._in_stream_id[ts])
        )

        if frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VHEAD:
            log.info('HBP call start: src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
        elif frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VTERM:
            log.info('HBP call end:   src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
            self._in_lc[ts]     = None
            self._in_emb_lc[ts] = None
        else:
            log.debug('← IPSC GV  burst=0x%02x  ts=%d  dtype=%d', slot_burst, ts, dtype)

    def _build_gv(self, src_sub, dst_group, call_info, rtp_hdr, gv_payload, stream_id: int) -> bytes:
        """Assemble a complete GROUP_VOICE packet."""
        return (
            bytes([GROUP_VOICE])
            + self._master_id_b
            + bytes([stream_id])   # call stream ID — constant for the entire call
            + src_sub
            + dst_group
            + self._peer_call_type
            + self._peer_call_ctrl
            + bytes([call_info])
            + rtp_hdr
            + gv_payload
        )

    # ------------------------------------------------------------------
    # Watchdog support
    # ------------------------------------------------------------------

    def check_call_timeouts(self, timeout: float = 10.0):
        """
        Called by the IPSC watchdog every 5 s.  If a call stream has been active
        but silent for longer than `timeout` seconds (default 10 s — 2 watchdog
        ticks), log a warning and clear that timeslot's state so it can accept
        a new call.  This handles the case where VOICE_TERM is never received
        (RF dropout, firmware bug, lost packet).
        """
        now = time()
        for ts in (1, 2):
            if self._out_stream_id[ts] is not None:
                elapsed = now - self._out_last_pkt[ts]
                if elapsed > timeout:
                    log.warning(
                        'IPSC→HBP call timeout: ts=%d stream=%s — no voice for %.1fs, clearing',
                        ts, self._out_stream_id[ts].hex(), elapsed,
                    )
                    self._out_stream_id[ts] = None
                    self._out_lc[ts]        = None
                    self._out_emb_lc[ts]    = None
            if self._in_lc[ts] is not None:
                elapsed = now - self._in_last_pkt[ts]
                if elapsed > timeout:
                    log.warning(
                        'HBP→IPSC call timeout: ts=%d — no voice for %.1fs, clearing',
                        ts, elapsed,
                    )
                    self._in_lc[ts]     = None
                    self._in_emb_lc[ts] = None

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    def is_hbp_connected(self) -> bool:
        return self._hbp is not None and self._hbp.is_connected()

    def has_ipsc_peers(self) -> bool:
        return self._ipsc is not None and self._ipsc.has_peers()
