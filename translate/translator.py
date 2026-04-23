"""
CallTranslator — bidirectional IPSC ↔ HBP translation.

Outbound (IPSC → HBP): ipsc_voice_received()
  VOICE_HEAD:       Build DMRD VOICE_LC_HEAD frame from BPTC-encoded LC.
  SLOT1/SLOT2_VOICE: Convert 3×49-bit AMBE from IPSC to 3×72-bit, assemble
                    264-bit DMR voice frame with proper EMBED/SYNC field.
  VOICE_TERM:       Build DMRD VOICE_LC_TERM frame from BPTC-encoded LC.

Inbound (HBP → IPSC): hbp_voice_received()
  VOICE_HEAD/TERM:  Reconstruct IPSC header/term packet with LC payload.
  VOICE/VOICESYNC:  Extract 3×72-bit AMBE from DMRD, convert to 3×49-bit,
                    pack into 19-byte IPSC AMBE format.

AMBE layout in IPSC SLOT_VOICE (bytes 33–51, 19 bytes = 152 bits):
  bits[0:49]   = AMBE frame 1 (49 bits)
  bits[49]     = separator (0)
  bits[50:99]  = AMBE frame 2 (49 bits)
  bits[99]     = separator (0)
  bits[100:149] = AMBE frame 3 (49 bits)
  bits[149:152] = padding (0)

DMR voice frame layout (264 bits = 33 bytes):
  AMBE1[72] | AMBE2_first[36] | EMBED[48] | AMBE2_second[36] | AMBE3[72]

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

from bitarray import bitarray

from dmr_utils3 import bptc, decode
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
    VOICE_HEAD (26 bytes) or VOICE_TERM (23 bytes).

    Structure (confirmed from DMRlink IPSC_Bridge.py dumpIPSCFrame):
      byte 0:   RSSI threshold/parity
      bytes 1–2: length_to_follow (big-endian word count from offset 34 to end)
      byte 3:   RSSI status
      byte 4:   slot type / sync
      bytes 5–6: data size (bytes of LC that follow)
      bytes 7+:  LC word (9 bytes) + RS129 FEC padding

    length_to_follow = (packet_len - 34) / 2 words
      VOICE_TERM: (54-34)/2 = 10 words → 23-byte payload
      VOICE_HEAD: (58-34)/2 = 12 words → 26-byte payload (packet may be 57 or 58)
    """
    if burst_type == VOICE_HEAD:
        ltf = 12
        pad = b'\x00' * 10
    else:  # VOICE_TERM
        ltf = 10
        pad = b'\x00' * 7

    return (
        b'\x00'                  # RSSI threshold/parity
        + struct.pack('>H', ltf) # length_to_follow
        + b'\x00'                # RSSI status
        + b'\x00'                # slot type sync
        + struct.pack('>H', 9)   # LC data size = 9 bytes
        + lc[:9]                 # LC_OPT(3) + dst_group(3) + src_sub(3)
        + pad
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

        # Outbound call state (IPSC → HBP)
        self._out_stream_id = None   # 4 random bytes, new per call
        self._out_seq       = 0      # DMRD sequence byte, wraps at 256
        self._out_frame_pos = 0      # superframe position (0–5, cycles)
        self._out_lc        = None   # 9-byte LC for embedded LC generation
        self._out_emb_lc    = None   # dict {1–4: bitarray(32)} embedded LC

        # Inbound call state (HBP → IPSC)
        self._in_lc         = None   # 9-byte LC decoded from HBP VOICE_HEAD
        self._in_ipsc_seq   = 0      # IPSC sequence byte at GV offset 5
        self._in_rtp_seq    = 0      # RTP sequence in GV header

    def set_protocols(self, ipsc_proto, hbp_client):
        self._ipsc = ipsc_proto
        self._hbp  = hbp_client

    # ------------------------------------------------------------------
    # IPSC callbacks
    # ------------------------------------------------------------------

    def peer_registered(self, peer_id: bytes, host: str, port: int):
        log.info('IPSC peer registered: id=%d  %s:%d',
                 int.from_bytes(peer_id, 'big'), host, port)
        if self._cfg.hbp_mode == 'TRACKING':
            self._hbp.activate()

    def peer_lost(self):
        log.warning('IPSC peer lost')
        self._out_stream_id = None
        self._out_lc        = None
        self._out_emb_lc    = None
        if self._cfg.hbp_mode == 'TRACKING':
            self._hbp.deactivate()

    def ipsc_voice_received(self, data: bytes, ts: int, burst_type: int):
        if not self._hbp.is_connected():
            return

        src_sub   = data[GV_SRC_SUB_OFF   : GV_SRC_SUB_OFF   + 3]
        dst_group = data[GV_DST_GROUP_OFF  : GV_DST_GROUP_OFF + 3]
        flags     = HBPF_TGID_TS2 if ts == 2 else 0x00

        if burst_type == VOICE_HEAD:
            self._out_stream_id = os.urandom(4)
            self._out_frame_pos = 0
            lc = LC_OPT + dst_group + src_sub
            self._out_lc     = lc
            self._out_emb_lc = bptc.encode_emblc(lc)
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
            log.info('Outbound call start: src=%d  tg=%d  ts=%d  stream=%s',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'),
                     ts, self._out_stream_id.hex())

        elif burst_type == VOICE_TERM:
            if self._out_stream_id is None:
                return
            lc = self._out_lc if self._out_lc else LC_OPT + dst_group + src_sub
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
            if self._out_stream_id is None:
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

            pos   = self._out_frame_pos % 6
            embed = self._build_embed(pos)
            frame_bits = a1_72 + a2_72[:36] + embed + a2_72[36:] + a3_72
            payload_33 = frame_bits.tobytes()
            flags |= HBPF_FRAMETYPE_VOICESYNC if pos == 0 else (HBPF_FRAMETYPE_VOICE | (pos - 1))
            self._out_frame_pos += 1

        dmrd = (
            HBPF_DMRD
            + bytes([self._out_seq])
            + src_sub
            + dst_group
            + self._repeater_id_b
            + bytes([flags])
            + self._out_stream_id
            + payload_33
        )
        self._out_seq = (self._out_seq + 1) & 0xFF
        self._hbp.send_dmrd(dmrd)
        log.debug('→ HBP DMRD  burst=0x%02x  ts=%d  flags=0x%02x', burst_type, ts, flags)

        if burst_type == VOICE_TERM:
            log.info('Outbound call end:   src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
            self._out_stream_id = None
            self._out_lc        = None
            self._out_emb_lc    = None

    def _build_embed(self, pos: int) -> bitarray:
        """Build the 48-bit EMBED field for superframe position 0–5."""
        if pos == 0:
            return BS_VOICE_SYNC
        name    = _EMB_BURST_NAMES[pos - 1]
        lc_bits = self._out_emb_lc.get(pos, _NULL_EMB_LC) if self._out_emb_lc and pos <= 4 else _NULL_EMB_LC
        return EMB[name][:8] + lc_bits + EMB[name][-8:]

    # ------------------------------------------------------------------
    # HBP callbacks
    # ------------------------------------------------------------------

    def hbp_connected(self):
        log.info('HBP connected')

    def hbp_disconnected(self):
        log.warning('HBP disconnected')
        self._out_stream_id = None
        self._out_lc        = None
        self._out_emb_lc    = None

    def hbp_voice_received(self, dmrd: bytes):
        """Inbound HBP → IPSC."""
        if not self._ipsc.is_peer_registered():
            return
        if len(dmrd) < DMRD_LEN:
            return

        src_sub    = dmrd[DMRD_SRC_OFF  : DMRD_SRC_OFF  + 3]
        dst_group  = dmrd[DMRD_DST_OFF  : DMRD_DST_OFF  + 3]
        flags      = dmrd[DMRD_FLAGS_OFF]
        payload_33 = dmrd[DMRD_PAYLOAD_OFF : DMRD_PAYLOAD_OFF + 33]

        ts         = 2 if (flags & HBPF_TGID_TS2) else 1
        frame_type = flags & HBPF_FRAMETYPE_MASK
        dtype      = flags & HBPF_DTYPE_MASK
        call_info  = TS_CALL_MSK if ts == 2 else 0x00

        rtp_seq_b = struct.pack('>H', self._in_rtp_seq & 0xFFFF)
        self._in_rtp_seq += 1
        rtp_header = b'\x80\x00' + rtp_seq_b + b'\x00\x00\x00\x00' + b'\x00\x00\x00\x00'

        if frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VHEAD:
            lc = LC_OPT + dst_group + src_sub
            self._in_lc = lc
            burst_type  = VOICE_HEAD
            gv_payload  = bytes([burst_type]) + _build_ipsc_voice_payload(lc, burst_type)

        elif frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VTERM:
            lc = self._in_lc if self._in_lc else LC_OPT + dst_group + src_sub
            call_info  |= END_MSK
            burst_type  = VOICE_TERM
            gv_payload  = bytes([burst_type]) + _build_ipsc_voice_payload(lc, burst_type)

        else:  # VOICESYNC or VOICE — audio frame
            burst_type = SLOT2_VOICE if ts == 2 else SLOT1_VOICE
            ambe_19    = _extract_ambe_from_dmrd(payload_33)
            # byte 31: RTP payload length indicator; byte 32: reserved (both 0)
            gv_payload = bytes([burst_type]) + b'\x00\x00' + ambe_19

        gv = (
            bytes([GROUP_VOICE])
            + self._repeater_id_b          # peer_id — we identify as the repeater
            + bytes([self._in_ipsc_seq])
            + src_sub                      # source subscriber (3 bytes)
            + dst_group                    # destination group (3 bytes)
            + b'\x00'                      # call_type: group
            + b'\x00\x00\x00\x00'         # call_ctrl (4 bytes)
            + bytes([call_info])           # TS + END flags
            + rtp_header                   # 12-byte RTP header
            + gv_payload                   # burst_type + payload bytes
        )
        self._in_ipsc_seq = (self._in_ipsc_seq + 1) & 0xFF
        self._ipsc.send_to_peer(gv)

        if burst_type == VOICE_HEAD:
            log.info('Inbound call start: src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
        elif burst_type == VOICE_TERM:
            log.info('Inbound call end:   src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
            self._in_lc = None
        else:
            log.debug('← IPSC GV  burst=0x%02x  ts=%d', burst_type, ts)

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    def is_hbp_connected(self) -> bool:
        return self._hbp is not None and self._hbp.is_connected()

    def is_ipsc_registered(self) -> bool:
        return self._ipsc is not None and self._ipsc.is_peer_registered()
