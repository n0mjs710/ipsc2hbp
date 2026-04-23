"""
CallTranslator — bidirectional IPSC ↔ HBP translation.

Outbound (IPSC → HBP): ipsc_voice_received()
  - Byte-pair-swaps the 34-byte IPSC DMR payload → 33-byte HBP payload
  - Maps IPSC burst types to HBP frame type flags
  - Tracks voice superframe position (VOICESYNC / VOICE 0–4)
  - Generates a random 4-byte stream ID per call

Inbound (HBP → IPSC): hbp_voice_received()
  - Extracts src/dst/ts/frame-type from 53-byte DMRD frame
  - Maps HBP frame type flags back to IPSC burst type and call_info byte
  - Byte-pair-swaps the 33-byte HBP payload → 34-byte IPSC payload
  - Rebuilds GROUP_VOICE packet and forwards to registered repeater

Payload byte-pair swap (self-inverse, confirmed from DMRlink IPSC_Bridge.py):
  IPSC → HBP:  swap(payload_34)[:33]
  HBP  → IPSC: swap(b'\\x00' + payload_33)

Superframe mapping (6-frame cycle, positions reset on each VOICE_HEAD):
  position 0   → HBPF_FRAMETYPE_VOICESYNC (frame A / sync)
  positions 1–5 → HBPF_FRAMETYPE_VOICE + seq 0–4 (frames B–F)
"""

import logging
import os
import struct

from config import Config
from ipsc.const import (
    GROUP_VOICE,
    VOICE_HEAD, VOICE_TERM, SLOT1_VOICE, SLOT2_VOICE,
    TS_CALL_MSK, END_MSK,
    GV_SRC_SUB_OFF, GV_DST_GROUP_OFF, GV_PAYLOAD_OFF,
)
from hbp.const import (
    HBPF_DMRD,
    HBPF_TGID_TS2,
    HBPF_FRAMETYPE_VOICE, HBPF_FRAMETYPE_VOICESYNC, HBPF_FRAMETYPE_DATASYNC,
    HBPF_FRAMETYPE_MASK, HBPF_DTYPE_MASK,
    HBPF_SLT_VHEAD, HBPF_SLT_VTERM,
    DMRD_LEN,
    DMRD_SEQ_OFF, DMRD_SRC_OFF, DMRD_DST_OFF,
    DMRD_FLAGS_OFF, DMRD_STREAM_OFF, DMRD_PAYLOAD_OFF,
)

log = logging.getLogger(__name__)


def _swap_pairs(data: bytes) -> bytes:
    """Swap every adjacent byte pair. Self-inverse."""
    arr = bytearray(data)
    for i in range(0, len(arr) - 1, 2):
        arr[i], arr[i + 1] = arr[i + 1], arr[i]
    return bytes(arr)


class CallTranslator:
    """
    Wires IPSCProtocol and HBPClient together.

    Instantiate first, then pass to both protocol objects, then call
    set_protocols() so the translator can reach back into each stack.
    """

    def __init__(self, cfg: Config):
        self._cfg           = cfg
        self._ipsc          = None   # set via set_protocols()
        self._hbp           = None   # set via set_protocols()
        self._repeater_id_b = cfg.hbp_repeater_id.to_bytes(4, 'big')

        # Outbound call state (IPSC → HBP)
        self._out_stream_id  = None   # 4 random bytes, new per call
        self._out_seq        = 0      # DMRD sequence byte, wraps at 256
        self._out_frame_pos  = 0      # superframe position counter

        # Inbound call state (HBP → IPSC)
        self._in_ipsc_seq    = 0      # IPSC sequence byte at GV offset 5
        self._in_rtp_seq     = 0      # RTP sequence number in GV header

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
        if self._cfg.hbp_mode == 'TRACKING':
            self._hbp.deactivate()

    def ipsc_voice_received(self, data: bytes, ts: int, burst_type: int):
        if not self._hbp.is_connected():
            return

        if burst_type == VOICE_HEAD:
            self._out_stream_id = os.urandom(4)
            self._out_frame_pos = 0
            src = int.from_bytes(data[GV_SRC_SUB_OFF:GV_SRC_SUB_OFF + 3], 'big')
            dst = int.from_bytes(data[GV_DST_GROUP_OFF:GV_DST_GROUP_OFF + 3], 'big')
            log.info('Outbound call start: src=%d  tg=%d  ts=%d  stream=%s',
                     src, dst, ts, self._out_stream_id.hex())

        if self._out_stream_id is None:
            return   # missed VOICE_HEAD

        src_sub    = data[GV_SRC_SUB_OFF  : GV_SRC_SUB_OFF  + 3]
        dst_group  = data[GV_DST_GROUP_OFF : GV_DST_GROUP_OFF + 3]
        raw_payload = data[GV_PAYLOAD_OFF  : GV_PAYLOAD_OFF  + 34]

        payload_33 = _swap_pairs(raw_payload)[:33]

        flags = HBPF_TGID_TS2 if ts == 2 else 0x00

        if burst_type == VOICE_HEAD:
            flags |= HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VHEAD
        elif burst_type == VOICE_TERM:
            flags |= HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VTERM
        else:
            pos = self._out_frame_pos % 6
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

    # ------------------------------------------------------------------
    # HBP callbacks
    # ------------------------------------------------------------------

    def hbp_connected(self):
        log.info('HBP connected')

    def hbp_disconnected(self):
        log.warning('HBP disconnected')
        self._out_stream_id = None

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

        # Map HBP frame type → IPSC burst type + call_info byte
        if frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VHEAD:
            burst_type = VOICE_HEAD
            call_info  = TS_CALL_MSK if ts == 2 else 0x00
        elif frame_type == HBPF_FRAMETYPE_DATASYNC and dtype == HBPF_SLT_VTERM:
            burst_type = VOICE_TERM
            call_info  = (TS_CALL_MSK | END_MSK) if ts == 2 else END_MSK
        else:  # VOICESYNC or VOICE
            burst_type = SLOT2_VOICE if ts == 2 else SLOT1_VOICE
            call_info  = TS_CALL_MSK if ts == 2 else 0x00

        # Reconstruct 34-byte IPSC payload: prepend 0x00 → swap
        payload_34 = _swap_pairs(b'\x00' + payload_33)

        rtp_seq_b = struct.pack('>H', self._in_rtp_seq & 0xFFFF)
        self._in_rtp_seq += 1

        gv = (
            bytes([GROUP_VOICE])
            + self._repeater_id_b           # peer_id (4 bytes)
            + bytes([self._in_ipsc_seq])     # IPSC seq (1 byte)
            + src_sub                        # src subscriber (3 bytes)
            + dst_group                      # dst group (3 bytes)
            + b'\x00'                        # call_type: group
            + b'\x00\x00\x00\x00'           # call_ctrl (4 bytes)
            + bytes([call_info])             # call_info: TS + END bits
            + b'\x80\x00'                   # RTP: v=2, no flags
            + rtp_seq_b                      # RTP sequence (2 bytes)
            + b'\x00\x00\x00\x00'           # RTP timestamp (4 bytes)
            + b'\x00\x00\x00\x00'           # RTP SSRC (4 bytes)
            + bytes([burst_type])            # burst type (1 byte)
            + payload_34                     # 34-byte DMR payload
        )
        self._in_ipsc_seq = (self._in_ipsc_seq + 1) & 0xFF
        self._ipsc.send_to_peer(gv)

        if burst_type == VOICE_HEAD:
            log.info('Inbound call start: src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
        elif burst_type == VOICE_TERM:
            log.info('Inbound call end:   src=%d  tg=%d  ts=%d',
                     int.from_bytes(src_sub, 'big'), int.from_bytes(dst_group, 'big'), ts)
        else:
            log.debug('← IPSC GV  burst=0x%02x  ts=%d', burst_type, ts)

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    def is_hbp_connected(self) -> bool:
        return self._hbp is not None and self._hbp.is_connected()

    def is_ipsc_registered(self) -> bool:
        return self._ipsc is not None and self._ipsc.is_peer_registered()
