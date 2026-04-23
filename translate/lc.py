"""
LC encode/decode wrappers over dmr_utils3.

All functions operate on plain bytes — no bitarray leaks into caller code.

NOTE: The spec attributes encode_header_lc / encode_terminator_lc / encode_emblc
to dmr_utils3.encode, but they actually live in dmr_utils3.bptc. encode.py is a stub.
"""

import logging
from bitarray import bitarray
from dmr_utils3 import bptc, const as dmr_const
from dmr_utils3 import decode as dmr_decode

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Voice burst frame layout (264 bits = 33 bytes)
#   [0:98]    info part 1
#   [98:108]  slot type part 1 (10 bits)
#   [108:156] sync (48 bits)
#   [156:166] slot type part 2 (10 bits)
#   [166:264] info part 2
# ---------------------------------------------------------------------------


def decode_lc_from_voice_head(payload_33: bytes) -> bytes | None:
    """Decode the 9-byte LC from a 33-byte voice head or terminator payload.

    Returns None on any decode failure (caller should drop the call).
    """
    try:
        result = dmr_decode.voice_head_term(payload_33)
        lc = result['LC']  # bytes, exactly 9 bytes from decode_full_lc
        if len(lc) < 9:
            log.warning('LC decode returned %d bytes (expected 9)', len(lc))
            return None
        return lc[:9]
    except Exception as exc:
        log.warning('LC decode failed: %s', exc)
        return None


def _build_burst(bptc_bits: bitarray, slot_type: bitarray, sync: bitarray) -> bytes:
    """Assemble a 33-byte (264-bit) DMR voice burst from pre-computed components."""
    burst = bitarray(endian='big')
    burst.extend(bptc_bits[0:98])
    burst.extend(slot_type[0:10])
    burst.extend(sync)
    burst.extend(slot_type[10:20])
    burst.extend(bptc_bits[98:196])
    return burst.tobytes()


def encode_voice_head(lc_9: bytes) -> bytes:
    """Return a 33-byte voice LC header burst payload from a 9-byte LC."""
    bptc_bits = bptc.encode_header_lc(lc_9)
    return _build_burst(
        bptc_bits,
        dmr_const.SLOT_TYPE['VOICE_LC_HEAD'],
        dmr_const.BS_DATA_SYNC,
    )


def encode_voice_term(lc_9: bytes) -> bytes:
    """Return a 33-byte voice LC terminator burst payload from a 9-byte LC."""
    bptc_bits = bptc.encode_terminator_lc(lc_9)
    return _build_burst(
        bptc_bits,
        dmr_const.SLOT_TYPE['VOICE_LC_TERM'],
        dmr_const.BS_DATA_SYNC,
    )


def build_embedded_lc(lc_9: bytes) -> dict[int, bytes]:
    """Return embedded LC fragments for voice bursts B–E.

    Returns {1: bytes(4), 2: bytes(4), 3: bytes(4), 4: bytes(4)}.
    Keys 1–4 correspond to DMR bursts B, C, D, E respectively.
    Each 4-byte value goes into bits [116:148] of the 33-byte voice burst.
    """
    emblc = bptc.encode_emblc(lc_9)
    return {k: v.tobytes() for k, v in emblc.items()}
