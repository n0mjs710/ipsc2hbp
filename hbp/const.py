# ---------------------------------------------------------------------------
# HomeBrew Repeater Protocol — magic strings and frame type constants
# Source: hblink.py (HB_Bridge branch), hblink3/const.py
# ---------------------------------------------------------------------------

# Magic byte strings — authoritative from hblink4/hblink4/constants.py
HBPF_DMRD    = b'DMRD'    # Voice/data frame
HBPF_RPTL    = b'RPTL'    # Login request (repeater → master)
HBPF_RPTK    = b'RPTK'    # Auth response (repeater → master)
HBPF_RPTC    = b'RPTC'    # Config blob (repeater → master)
HBPF_RPTACK  = b'RPTACK'  # ACK at every handshake step (master → repeater)
HBPF_MSTNAK  = b'MSTNAK'  # NAK from master
HBPF_RPTPING = b'RPTPING' # Keep-alive ping (repeater → master)
HBPF_MSTPONG = b'MSTPONG' # Keep-alive pong (master → repeater)
HBPF_RPTO    = b'RPTO'    # Options (repeater → master, optional post-RPTC step)
HBPF_RPTCL   = b'RPTCL'   # Close / disconnect (repeater → master)
HBPF_MSTCL   = b'MSTCL'   # Close from master (master → repeater)

# Parsed command prefixes (first 4 bytes) used for dispatch
HBPF_CMD_DMRD = b'DMRD'
HBPF_CMD_RPTA = b'RPTA'   # matches RPTACK
HBPF_CMD_MSTN = b'MSTN'   # matches MSTNAK
HBPF_CMD_MSTP = b'MSTP'   # matches MSTPONG
HBPF_CMD_MSTC = b'MSTC'   # matches MSTCL
HBPF_CMD_RPTP = b'RPTP'   # matches RPTPING

# ---------------------------------------------------------------------------
# DMRD flags byte (byte 15) — bit layout confirmed from hblink.py and hblink3
#
# Bit 7 (0x80): Timeslot  — 0=TS1, 1=TS2
# Bit 6 (0x40): Call type — 0=group, 1=private
# Bits 5–4:     Frame type (VOICE=0, VOICESYNC=1, DATASYNC=2)
# Bits 3–0:     Data type / voice sequence
#
# NOTE: The spec (section 4.2) incorrectly places TS at bit 6 and call type
# at bit 5. Authoritative source is hblink.py: _slot = 2 if (_bits & 0x80)
# ---------------------------------------------------------------------------
HBPF_TGID_TS2    = 0x80   # Bit 7: timeslot 2
HBPF_TGID_CALL_P = 0x40   # Bit 6: private call

# Frame type values (shifted into bits 5–4)
HBPF_FRAMETYPE_VOICE     = 0x00   # 0b00 → bits 5-4 = 00
HBPF_FRAMETYPE_VOICESYNC = 0x10   # 0b01 → bits 5-4 = 01
HBPF_FRAMETYPE_DATASYNC  = 0x20   # 0b10 → bits 5-4 = 10

# Data type field values (bits 3–0) for DataSync frames
HBPF_SLT_VHEAD  = 0x01   # DataSync + VHEAD (voice LC header)
HBPF_SLT_VTERM  = 0x02   # DataSync + VTERM (voice LC terminator)

# Frame type extraction helper masks
HBPF_FRAMETYPE_MASK = 0x30   # bits 5–4
HBPF_DTYPE_MASK     = 0x0F   # bits 3–0

# ---------------------------------------------------------------------------
# DMRD packet layout constants
# ---------------------------------------------------------------------------
DMRD_LEN         = 55    # Total DMRD packet length (bytes) — HBlink4 format
DMRD_MAGIC_OFF   = 0     # bytes 0–3: b'DMRD'
DMRD_SEQ_OFF     = 4     # byte 4: sequence number (0–255, wraps)
DMRD_SRC_OFF     = 5     # bytes 5–7: source radio ID (3 bytes, big-endian)
DMRD_DST_OFF     = 8     # bytes 8–10: destination TGID (3 bytes, big-endian)
DMRD_RPTR_OFF    = 11    # bytes 11–14: repeater ID (4 bytes, big-endian)
DMRD_FLAGS_OFF   = 15    # byte 15: flags (TS, call type, frame type, dtype/vseq)
DMRD_STREAM_OFF  = 16    # bytes 16–19: stream ID (4 bytes random per call)
DMRD_PAYLOAD_OFF = 20    # bytes 20–52: 33-byte DMR payload
DMRD_BER_OFF     = 53    # byte 53: bit error rate (0 for synthesised frames)
DMRD_RSSI_OFF    = 54    # byte 54: RSSI (0 for synthesised frames)

# ---------------------------------------------------------------------------
# RPTC config blob layout — 302 bytes total.
# Confirmed from hblink.py RPTC parsing (HB_Bridge branch).
# Several fields differ from the written spec — these are the authoritative offsets.
# ---------------------------------------------------------------------------
RPTC_LEN = 302

# Field slices within the 302-byte RPTC packet (including 4-byte magic prefix)
RPTC_RADIO_ID   = slice(4,   8)    # 4 bytes
RPTC_CALLSIGN   = slice(8,  16)    # 8 bytes
RPTC_RX_FREQ    = slice(16, 25)    # 9 bytes, ASCII digits, Hz
RPTC_TX_FREQ    = slice(25, 34)    # 9 bytes, ASCII digits, Hz
RPTC_TX_POWER   = slice(34, 36)    # 2 bytes, ASCII decimal
RPTC_COLORCODE  = slice(36, 38)    # 2 bytes (spec incorrectly said 3)
RPTC_LATITUDE   = slice(38, 46)    # 8 bytes, ASCII float
RPTC_LONGITUDE  = slice(46, 55)    # 9 bytes, ASCII float
RPTC_HEIGHT     = slice(55, 58)    # 3 bytes, ASCII decimal, meters
RPTC_LOCATION   = slice(58, 78)    # 20 bytes, space-padded
RPTC_DESCRIPTION= slice(78, 97)    # 19 bytes (spec incorrectly said 20)
RPTC_SLOTS      = slice(97, 98)    # 1 byte  (spec omitted this field entirely)
RPTC_URL        = slice(98, 222)   # 124 bytes (spec incorrectly said 24)
RPTC_SOFTWARE_ID= slice(222, 262)  # 40 bytes
RPTC_PACKAGE_ID = slice(262, 302)  # 40 bytes

# ---------------------------------------------------------------------------
# HBP handshake — RPTACK is used at every step. No MSTACK in any HBlink version.
# Confirmed from hblink4/hblink4/hblink.py _handle_repeater_login,
# _handle_auth_response, _handle_config, and _connect_outbound.
#
# Handshake (peer/client side):
#   1. Send RPTL + rptr_id(4)
#   2. Recv RPTACK + salt(4)  → salt at data[6:10]
#   3. Compute: sha256(salt_bytes + passphrase.encode()).hexdigest() → 64-char hex
#              bytes.fromhex(hexdigest) → 32 binary bytes
#   4. Send RPTK + rptr_id(4) + hash(32)          total = 40 bytes
#   5. Recv RPTACK + rptr_id(4)  → auth accepted
#   6. Send RPTC + config(298)                    total = 302 bytes
#   7. Recv RPTACK + rptr_id(4)  → config accepted
#   8. Send RPTO + rptr_id(4) + options_str(300)  total = 308 bytes  [if options configured]
#   9. Recv RPTACK + rptr_id(4)  → options accepted → CONNECTED
#   (steps 8–9 are skipped when options is empty; CONNECTED after step 7)
#
# RPTC padding: null bytes (\x00), NOT spaces — from hblink4 _send_outbound_config
# SLOTS field: always b'3' (both slots enabled)
# ---------------------------------------------------------------------------
RPTACK_NONCE_OFF = 6    # byte offset of 4-byte nonce in RPTACK (challenge)
RPTACK_ID_OFF    = 6    # byte offset of 4-byte repeater ID in RPTACK (post-auth/config)
MSTPONG_ID_OFF   = 7    # byte offset of 4-byte repeater ID in MSTPONG
MSTCL_ID_OFF     = 5    # byte offset of 4-byte repeater ID in MSTCL

RPTC_SLOTS_VALUE = b'3' # Both timeslots enabled (sent as ASCII '3')
