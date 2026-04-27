# ---------------------------------------------------------------------------
# IPSC opcodes (from DMRlink ipsc/ipsc_const.py)
# ---------------------------------------------------------------------------
CALL_CONFIRMATION  = 0x05   # Ignore
TXT_MESSAGE_ACK    = 0x54   # Ignore
CALL_MON_STATUS    = 0x61   # Ignore
CALL_MON_RPT       = 0x62   # Ignore
CALL_MON_NACK      = 0x63   # Ignore
XCMP_XNL           = 0x70   # NEVER TOUCH — can damage repeaters
GROUP_VOICE        = 0x80   # PROCESS — primary payload
PVT_VOICE          = 0x81   # Ignore (log DEBUG)
GROUP_DATA         = 0x83   # Ignore (log DEBUG)
PVT_DATA           = 0x84   # Ignore (log DEBUG)
RPT_WAKE_UP        = 0x85   # Ignore
UNKNOWN_COLLISION  = 0x86   # Ignore (log DEBUG)
MASTER_REG_REQ     = 0x90   # PROCESS — repeater registering with us
MASTER_REG_REPLY   = 0x91   # SEND — our response to registration
PEER_LIST_REQ      = 0x92   # PROCESS — repeater requesting peer list
PEER_LIST_REPLY    = 0x93   # SEND — our peer list response
PEER_REG_REQ       = 0x94   # Ignore
PEER_REG_REPLY     = 0x95   # Ignore
MASTER_ALIVE_REQ   = 0x96   # PROCESS — repeater keep-alive
MASTER_ALIVE_REPLY = 0x97   # SEND — our keep-alive reply
PEER_ALIVE_REQ     = 0x98   # Ignore
PEER_ALIVE_REPLY   = 0x99   # Ignore
DE_REG_REQ         = 0x9A   # PROCESS — repeater deregistering
DE_REG_REPLY       = 0x9B   # SEND — our deregister acknowledgement

# ---------------------------------------------------------------------------
# Burst data type byte values — timeslot is encoded inside this byte
# ---------------------------------------------------------------------------
VOICE_HEAD  = 0x01   # Voice LC header — call start (TS from IPSC header byte 17)
VOICE_TERM  = 0x02   # Terminator with LC — call end (TS from IPSC header byte 17)
SLOT1_VOICE = 0x0A   # Voice burst on Timeslot 1
SLOT2_VOICE = 0x8A   # Voice burst on Timeslot 2 (bit 7 set)

# ---------------------------------------------------------------------------
# IPSC protocol version — used in MASTER_REG_REPLY and MASTER_ALIVE_REPLY.
# Source: DMRlink ipsc_const.py — LINK_TYPE_IPSC + IPSC_VER_17 + LINK_TYPE_IPSC + IPSC_VER_16
# ---------------------------------------------------------------------------
IPSC_VER = b'\x04\x02\x04\x01'

# ---------------------------------------------------------------------------
# Capability / link-type flags used in registration packets.
# Source: DMRlink ipsc/ipsc_mask.py
# ---------------------------------------------------------------------------
# Byte 4 of the 4-byte FLAGS field sent in REG_REQ / REG_REPLY:
VOICE_CALL_MSK = 0b00000100   # voice calls supported
DATA_CALL_MSK  = 0b00001000   # data calls supported
PKT_AUTH_MSK   = 0b00010000   # packets are authenticated
MSTR_PEER_MSK  = 0b00000001   # set when acting as master

# Byte 17 of GROUP_VOICE — timeslot and end-of-call:
TS_CALL_MSK = 0b00100000   # bit 5: 1=TS2, 0=TS1
END_MSK     = 0b01000000   # bit 6: 1=call end (VOICE_TERM already sent)

# ---------------------------------------------------------------------------
# GROUP_VOICE packet field offsets — confirmed from DMRlink IPSC_Bridge.py
# dumpIPSCFrame() and dmrlink.py datagramReceived().
# ---------------------------------------------------------------------------
GV_PEER_ID_OFF    = 1    # bytes 1–4:   source peer radio ID (4 bytes)
GV_IPSC_SEQ_OFF   = 5    # byte  5:     call stream ID — constant within a call, increments by 1 each new call, wraps at 255
GV_SRC_SUB_OFF    = 6    # bytes 6–8:   source subscriber ID (3 bytes)
GV_DST_GROUP_OFF  = 9    # bytes 9–11:  destination group ID / TGID (3 bytes)
GV_CALL_INFO_OFF  = 17   # byte  17:    call info — TS_CALL_MSK and END_MSK
GV_BURST_TYPE_OFF = 30   # byte  30:    burst data type (payload type)
GV_PAYLOAD_OFF    = 31   # bytes 31+:   burst payload (variable length by type)

# Minimum GROUP_VOICE length we will accept (must reach byte 30 for burst_type):
#   SLOT1/SLOT2_VOICE: 52 bytes (31-byte header + 2-byte pad + 19-byte AMBE)
#   VOICE_TERM:        54 bytes  (31-byte header + 23-byte payload)
#   VOICE_HEAD:        54 bytes  (31-byte header + 23-byte payload)
GV_MIN_LEN      = 31    # header through burst_type byte

AUTH_DIGEST_LEN = 10    # HMAC-SHA1 digest bytes appended when auth enabled
