# IPSC Packet Reference

Derived from DMRlink source, wire captures, and code analysis.
Fields marked **[?]** are confirmed from wire captures but their purpose is not fully understood.

All multi-byte integers are big-endian unless noted.

---

## Auth Suffix

When `auth_enabled = true`, every packet has a 10-byte HMAC-SHA1 digest appended
after the last documented field.  The digest is computed over the packet body
(excluding the suffix itself).

---

## Control Packets

### MASTER_REG_REQ (0x90) — received from peer

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x90 |
| 1 | 4 | Peer Radio ID | big-endian uint32 |
| 5 | 1 | Peer MODE | peer capability/mode flags (see MODE byte below) |
| 6 | 4 | Peer FLAGS | peer capability flags (see FLAGS word below); reserved for future use |
| [10] | 10 | Auth digest | if auth enabled |

**Minimum length:** 10 bytes (+ 10 if auth).

---

### MASTER_REG_REPLY (0x91) — we send

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x91 |
| 1 | 4 | Master Radio ID | our master ID |
| 5 | 1 | Master MODE | 0x6A (see MODE byte below) |
| 6 | 4 | Master FLAGS | 0x00000005 (VOICE_CALL\|MSTR_PEER); +0x10 (PKT_AUTH) if auth enabled |
| 10 | 2 | Num Peers | always 1 |
| 12 | 4 | IPSC Version | 0x04020401 (LINK_TYPE_IPSC + VER17 + LINK_TYPE_IPSC + VER16) |
| [16] | 10 | Auth digest | if auth enabled |

**Total:** 16 bytes (+ 10 if auth).

---

### PEER_LIST_REQ (0x92) — received from peer

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x92 |
| [1] | 10 | Auth digest | if auth enabled |

**Minimum length:** 1 byte (+ 10 if auth).

---

### PEER_LIST_REPLY (0x93) — we send

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x93 |
| 1 | 4 | Master Radio ID | our master ID |
| 5 | 2 | Peer Data Length | total length of peer entries in bytes (11 bytes per peer) |
| 7 | 4 | Peer Radio ID | peer's radio ID |
| 11 | 4 | Peer IP | packed IPv4 (inet_aton format) |
| 15 | 2 | Peer Port | UDP port |
| 17 | 1 | Peer MODE | peer's MODE byte (echoed from REG_REQ) |
| [18] | 10 | Auth digest | if auth enabled |

**Total:** 18 bytes for 1 peer (+ 10 if auth).
Multiple peers would extend the peer data section; we always send exactly 1 peer.

---

### MASTER_ALIVE_REQ (0x96) — received from peer

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x96 |
| 1 | 4 | Peer Radio ID | confirmed from wire captures |
| 5 | 1 | Peer MODE | same as REG_REQ |
| 6 | 4 | Peer FLAGS | same as REG_REQ |
| 10 | 4 | IPSC Version | 0x04020401 |
| [14] | 10 | Auth digest | if auth enabled |

**Total:** 14 bytes (+ 10 if auth) — confirmed from wire captures.
Same structure as MASTER_REG_REQ; we only inspect bytes 1–4 (peer radio ID).

The keepalive interval is user-configurable in the repeater CPS (Customer Programming Software)
and is typically set to keep UDP NAT translations alive through aggressive firewalls.
15 seconds is a common value but not a protocol constant.

---

### MASTER_ALIVE_REPLY (0x97) — we send

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x97 |
| 1 | 4 | Master Radio ID | our master ID |
| 5 | 1 | Master MODE | 0x6A |
| 6 | 4 | Master FLAGS | same as REG_REPLY |
| 10 | 4 | IPSC Version | 0x04020401 |
| [14] | 10 | Auth digest | if auth enabled |

**Total:** 14 bytes (+ 10 if auth).

---

### DE_REG_REQ (0x9A) — received from peer

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x9A |
| 1 | 4 | Peer Radio ID | |
| [5] | 10 | Auth digest | if auth enabled |

---

### DE_REG_REPLY (0x9B) — we send

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x9B |
| 1 | 4 | Master Radio ID | |
| [5] | 10 | Auth digest | if auth enabled |

**Total:** 5 bytes (+ 10 if auth).

---

### MASTER_ACK (0xF0) — received from peer, post-original-firmware

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0xF0 |
| 1 | 4 | Peer Radio ID | confirmed from wire captures |
| 5 | 4 | Unknown | always 0x00000000 in observed traffic |

**Total:** 9 bytes. No response sent.

Observed in wire captures from later repeater firmware versions; not present in original firmware.
Consistently appears in the keepalive cycle following MASTER_ALIVE_REPLY.
Purpose is not known — possibly a keepalive acknowledgement, possibly RDAC-related.
Documented from observation only; no assumption about intent is made.

---

## MODE Byte

One byte encoding capability and operational state.  Our value: **0x6A**.

| Bit | Mask | Meaning |
|-----|------|---------|
| 6 | 0x40 | Operational |
| 5 | 0x20 | Digital |
| 3 | 0x08 | Timeslot 1 active |
| 1 | 0x02 | Timeslot 2 active |

---

## FLAGS Word (4 bytes)

Only byte 4 (the last byte) is used; bytes 1–3 are zero.

| Bit | Mask | Meaning |
|-----|------|---------|
| 2 | 0x04 | Voice calls supported (VOICE_CALL_MSK) |
| 4 | 0x10 | Packets authenticated (PKT_AUTH_MSK) |
| 0 | 0x01 | Acting as master (MSTR_PEER_MSK) |

---

## GROUP_VOICE (0x80) — Common Header (bytes 0–29)

Identical structure for both directions (peer→us and us→peer).

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 0 | 1 | Opcode | 0x80 |
| 1 | 4 | Source Radio ID | repeater's peer ID (outbound) or our master ID (inbound) |
| 5 | 1 | Call Stream ID | constant for all packets of one call; increments by 1 per new call; wraps at 255 |
| 6 | 3 | Source Subscriber ID | originating radio ID |
| 9 | 3 | Destination Group ID | TGID |
| 12 | 1 | Call Type | 0x02 = group voice; echoed from repeater, default 0x02 |
| 13 | 4 | Call Control | Motorola call priority / control field; purpose opaque without access to Motorola's proprietary documentation. Safe to echo from repeater — call interrupt and priority data are not used on amateur networks. Default 0x000043E2. |
| 17 | 1 | Call Info | bit 5 (0x20) = TS2; bit 6 (0x40) = call end (set in VOICE_TERM) |
| 18 | 1 | RTP byte 0 | 0x80 — V=2, P=0, X=0, CC=0 |
| 19 | 1 | RTP PT | payload type + M bit: 0xDD=call start (VOICE_HEAD), 0x5E=call end (VOICE_TERM), 0x5D=voice burst |
| 20 | 2 | RTP Sequence | uint16, increments per packet, wraps at 65535 |
| 22 | 4 | RTP Timestamp | uint32, starts at 0, increments 480 per frame (8 kHz × 60 ms DMR slot) |
| 26 | 4 | RTP SSRC | 0x00000000 — not used |
| 30 | 1 | Burst Type | see burst type table below |

---

## Burst Type Values (byte 30)

| Value | Constant | Direction | Meaning |
|-------|----------|-----------|---------|
| 0x01 | VOICE_HEAD | both | Voice LC header — call start |
| 0x02 | VOICE_TERM | both | Terminator with LC — call end |
| 0x0A | SLOT1_VOICE | both | Voice burst, Timeslot 1 |
| 0x8A | SLOT2_VOICE | both | Voice burst, Timeslot 2 (bit 7 set) |

---

## GROUP_VOICE Payloads (byte 31 onward)

### VOICE_HEAD / VOICE_TERM — 54 bytes total (23-byte payload)

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 31 | 1 | RSSI_THRESH_PARITY | 0x80 — confirmed from wire captures |
| 32 | 2 | Length to Follow | 0x000A = 10 words — length of repeater burst data that follows, in 16-bit words (HEAD/TERM are data packets in IPSC); covers bytes 34–53 = 20 bytes |
| 34 | 1 | RSSI Status | 0x80 — confirmed from wire captures |
| 35 | 1 | Slot Type | 0x0A — DMR slot type byte, FEC-decoded from the DMR frame header |
| 36 | 2 | Data Size | 0x0060 = 96 bits |
| 38 | 9 | LC Word | FLCO(1) + FID(1) + SVC_OPT(1) + dst_group(3) + src_sub(3) |
| 47 | 3 | RS(12,9) FEC | parity bytes; differs between HEAD and TERM encoding |
| 50 | 1 | Padding | 0x00 |
| 51 | 1 | Type Indicator | 0x11 = VOICE_HEAD, 0x12 = VOICE_TERM |
| 52 | 2 | Padding | 0x0000 |

---

### SLOT1/SLOT2_VOICE — Burst A (VOICESYNC) — 52 bytes total

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 31 | 1 | Length to Follow | 0x14 = 20 bytes — length of EMB flags + FEC-decoded AMBE data (including bad-data bits per frame, always 0) that follows; covers bytes 32–51 |
| 32 | 1 | EMB / LC / Sync Flags | 0x40 — encodes LC, sync, and EMB content indicators; constant for group voice VOICESYNC bursts; partially deciphered |
| 33 | 19 | AMBE (frames a/b/c) | 152 bits: frame_a(49) + bad_data_a(1) + frame_b(49) + bad_data_b(1) + frame_c(49) + bad_data_c(1) + pad(2); bad data bits set to 0 on transmit (no decode-error information available from HBP side) |

---

### SLOT1/SLOT2_VOICE — Bursts B / C / D — 57 bytes total

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 31 | 1 | Length to Follow | 0x19 = 25 bytes — EMB flags + AMBE + embedded LC fragment; covers bytes 32–56 |
| 32 | 1 | EMB / LC / Sync Flags | 0x06 — constant for group voice B/C/D bursts; partially deciphered |
| 33 | 19 | AMBE (frames a/b/c) | 152 bits: frame_a(49) + bad_data_a(1) + frame_b(49) + bad_data_b(1) + frame_c(49) + bad_data_c(1) + pad(2); bad data bits set to 0 on transmit |
| 52 | 4 | Embedded LC Fragment | LC fragment 1/2/3 (for B/C/D) from embedded LC encoding |
| 56 | 1 | EMB Header | burst-specific EMB header byte, bit 0 cleared (& 0xFE) |

---

### SLOT1/SLOT2_VOICE — Burst E — 66 bytes total

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 31 | 1 | Length to Follow | 0x22 = 34 bytes — EMB flags + AMBE + embedded LC fragment + LC repeat; covers bytes 32–65 |
| 32 | 1 | EMB / LC / Sync Flags | 0x16 — constant for group voice burst E; partially deciphered |
| 33 | 19 | AMBE (frames a/b/c) | 152 bits: frame_a(49) + bad_data_a(1) + frame_b(49) + bad_data_b(1) + frame_c(49) + bad_data_c(1) + pad(2); bad data bits set to 0 on transmit |
| 52 | 4 | Embedded LC Fragment 4 | LC fragment 4 from embedded LC encoding |
| 56 | 3 | LC Prefix | FLCO(1) + FID(1) + SVC_OPT(1) |
| 59 | 3 | Destination Group | TGID |
| 62 | 3 | Source Subscriber | originating radio ID |
| 65 | 1 | EMB (FEC decoded) | 7-bit FEC-decoded EMB value + 1 pad bit; 0x14 for group voice burst E |

---

### SLOT1/SLOT2_VOICE — Burst F — 57 bytes total

| Offset | Len | Field | Value / Notes |
|--------|-----|-------|---------------|
| 31 | 1 | Length to Follow | 0x19 = 25 bytes — EMB flags + AMBE + null embedded LC; covers bytes 32–56 |
| 32 | 1 | EMB / LC / Sync Flags | 0x06 — constant for group voice burst F; partially deciphered |
| 33 | 19 | AMBE (frames a/b/c) | 152 bits: frame_a(49) + bad_data_a(1) + frame_b(49) + bad_data_b(1) + frame_c(49) + bad_data_c(1) + pad(2); bad data bits set to 0 on transmit |
| 52 | 4 | Null Embedded LC | 0x00000000 |
| 56 | 1 | EMB Header | 0x10 (BURST_F EMB header 0x11, bit 0 cleared) |

---

## Partially Understood Fields

| Packet | Offset | Value | Status |
|--------|--------|-------|--------|
| GROUP_VOICE header | 13–16 | 0x000043E2 | Motorola call priority / control; opaque without proprietary documentation. Safe to echo for amateur use (no call interrupt or priority data). |
| VOICE_HEAD/TERM payload | 35 | 0x0A | DMR slot type byte, FEC-decoded from DMR frame header. Value understood, full decoding not implemented. |
| Burst A payload | 32 | 0x40 | EMB/LC/sync flags; partially deciphered. Constant for group voice VOICESYNC bursts. |
| Bursts B/C/D/F payload | 32 | 0x06 | EMB/LC/sync flags; partially deciphered. Constant for group voice B/C/D/F bursts. |
| Burst E payload | 32 | 0x16 | EMB/LC/sync flags; partially deciphered. Constant for group voice burst E. |
| Burst E payload | 65 | 0x14 | FEC-decoded EMB (7 bits) + 1 pad bit. |

All values are confirmed correct from live wire captures with a working system.
Further decoding of byte 32 variants may be possible as more protocol notes are recovered.
The call control field (bytes 13–16) is considered permanently opaque without access to Motorola's proprietary IPSC documentation.
