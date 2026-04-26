# `ipsc2hbp` — Theory of Operation

---

## 1. Overview

`ipsc2hbp` is a single-process, bidirectional protocol translator that connects one Motorola MOTOTRBO repeater to one upstream DMR network server. It presents itself to the repeater as an IPSC master, and presents itself to the network as an HBP repeater/peer. Between them it converts voice call frames in real time.

The previous solution for this problem was two separate Python 2 processes — `IPSC_Bridge` from DMRlink and `HB_Bridge` from HBlink — communicating over a local UDP socket using an intermediate AMBE frame format. `ipsc2hbp` replaces both with a single Python 3 process that translates directly in memory, with no inter-process communication.

---

## 2. Architecture

### 2.1 Process Model

Single Python process. Single asyncio event loop. Two UDP endpoints. No threads. No subprocesses.

```
                ┌───────────────────────────────────────┐
                │               ipsc2hbp                │
                │                                       │
  Motorola      │  ┌───────────┐    ┌───────────────┐   │       HBP
  Repeater  UDP │  │  IPSC     │    │  HBP          │   │  UDP
  (IPSC ────────►  │  master   │◄──►│  peer         ├───┼────────► BrandMeister
  peer)   ◄─────│  │  :50000   │    │  → master_ip  │   │         DMR+
                │  └───────────┘    └───────────────┘   │         HBlink4
                │         ▲                ▲            │
                │         └────────────────┘            │
                │           CallTranslator              │
                └───────────────────────────────────────┘
```

### 2.2 Repository Layout

```
ipsc2hbp/
├── ipsc2hbp.py              # Entry point — wires all components, runs event loop
├── config.py                # TOML config parsing and validation → Config dataclass
├── ipsc/
│   ├── protocol.py          # asyncio.DatagramProtocol — IPSC master stack
│   └── const.py             # IPSC opcodes, burst types, field offsets, flag masks
├── hbp/
│   ├── protocol.py          # asyncio.DatagramProtocol + reconnect manager — HBP peer
│   └── const.py             # HBP magic strings, DMRD frame layout, RPTC field slices
├── translate/
│   └── translator.py        # CallTranslator — voice call state and frame conversion
├── tests/
│   ├── fake_ipsc_peer.py    # Test tool: simulates a Motorola repeater
│   ├── fake_hbp_master.py   # Test tool: simulates an HBP master server
│   ├── test_resilience.py   # Automated resilience scenarios
│   └── test_roundtrip.py    # AMBE round-trip verifier (feeds --wire log through translate)
├── ipsc2hbp.toml            # Live configuration (gitignored)
├── ipsc2hbp.toml.sample     # Annotated sample configuration
├── ipsc2hbp.service         # systemd unit template
├── requirements.txt         # dmr-utils3, bitarray
└── INSTALL.md               # Installation and setup guide
```

### 2.3 Startup Sequence

1. Parse CLI arguments (`-c config`, `--log-level override`, `--wire`)
2. Load and validate TOML config → `Config` dataclass (fail loudly on any error)
3. Instantiate `CallTranslator`, `IPSCProtocol`, `HBPClient`; wire them together
4. Register SIGTERM/SIGINT handlers for graceful shutdown
5. Bind IPSC UDP endpoint (asyncio datagram endpoint, local)
6. Start `HBPClient` (launches connection loop if PERSISTENT mode; waits for peer in TRACKING mode)
7. Run event loop forever

---

## 3. Configuration

Config format is **TOML** (Python 3.11+ `tomllib`). The config file is validated at startup; any missing or invalid field exits immediately with a descriptive error.

### Sections and fields

**`[global]`**
- `log_level` — `DEBUG | INFO | WARNING | ERROR` (DEBUG logs every voice burst; INFO for production)

**`[ipsc]`**
- `bind_ip` — local IP to bind the IPSC UDP socket (`0.0.0.0` for all interfaces)
- `bind_port` — UDP port the repeater connects to (must match the codeplug)
- `ipsc_master_id` — radio ID this translator presents as the IPSC master node
- `ipsc_peer_id` — radio ID of the Motorola repeater; if set, only that ID is accepted; if 0 or omitted, any peer ID is accepted (wildcard mode)
- `allowed_peer_ip` — optional; if set, only registrations from this source IP are accepted regardless of peer state or radio ID
- `auth_enabled` — boolean; enables HMAC-SHA1 packet authentication
- `auth_key` — hex string, up to 40 hex chars (20 bytes); shorter keys are left-zero-padded
- `keepalive_watchdog` — seconds without keepalive before declaring peer lost (minimum 5)

**`[hbp]`**
- `master_ip`, `master_port` — upstream HBP server address
- `passphrase` — plaintext passphrase for the HBP master (encoded to bytes internally)
- `hbp_repeater_id` — radio ID sent in all HBP packets; defaults to `ipsc_peer_id` when 0 or omitted; at least one of `ipsc_peer_id` or `hbp_repeater_id` must be non-zero
- `hbp_mode` — `TRACKING` or `PERSISTENT` (see section 6.3)
- `options` — RPTO options string, e.g. `"TS1=91,310;TS2=*"`; empty = skip RPTO step
- RPTC announcement fields: `callsign`, `rx_freq`, `tx_freq`, `tx_power`, `colorcode`, `latitude`, `longitude`, `height`, `location`, `description`, `url`, `software_id`, `package_id`

---

## 4. IPSC Master Stack

### 4.1 Protocol Overview

IPSC (Inter-IPSC Site Communication Protocol) is a proprietary Motorola MOTOTRBO protocol. ipsc2hbp operates as the **IPSC master**; the repeater is the **IPSC peer**. All packets are UDP datagrams. Packet authentication is optional HMAC-SHA1 (section 4.2).

### 4.2 IPSC Authentication

When `auth_enabled = true`, every packet sent or received carries a 10-byte HMAC-SHA1 digest appended as the last 10 bytes.

```
auth_key_bytes = binascii.unhexlify(auth_key.strip().zfill(40))   # 20 bytes
digest_hex = hmac.new(auth_key_bytes, payload, sha1).hexdigest()
digest = binascii.unhexlify(digest_hex[:20])                       # 10 bytes
packet_on_wire = payload + digest
```

On reception: strip the last 10 bytes, recompute the digest over the remaining payload, compare. Mismatch → packet dropped, WARNING logged.

### 4.3 Opcode Dispatch

All IPSC opcodes:

| Opcode | Name | Handling |
|--------|------|---------|
| `0x05` | CALL_CONFIRMATION | Ignored |
| `0x54` | TXT_MESSAGE_ACK | Ignored |
| `0x61` | CALL_MON_STATUS | Ignored |
| `0x62` | CALL_MON_RPT | Ignored |
| `0x63` | CALL_MON_NACK | Ignored |
| `0x70` | XCMP_XNL | **NEVER process** — logged DEBUG only; these packets can damage repeater RF configuration |
| `0x80` | GROUP_VOICE | Processed — primary payload |
| `0x81` | PVT_VOICE | Ignored (logged DEBUG) |
| `0x83` | GROUP_DATA | Ignored (logged DEBUG) |
| `0x84` | PVT_DATA | Ignored (logged DEBUG) |
| `0x85` | RPT_WAKE_UP | Ignored |
| `0x86` | UNKNOWN_COLLISION | Ignored (logged DEBUG) |
| `0x90` | MASTER_REG_REQ | Processed — registration |
| `0x91` | MASTER_REG_REPLY | Sent — our registration reply |
| `0x92` | PEER_LIST_REQ | Processed — peer list request |
| `0x93` | PEER_LIST_REPLY | Sent — our peer list |
| `0x94` | PEER_REG_REQ | Ignored |
| `0x95` | PEER_REG_REPLY | Ignored |
| `0x96` | MASTER_ALIVE_REQ | Processed — keepalive from repeater |
| `0x97` | MASTER_ALIVE_REPLY | Sent — keepalive acknowledgement |
| `0x98` | PEER_ALIVE_REQ | Ignored |
| `0x99` | PEER_ALIVE_REPLY | Ignored |
| `0x9A` | DE_REG_REQ | Processed — deregistration |
| `0x9B` | DE_REG_REPLY | Sent — deregister acknowledgement |
| All others | — | Silently ignored |

### 4.4 Registration Handshake

When the repeater boots, it sends `MASTER_REG_REQ`. ipsc2hbp responds immediately with `MASTER_REG_REPLY` and then `PEER_LIST_REPLY`.

**MASTER_REG_REQ received** (minimum 10 bytes):
```
Byte  0:     0x90 (opcode)
Bytes 1–4:   Repeater radio ID (4 bytes, big-endian)
Byte  5:     Mode byte (capability flags byte 1)
Bytes 6–9:   Flags (4 bytes, capability / link-type flags)
```

Radio ID validation:
- If `ipsc_peer_id` is non-zero and `peer_id_int != ipsc_peer_id` → log WARNING, drop
- If `ipsc_peer_id` is 0 (wildcard) → any peer radio ID is accepted

**MASTER_REG_REPLY sent** (16 bytes before auth):
```
Byte  0:     0x91 (opcode)
Bytes 1–4:   ipsc_master_id (4 bytes, big-endian)
Byte  5:     Our mode byte: 0x6A (operational + digital + TS1 on + TS2 on)
Bytes 6–9:   Our flags: 0x00 0x00 0x00 <flags_byte>
               flags_byte = VOICE_CALL_MSK(0x04) | MSTR_PEER_MSK(0x01)
               | PKT_AUTH_MSK(0x10) if auth enabled
Bytes 10–11: Peer count: 0x00 0x01 (one peer — the repeater itself)
Bytes 12–15: IPSC_VER: 0x04 0x02 0x04 0x01
```

**PEER_LIST_REPLY sent** immediately after REG_REPLY (18 bytes before auth):
```
Byte  0:     0x93 (opcode)
Bytes 1–4:   ipsc_master_id
Bytes 5–6:   Peer entry length: 0x00 0x0B (11 bytes)
Bytes 7–10:  Repeater's radio ID (echoed back)
Bytes 11–14: Repeater's IP address (packed binary, socket.inet_aton)
Bytes 15–16: Repeater's UDP port (big-endian uint16)
Byte  17:    Repeater's mode byte (echoed back)
```

### 4.5 Keepalive and Watchdog

The repeater sends `MASTER_ALIVE_REQ` (opcode `0x96`) periodically. ipsc2hbp responds with `MASTER_ALIVE_REPLY` (opcode `0x97`, 14 bytes: master_id + ts_flags + IPSC_VER) and updates `_last_ka = time()`.

A background asyncio task checks every 5 seconds: if `time() - _last_ka > keepalive_watchdog`, the peer is declared lost — registration state is cleared and `CallTranslator.peer_lost()` is called.

### 4.6 GROUP_VOICE Packet Layout

Real MOTOTRBO repeaters send GROUP_VOICE packets in one fixed format — the full 31-byte header is always present, including a 12-byte RTP subheader. Packet size varies by burst type:

```
Byte  0:       0x80 (GROUP_VOICE opcode)
Bytes 1–4:     Source peer radio ID (4 bytes, big-endian)
Byte  5:       Call stream ID — constant for every packet of one call, changes per call
Bytes 6–8:     Source subscriber ID (3 bytes, big-endian)
Bytes 9–11:    Destination group ID / TGID (3 bytes, big-endian)
Byte  12:      Call type (0x00 = group, 0x03 = private)
Bytes 13–16:   Call control info (4 bytes, purpose not fully documented)
Byte  17:      Call info flags:
                 bit 5 (0x20): timeslot — 0=TS1, 1=TS2
                 bit 6 (0x40): end-of-call flag
Bytes 18–19:   RTP byte 1 (v=2 flags) and byte 2 (payload type)
Bytes 20–21:   RTP sequence number (big-endian uint16)
Bytes 22–25:   RTP timestamp (big-endian uint32)
Bytes 26–29:   RTP SSRC (big-endian uint32)
Byte  30:      Burst data type (see section 4.7)
Bytes 31+:     Burst payload (variable, type-dependent — see section 5)
[last 10 bytes appended when auth enabled: HMAC-SHA1 digest]
```

Minimum accepted length: **31 bytes** (must be long enough to read burst_type at byte 30).

### 4.7 Burst Data Types

The burst data type byte encodes both the frame type and, for voice bursts, the timeslot:

| Value | Name | Timeslot determination |
|-------|------|----------------------|
| `0x01` | VOICE_HEAD | From call_info byte 17, bit 5 |
| `0x02` | VOICE_TERM | From call_info byte 17, bit 5 |
| `0x0A` | SLOT1_VOICE | Implied by value (bit 7 = 0) |
| `0x8A` | SLOT2_VOICE | Implied by value (bit 7 = 1) |

---

## 5. AMBE in IPSC Voice Packets

This section describes the physical structure of voice data in real MOTOTRBO IPSC packets, which is fundamentally different from the HBP/DMR-standard format and drives the core translation work.

### 5.1 SLOT_VOICE Payload (bytes 31–51, 21 bytes)

```
Byte 31:       RTP payload length indicator (informational)
Byte 32:       Reserved
Bytes 33–51:   19 bytes of packed AMBE codewords (three 49-bit raw AMBE frames)
```

The 19-byte AMBE block (152 bits) is laid out as:

```
bits   0– 48:  AMBE frame 1 (49 bits of raw AMBE)
bit    49:     separator (always 0)
bits  50– 98:  AMBE frame 2 (49 bits of raw AMBE)
bit    99:     separator (always 0)
bits 100–148:  AMBE frame 3 (49 bits of raw AMBE)
bits 149–151:  trailing pad (3 bits, zero)
```

This is the raw 49-bit AMBE+ECC codeword format used by the AMBE-3000 vocoder chip.

### 5.2 VOICE_TERM Payload (bytes 31–53, 23 bytes)

```
Byte 31:       RSSI threshold/parity
Bytes 32–33:   length_to_follow (big-endian word count; 10 words → 20 bytes follow)
Byte 34:       RSSI status
Byte 35:       slot type / sync indicator
Bytes 36–37:   data size (9 bytes of LC follow)
Bytes 38–40:   LC options (3 bytes: FLCO, FID, service options)
Bytes 41–43:   Destination group ID (3 bytes, big-endian)
Bytes 44–46:   Source subscriber ID (3 bytes, big-endian)
Bytes 47–49:   RS(12,9) parity — 3-byte FEC for the LC word
Bytes 50–53:   Type indicator: 0x00, 0x11 (HEAD) or 0x12 (TERM), 0x00, 0x00
```

### 5.3 VOICE_HEAD Payload (bytes 31–53, 23 bytes)

Identical structure to VOICE_TERM. The only difference is the type indicator byte: `0x11` for VOICE_HEAD vs `0x12` for VOICE_TERM (bytes 51 of the packet). Total packet length is 54 bytes for both.

---

## 6. HBP Peer Stack

### 6.1 Handshake

The HBP handshake is driven by the repeater/client side (us). Authentication uses SHA-256 (not SHA-1 — this differs from IPSC auth).

```
→ RPTL + radio_id(4)                                       [8 bytes]
← RPTACK + radio_id(4) + salt(4)                           [salt at data[6:10]]
→ RPTK + radio_id(4) + sha256(salt_bytes + passphrase)(32) [40 bytes]
← RPTACK + radio_id(4)                                     [auth accepted]
→ RPTC + config(298)                                       [302 bytes total]
← RPTACK + radio_id(4)                                     [config accepted]
→ RPTO + radio_id(4) + options(300)                        [308 bytes; only if options != ""]
← RPTACK                                                   [options accepted → CONNECTED]
```

State machine in `_HBPProtocol`: `LOGIN → AUTH_SENT → CONFIG_SENT → [OPTIONS_SENT] → CONNECTED`

There is no MSTACK packet in any HBlink version. The `RPTACK` is used at every step. The state machine advances solely on receiving `RPTACK`, with the current state determining what was being acknowledged.

### 6.2 RPTC Config Blob (302 bytes)

All fields are null-byte padded (not space-padded). BrandMeister is strict about field widths.

```
Bytes   0–  3:  b'RPTC'
Bytes   4–  7:  Repeater ID (4 bytes, big-endian)
Bytes   8– 15:  Callsign (8 bytes, null-padded)
Bytes  16– 24:  RX frequency (9 bytes, ASCII decimal Hz)
Bytes  25– 33:  TX frequency (9 bytes, ASCII decimal Hz)
Bytes  34– 35:  TX power (2 bytes, ASCII decimal watts)
Bytes  36– 37:  Color code (2 bytes, ASCII decimal 1–15)
Bytes  38– 45:  Latitude (8 bytes, ASCII decimal degrees)
Bytes  46– 54:  Longitude (9 bytes, ASCII decimal degrees)
Bytes  55– 57:  Antenna height AGL (3 bytes, ASCII decimal metres)
Bytes  58– 77:  Location (20 bytes, null-padded)
Bytes  78– 96:  Description (19 bytes, null-padded)
Byte      97:   Slots: b'3' (both timeslots enabled, always)
Bytes  98–221:  URL (124 bytes, null-padded)
Bytes 222–261:  Software ID (40 bytes, null-padded)
Bytes 262–301:  Package ID (40 bytes, null-padded)
```

### 6.3 Connection Modes: TRACKING vs PERSISTENT

**TRACKING**: HBP connects only when an IPSC peer is registered. When the repeater deregisters or the watchdog fires, ipsc2hbp sends `RPTCL` to the HBP master and disconnects. When the repeater re-registers, HBP reconnects. This keeps the network accurate about which repeaters are actually online.

**PERSISTENT**: HBP stays connected regardless of IPSC peer state. Voice is only forwarded when both sides are live, but the repeater appears permanently online to the HBP network and its dashboards.

### 6.4 Keepalive

When CONNECTED, a background asyncio task sends `RPTPING + radio_id(4)` every 5 seconds. The master responds with `MSTPONG`. If `time() - last_pong > 15 seconds` (3 missed pongs), the connection is declared lost, `CallTranslator.hbp_disconnected()` is called, and a reconnect is initiated.

### 6.5 Reconnect

On any disconnect (watchdog, MSTNAK, MSTCL, socket error), the connection manager waits 5 seconds and retries. The reconnect delay is flat, not exponential — the rationale is that the underlying network condition (UDP reachability to the master) usually resolves within one or two attempts.

### 6.6 DMRD Packet Layout

All voice frames between ipsc2hbp and the HBP master use `DMRD` packets (55 bytes — HBlink4 format):

```
Bytes  0– 3:  b'DMRD'
Byte      4:  Sequence number (0–255, wraps, per-call counter)
Bytes  5– 7:  Source radio ID (3 bytes, big-endian)
Bytes  8–10:  Destination TGID (3 bytes, big-endian)
Bytes 11–14:  Repeater ID (4 bytes, big-endian)
Byte     15:  Flags:
                bit 7 (0x80): Timeslot — 0=TS1, 1=TS2
                bit 6 (0x40): Call type — 0=group, 1=private
                bits 5–4:     Frame type:
                                0b00 (0x00) = VOICE
                                0b01 (0x10) = VOICESYNC
                                0b10 (0x20) = DATASYNC
                bits 3–0:     Voice sequence (for VOICE frames, 0–4)
                              Data type (for DATASYNC frames: 0x01=VHEAD, 0x02=VTERM)
Bytes 16–19:  Stream ID (4 random bytes, constant across a call, new per VOICE_HEAD)
Bytes 20–52:  33-byte DMR frame payload (264 bits)
Byte     53:  BER — bit error rate (0x00 for synthesised frames with no RF measurement)
Byte     54:  RSSI (0x00 for synthesised frames)
```

Note: The published HBP spec incorrectly places the timeslot bit at bit 6 and call type at bit 5. The implementation in HBlink (all versions) uses bit 7 for timeslot, which is the authoritative source.

### 6.7 DMR Voice Frame Layout (33-byte DMRD payload)

The 33-byte DMRD payload is a 264-bit DMR voice frame:

```
bits   0– 71: AMBE frame 1 (72 bits, interleaved and ECC-encoded)
bits  72–107: AMBE frame 2, first half (36 bits)
bits 108–155: EMBED field (48 bits) — voice sync or embedded LC
bits 156–191: AMBE frame 2, second half (36 bits)
bits 192–263: AMBE frame 3 (72 bits, interleaved and ECC-encoded)
```

The EMBED field content depends on the superframe position (see section 7.3).

---

## 7. Voice Frame Translation

### 7.1 AMBE Conversion Pipeline

The core translation work is converting between the IPSC 49-bit raw AMBE format and the HBP 72-bit interleaved AMBE format. Both directions use `dmr_utils3.ambe_utils`:

- `convert49BitTo72BitAMBE(bitarray_49)` → `bytearray(9)` — applies Golay ECC encoding and interleaving
- `convert72BitTo49BitAMBE(bitarray_72)` → `bitarray(49)` — deinterleaves and extracts raw 49-bit codeword

Both functions take `bitarray` objects (from the `bitarray` package, endian='big').

### 7.2 Outbound: IPSC SLOT_VOICE → HBP DMRD

For each `SLOT1_VOICE` or `SLOT2_VOICE` packet:

1. Extract 19 bytes from `data[33:52]`
2. Load into a 152-bit bitarray, extract three 49-bit codewords (skipping separator bits at positions 49 and 99):
   ```python
   raw = bitarray(endian='big')
   raw.frombytes(data[33:52])
   a1_49 = raw[0:49]
   a2_49 = raw[50:99]
   a3_49 = raw[100:149]
   ```
3. Convert each to 72-bit interleaved form:
   ```python
   a1_72 = bitarray(); a1_72.frombytes(bytes(convert49BitTo72BitAMBE(a1_49)))
   a2_72 = bitarray(); a2_72.frombytes(bytes(convert49BitTo72BitAMBE(a2_49)))
   a3_72 = bitarray(); a3_72.frombytes(bytes(convert49BitTo72BitAMBE(a3_49)))
   ```
4. Build the 48-bit EMBED field for the current superframe position (section 7.3)
5. Assemble the 264-bit DMR frame:
   ```python
   frame = a1_72 + a2_72[:36] + embed_48 + a2_72[36:] + a3_72
   payload_33 = frame.tobytes()
   ```
6. Send as DMRD with the appropriate flags byte

### 7.3 Superframe Position and EMBED Field

HBP requires the flags byte to reflect the burst's position within the 6-frame DMR voice superframe. ipsc2hbp counts SLOT_VOICE packets within each call and computes `position = frame_count % 6`:

| Position | HBP flags (TS1 example) | EMBED field content |
|----------|------------------------|-------------------|
| 0 | `0x10` (VOICESYNC) | `BS_VOICE_SYNC` (48-bit constant `755FD7DF75F7`) |
| 1 | `0x00` (VOICE, seq=0) | `EMB[BURST_B][:8]` + `EMB_LC[1]` + `EMB[BURST_B][-8:]` |
| 2 | `0x01` (VOICE, seq=1) | `EMB[BURST_C][:8]` + `EMB_LC[2]` + `EMB[BURST_C][-8:]` |
| 3 | `0x02` (VOICE, seq=2) | `EMB[BURST_D][:8]` + `EMB_LC[3]` + `EMB[BURST_D][-8:]` |
| 4 | `0x03` (VOICE, seq=3) | `EMB[BURST_E][:8]` + `EMB_LC[4]` + `EMB[BURST_E][-8:]` |
| 5 | `0x04` (VOICE, seq=4) | `EMB[BURST_F][:8]` + `NULL_EMB_LC` + `EMB[BURST_F][-8:]` |

`EMB[BURST_x]` are precomputed 16-bit burst type words (from `dmr_utils3.const.EMB`). `EMB_LC[1–4]` are 32-bit embedded LC fragments computed at call start from `bptc.encode_emblc(lc)`. `NULL_EMB_LC` is 32 zero bits (position 5 carries no LC data).

The EMBED field is 48 bits: `EMB[8 bits] + embedded_LC_fragment[32 bits] + EMB[8 bits]`.

### 7.4 Outbound: VOICE_HEAD → HBP DMRD

1. Extract `src_sub = data[6:9]` and `dst_group = data[9:12]`
2. Build 9-byte LC word: `lc = LC_OPT + dst_group + src_sub`  
   where `LC_OPT = b'\x00\x00\x00'` for group calls (FLCO=0, FID=0, SVC=0)
3. Encode using BPTC(196,96): `full_lc = bptc.encode_header_lc(lc)` → 196-bit bitarray
4. Assemble the 264-bit DMRD payload:
   ```
   full_lc[0:98] | SLOT_TYPE['VOICE_LC_HEAD'][:10] | BS_DATA_SYNC(48) | SLOT_TYPE['VOICE_LC_HEAD'][-10:] | full_lc[98:]
   ```
5. Pre-compute embedded LC for subsequent voice bursts: `emb_lc = bptc.encode_emblc(lc)` → `{1:ba32, 2:ba32, 3:ba32, 4:ba32}`
6. Generate new stream ID: `stream_id = os.urandom(4)`; reset frame position counter
7. Send DMRD with `flags = HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VHEAD` (= `0x21` for TS1)

### 7.5 Outbound: VOICE_TERM → HBP DMRD

1. Use stored LC from the call's VOICE_HEAD
2. Encode: `full_lc = bptc.encode_terminator_lc(lc)` → 196-bit bitarray
3. Assemble 264-bit payload using `SLOT_TYPE['VOICE_LC_TERM']` and `BS_DATA_SYNC`
4. Send DMRD with `flags = HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VTERM` (= `0x22` for TS1)
5. Clear call state

### 7.6 Inbound: HBP DMRD VOICE/VOICESYNC → IPSC SLOT_VOICE

AMBE extraction is the same for every burst type:

1. Extract `payload_33 = dmrd[20:53]`
2. Load 264 bits; extract three 72-bit AMBE frames (AMBE2 is split around the EMBED field):
   ```python
   burst = bitarray(); burst.frombytes(payload_33)
   a1_72 = burst[0:72]
   a2_72 = burst[72:108] + burst[156:192]   # concatenate split halves
   a3_72 = burst[192:264]
   ```
3. Convert each to 49-bit raw AMBE and pack into the 19-byte IPSC format:
   ```python
   bits = bitarray(152); bits.setall(0)
   bits[0:49] = a1_49; bits[50:99] = a2_49; bits[100:149] = a3_49
   ambe_19 = bits.tobytes()
   ```

The IPSC payload after the burst_type byte differs by HBP frame type / dtype:

| HBP frame | dtype | IPSC packet bytes | Extra payload content |
|-----------|-------|------------------|-----------------------|
| VOICESYNC | — | 52 | `b'\x14\x40'` + ambe_19 |
| VOICE | 0/1/2 (B/C/D) | 57 | `b'\x19\x06'` + ambe_19 + EMB_LC fragment + EMB header byte |
| VOICE | 3 (E) | 66 | `b'\x22\x16'` + ambe_19 + EMB_LC fragment 4 + LC[0:3] + dst + src + `b'\x14'` |
| VOICE | 4 (F) | 57 | `b'\x19\x06'` + ambe_19 + null EMB LC (4×0x00) + `b'\x10'` |
| VOICE | ≥5 | 57 | Null-LC fallback; same wire format as burst F |

`burst_type` = `SLOT2_VOICE` if TS2, else `SLOT1_VOICE`. `call_info` = `TS_CALL_MSK` if TS2, else `0x00`.

### 7.7 Inbound: HBP VOICE_HEAD/VOICE_TERM → IPSC

**VOICE_HEAD**: Decode the LC from the 264-bit BPTC-encoded DMRD payload. The BPTC functions expect a 196-bit codeword, but the full DMR frame inserts 10 slot-type bits and 48 sync bits in the middle, so the second BPTC half is at frame bits [166:264]:
```python
bptc_bits = frame_bits[0:98] + frame_bits[166:264]   # 196-bit BPTC
lc = bptc.decode_full_lc(bptc_bits).tobytes()
```
Assign a new call stream ID for byte 5 (per-call constant — see section 4.6). Pre-compute embedded LC fragments for subsequent SLOT_VOICE bursts. Send one 54-byte GROUP_VOICE packet with `burst_type = VOICE_HEAD`, RTP PT=0xdd (M=1, call-start marker).

**VOICE_TERM**: Use stored LC from the call's VOICE_HEAD. Send one 54-byte GROUP_VOICE packet with `burst_type = VOICE_TERM`, `call_info |= END_MSK`, RTP PT=0x5e. Clear inbound call state.

---

## 8. LC Word Structure

The 9-byte Link Control (LC) word is the key identifier for a voice call:

```
Byte 0: FLCO — Full LC Opcode and flags (PF bit, Reserved bit, FLCO field)
         0x00 = group voice call (FLCO-GRP)
Byte 1: FID  — Feature ID (0x00 = generic, 0x10 = Motorola proprietary)
Byte 2: Service options (0x00 = no special options)
Bytes 3–5: Destination group ID (3 bytes, big-endian)
Bytes 6–8: Source subscriber ID (3 bytes, big-endian)
```

For all calls translated by ipsc2hbp, the first 3 bytes are `b'\x00\x00\x00'` (standard group call, no special features). `dmr_utils3.const.LC_OPT` provides this constant.

---

## 9. dmr_utils3 Functions Used

All BPTC encoding, LC handling, and AMBE conversion goes through `dmr_utils3`. Note that the original Python 2 `dmr_utils` placed these functions in a module named `encode`; in `dmr_utils3` they live in `bptc`.

| Function | Module | Returns | Purpose |
|----------|--------|---------|---------|
| `encode_header_lc(lc_9)` | `dmr_utils3.bptc` | `bitarray(196)` | BPTC-encode LC for VOICE_HEAD |
| `encode_terminator_lc(lc_9)` | `dmr_utils3.bptc` | `bitarray(196)` | BPTC-encode LC for VOICE_TERM |
| `encode_emblc(lc_9)` | `dmr_utils3.bptc` | `{1–4: bitarray(32)}` | Embedded LC fragments for bursts B–E |
| `decode_full_lc(info_bits)` | `dmr_utils3.bptc` | `bitarray(72)` | BPTC-decode LC from 196-bit info field |
| `convert49BitTo72BitAMBE(ba49)` | `dmr_utils3.ambe_utils` | `bytearray(9)` | Encode 49-bit raw AMBE to 72-bit interleaved |
| `convert72BitTo49BitAMBE(ba72)` | `dmr_utils3.ambe_utils` | `bitarray(49)` | Decode 72-bit interleaved to 49-bit raw AMBE |

`dmr_utils3.const` provides protocol constants: `EMB`, `SLOT_TYPE`, `BS_VOICE_SYNC`, `BS_DATA_SYNC`, `LC_OPT`.

---

## 10. Logging

**Destination**: stderr only. systemd captures stderr into journald automatically.

**Wire mode** (`--wire` CLI flag): silences all normal logging and instead emits one line per raw IPSC packet — `SEND N hex` or `RECV N hex`. Use this to capture a live call to a file (`python ipsc2hbp.py --wire 2>wire.txt`) and replay through `tests/test_roundtrip.py` to verify AMBE round-trip integrity.

**Format**: `%(asctime)s %(levelname)s [%(name)s] %(message)s`

| Event | Level |
|-------|-------|
| Startup parameters | INFO |
| Shutdown (SIGTERM / SIGINT) | INFO |
| IPSC peer registered / re-registered | INFO |
| IPSC peer lost (watchdog or DE_REG) | WARNING |
| IPSC peer rejected — STRICT mode | WARNING |
| IPSC auth failure | WARNING |
| HBP connected | INFO |
| HBP disconnected (watchdog or close) | WARNING |
| HBP MSTNAK received | ERROR |
| HBP reconnect initiated | INFO |
| HBP socket error | WARNING |
| IPSC call start (VOICE_HEAD from repeater) | INFO |
| IPSC call end (VOICE_TERM from repeater) | INFO |
| HBP call start (VOICE_HEAD from network) | INFO |
| HBP call end (VOICE_TERM from network) | INFO |
| SLOT_VOICE too short for AMBE | WARNING |
| Individual voice burst (SLOT_VOICE/DMRD) | DEBUG |
| XCMP/XNL received | DEBUG |
| PEER_LIST_REQ | DEBUG |
| MASTER_ALIVE exchange | DEBUG |

DEBUG mode is noisy — every SLOT_VOICE burst logs a hex dump of the first 32 bytes. Use INFO for production.

---

## 11. Scope Boundaries

| Out of Scope | Rationale |
|---|---|
| Timeslot translation or rewriting | This is a translator, not a router |
| TGID translation or rewriting | Same |
| Private voice calls | Group voice only |
| Data calls (GROUP_DATA, PVT_DATA) | Dropped silently |
| XNL / XCMP processing | ignored |
| Multiple IPSC peers | One repeater only |
| Multiple HBP upstream masters | One network server only |
| Conference, bridging, routing | Not this tool |
| ACL / filtering | Upstream master's responsibility |
| Burst timeout watchdog (synthesize VOICE_TERM) | Not implemented; repeater is responsible for call termination |

---

## 12. Attribution

`ipsc2hbp` is a Python 3 implementation built from study of:

- **DMRlink** (IPSC stack) — Cortney T. Buffington, N0MJS
- **HBlink** / **HBlink3** / **HBlink4** (HomeBrew Protocol stack) — Cortney T. Buffington, N0MJS
- **dmr_utils** / **dmr_utils3** (AMBE, BPTC, LC utilities) — Cortney T. Buffington, N0MJS

The HomeBrew Repeater Protocol was developed by Jonathan Naylor G4KLX, Hans Barthen DL5DI, and Torsten Schultze DG1HT.

The IPSC protocol is a reverse-engineered interpretation of the Motorola MOTOTRBO IPSC protocol used for amateur radio interoperability. Motorola and MOTOTRBO are registered trademarks of Motorola Solutions, Inc. This project is not affiliated with Motorola Solutions.

---

*ipsc2hbp — Copyright (C) 2026 Cortney T. Buffington, N0MJS — GNU GPLv3*
