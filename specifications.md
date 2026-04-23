# `ipsc2hbp` — Complete Technical Specification
### Version 1.0 — For Implementation in Claude Code / VS Code

---

## 1. Project Overview

`ipsc2hbp` is a single-purpose, bidirectional protocol translator that connects one Motorola MOTOTRBO repeater (via IPSC, acting as the IPSC master) to one upstream DMR network server (via the HomeBrew Repeater Protocol, acting as an HBP peer/repeater). It is designed to run as a lightweight, resilient systemd service on a Raspberry Pi or similar ARM SBC co-located with the Motorola repeater. It has no routing, bridging, conference, or filtering capability — it is a transparent translator only.

---

## 2. Confirmed Technical Facts From Research

These facts are locked and must be implemented exactly as stated.

### 2.1 IPSC HMAC Authentication

- The auth key in the config is a **hex string**, up to 40 hex characters (= 20 bytes)
- Keys shorter than 40 hex chars are **left-zero-padded** to 40 hex chars before use
- In code: `key_bytes = binascii.unhexlify(auth_key.zfill(40))`
- HMAC-SHA1 is computed over the full UDP payload using this key
- Only the **first 10 bytes** (20 hex chars) of the resulting digest are used
- In code: `digest = hmac.new(key_bytes, payload, hashlib.sha1).hexdigest()[:20]`
- The 10-byte binary digest is **appended** to the end of every sent packet when auth is enabled
- On received packets when auth is enabled, the last 10 bytes are the digest and must be stripped before processing; validate by computing expected digest over the stripped payload

### 2.2 IPSC Burst Data Types (from `ipsc_const.py`)

The **timeslot is encoded inside the burst data type byte**, not in a separate packet field.

```
VOICE_HEAD  = 0x01   # Voice LC header — marks call start (TS determined separately)
VOICE_TERM  = 0x02   # Terminator with LC — marks call end (TS determined separately)
SLOT1_VOICE = 0x0A   # Voice burst on Timeslot 1
SLOT2_VOICE = 0x8A   # Voice burst on Timeslot 2 (bit 7 set = TS2)
```

For `VOICE_HEAD` and `VOICE_TERM`, the timeslot is determined from a separate field in the IPSC packet header (not the burst type byte). For `SLOT1_VOICE`/`SLOT2_VOICE`, bit 7 of the burst type byte encodes the timeslot directly.

### 2.3 IPSC DMR Payload Byte Swap — CRITICAL

**IPSC stores the 34-byte DMR payload with every pair of consecutive bytes swapped** relative to the standard HBP/over-the-air byte order. This swap must be applied in both directions:

```python
def swap_payload_bytes(payload: bytearray) -> bytes:
    """Swap every pair of bytes. Required for IPSC<->HBP payload conversion."""
    data = bytearray(payload)
    for i in range(0, len(data) - 1, 2):
        data[i], data[i+1] = data[i+1], data[i]
    return bytes(data)
```

- **IPSC→HBP (outbound)**: apply swap to IPSC payload to get HBP-compatible bytes
- **HBP→IPSC (inbound)**: apply swap to HBP payload to get IPSC-compatible bytes
- The swap is its own inverse — same function in both directions

### 2.4 IPSC vs HBP Payload Size

- IPSC GROUP_VOICE DMR payload: **34 bytes** (byte-swapped pairs, includes IPSC-specific framing)
- HBP DMRD DMR payload field: **33 bytes** (bytes 20–52 of the DMRD packet)
- The relationship: after byte-swapping the 34-byte IPSC payload, take bytes 0–32 (33 bytes) for HBP. When building IPSC from HBP, prepend a zero byte, apply swap, sending 34 bytes.

> **⚠️ TEST CHECKPOINT**: This boundary condition must be verified against live traffic during hardware testing.

### 2.5 IPSC Opcode Table (Complete)

```
CALL_CONFIRMATION  = 0x05   # Ignore
TXT_MESSAGE_ACK    = 0x54   # Ignore
CALL_MON_STATUS    = 0x61   # Ignore
CALL_MON_RPT       = 0x62   # Ignore
CALL_MON_NACK      = 0x63   # Ignore
XCMP_XNL           = 0x70   # NEVER TOUCH — not even logged above DEBUG
GROUP_VOICE        = 0x80   # PROCESS — primary payload
PVT_VOICE          = 0x81   # Ignore (log at DEBUG)
GROUP_DATA         = 0x83   # Ignore (log at DEBUG)
PVT_DATA           = 0x84   # Ignore (log at DEBUG)
RPT_WAKE_UP        = 0x85   # Ignore
UNKNOWN_COLLISION  = 0x86   # Log at DEBUG, ignore
MASTER_REG_REQ     = 0x90   # PROCESS — repeater registering with us
MASTER_REG_REPLY   = 0x91   # SEND — our response to registration
PEER_LIST_REQ      = 0x92   # PROCESS — repeater requesting peer list
PEER_LIST_REPLY    = 0x93   # SEND — our peer list response
PEER_REG_REQ       = 0x94   # Ignore (no peer-to-peer in single-peer setup)
PEER_REG_REPLY     = 0x95   # Ignore
MASTER_ALIVE_REQ   = 0x96   # PROCESS — repeater keep-alive to us (master)
MASTER_ALIVE_REPLY = 0x97   # SEND — our keep-alive reply
PEER_ALIVE_REQ     = 0x98   # Ignore
PEER_ALIVE_REPLY   = 0x99   # Ignore
DE_REG_REQ         = 0x9A   # PROCESS — repeater deregistering
DE_REG_REPLY       = 0x9B   # SEND — our deregister acknowledgement
```

### 2.6 IPSC Registration Validation — STRICT vs LOOSE

**STRICT mode**: validate that the packet is well-formed (minimum length, correct source IP/port, correct opcode) and that the source radio ID matches the configured `ipsc_peer_id`. If ID does not match: log WARNING and drop the packet. Do **not** validate capability flag bytes — these vary by firmware version and cause false rejections on legitimate hardware.

**LOOSE mode**: accept any well-formed registration packet from any source radio ID. Log a WARNING if the ID doesn't match the configured value, but proceed with registration.

### 2.7 dmr_utils3 Coverage — Complete

All required functions exist in `dmr_utils3`. The pip package name is `dmr-utils3`. Key functions used:

| Function | Module | Purpose |
|---|---|---|
| `decode.voice_head_term(dmrpkt)` | `dmr_utils3.decode` | Decode LC from 33-byte voice head/term payload |
| `bptc.decode_196_96(payload)` | `dmr_utils3.bptc` | BPTC FEC decode |
| `encode.encode_header_lc(lc_bits)` | `dmr_utils3.encode` | Build voice LC header packet |
| `encode.encode_terminator_lc(lc_bits)` | `dmr_utils3.encode` | Build voice LC terminator packet |
| `encode.encode_emblc(lc_bytes)` | `dmr_utils3.encode` | Build embedded LC fragments for bursts B–E; returns dict keys 1–4 |
| `utils.int_id(hex_str)` | `dmr_utils3.utils` | Convert 3/4-byte hex string to integer |
| `utils.hex_str_3(integer)` | `dmr_utils3.utils` | Convert integer to 3-byte hex string |
| `utils.hex_str_4(integer)` | `dmr_utils3.utils` | Convert integer to 4-byte hex string |

There is no functional gap between `dmr_utils` (Python 2) and `dmr_utils3` (Python 3) for any function required by this project.

---

## 3. Architecture

### 3.1 Design Philosophy

**One job, done well.** This software translates one IPSC network (one Motorola repeater) into one HBP peer connection to one upstream master. It does not bridge, conference, parrot, route, translate timeslots, or rewrite TGIDs.

### 3.2 Process Model

Single Python process. Single asyncio event loop. Two UDP endpoints. One translator state machine. No threads. No subprocesses. No inter-process communication.

### 3.3 Topology

```
                    ┌─────────────────────────────────────┐
                    │            Raspberry Pi              │
                    │                                      │
  Motorola          │  ┌────────────────────────────────┐ │
  Repeater   UDP    │  │         ipsc2hbp               │ │      HBP
  (MOTOTRBO) ──────►│  │  IPSC Master  │  HBP Peer      │ │─────────► BrandMeister
  (IPSC peer)  ◄────│  │  :50000       │  →:62031        │ │           DMR+
                    │  └────────────────────────────────┘ │           FreeDMR
                    │                                      │           HBlink4
                    └─────────────────────────────────────┘
```

### 3.4 Repository Structure

```
ipsc2hbp/
├── ipsc2hbp.py              # Entry point — wires all components, runs event loop
├── config.py                # Config parsing, validation, dataclass output
├── ipsc/
│   ├── __init__.py
│   ├── protocol.py          # asyncio.DatagramProtocol — IPSC master stack
│   └── const.py             # IPSC opcodes, burst data types, version constants
├── hbp/
│   ├── __init__.py
│   ├── protocol.py          # asyncio.DatagramProtocol — HBP peer stack
│   └── const.py             # HBP magic strings, frame type constants, RPTC format
├── translate/
│   ├── __init__.py
│   ├── bridge.py            # CallTranslator — bidirectional call state machine
│   └── lc.py                # LC encode/decode helpers wrapping dmr_utils3
├── tests/
│   ├── fake_ipsc_peer.py    # Test tool: simulates Motorola repeater
│   └── fake_hbp_master.py  # Test tool: simulates HBP master (HBlink4, BM, etc.)
├── ipsc2hbp.cfg.sample      # Annotated sample configuration file
├── ipsc2hbp.service         # systemd unit file
├── install.sh               # Installation script for Raspberry Pi OS
└── requirements.txt         # dmr-utils3, bitarray
```

### 3.5 Component Responsibilities

**`ipsc2hbp.py`**
- Parse CLI arguments (config file path, optional log level override)
- Load and validate config via `config.py`
- Instantiate `CallTranslator`, `IPSCProtocol`, `HBPProtocol`
- Wire them together: pass references so each can call the other
- Create asyncio event loop
- Register UDP endpoints with the loop
- Register SIGTERM/SIGINT handler for graceful shutdown
- Start the loop

**`config.py`**
- Parse `.cfg` (INI format) using `configparser`
- Validate all required fields are present and have valid values
- Return a frozen `Config` dataclass (not a dict — typed access only)
- Fail loudly at startup if config is invalid — no silent defaults for required fields

**`ipsc/protocol.py` — `IPSCProtocol(asyncio.DatagramProtocol)`**
- Bind UDP socket to `ipsc.bind_ip:ipsc.bind_port`
- Handle all incoming datagrams via `datagram_received()`
- Strip and validate auth digest on all received packets (if auth enabled)
- Dispatch to handler methods by opcode
- Maintain peer registration state: `{registered: bool, peer_ip: str, peer_port: int, last_keepalive: float, radio_id: bytes}`
- Run watchdog task (asyncio periodic task): if `time() - last_keepalive > watchdog_timeout`, declare peer lost
- On peer lost: log WARNING, clear registration state, notify `CallTranslator`
- On re-registration: log INFO, update state, notify `CallTranslator`
- Expose `send_to_peer(packet: bytes)` for inbound translation path

**`hbp/protocol.py` — `HBPProtocol(asyncio.DatagramProtocol)`**
- Connect UDP socket to `hbp.master_ip:hbp.master_port`
- Implement HBP handshake state machine (states: `DISCONNECTED`, `LOGIN_SENT`, `AUTH_SENT`, `CONFIG_SENT`, `CONNECTED`)
- Run keep-alive task (asyncio periodic task): send `RPTPING` every 5 seconds when `CONNECTED`
- Track missed pongs: if `missed_pongs > 5`, declare disconnected and begin reconnect
- Implement reconnect with exponential backoff: 5s → 10s → 20s → 40s → 60s cap
- Expose `send_voice(dmrd_packet: bytes)` — only sends if state is `CONNECTED`
- Expose `is_connected() -> bool`
- Expose `connection_state` property for monitoring

**`translate/bridge.py` — `CallTranslator`**
- Holds references to both protocol instances
- Maintains two independent call state slots, keyed by timeslot (1 and 2):
  ```python
  call_state = {
      1: {'active': False, 'stream_id': None, 'seq': 0, 'lc': None,
          'emb_lc': None, 'start_time': 0, 'last_burst_time': 0},
      2: {'active': False, 'stream_id': None, 'seq': 0, 'lc': None,
          'emb_lc': None, 'start_time': 0, 'last_burst_time': 0}
  }
  ```
- Implements `ipsc_voice_received(data: bytes, timeslot: int, burst_type: int)` — outbound path
- Implements `hbp_voice_received(dmrd: bytes)` — inbound path
- Runs burst watchdog task: check every 100ms; if `time() - last_burst_time > 0.360` for an active call, synthesize voice terminator and close the stream
- Never forwards outbound if HBP is not connected
- Never forwards inbound if IPSC peer is not registered (tracking mode only)

**`translate/lc.py`**
- Wrapper functions over `dmr_utils3` using clean Python 3 types (bytes in, bytes out)
- `decode_lc_from_voice_head(payload_33: bytes) -> bytes | None` — returns 9-byte LC or None on failure
- `encode_voice_head(lc_9: bytes) -> bytes` — returns 33-byte voice head payload
- `encode_voice_term(lc_9: bytes) -> bytes` — returns 33-byte voice term payload
- `build_embedded_lc(lc_9: bytes) -> dict` — returns `{1: bytes, 2: bytes, 3: bytes, 4: bytes}` for burst B/C/D/E embedding

---

## 4. Packet Layouts

### 4.1 IPSC GROUP_VOICE Packet

```
Byte  0:       Opcode (0x80 = GROUP_VOICE)
Bytes 1–4:     Source Peer ID (4 bytes, big-endian) — the repeater's Radio ID
Bytes 5–8:     Source Subscriber ID (4 bytes, big-endian) — the talking radio
Bytes 9–12:    Destination Group ID / TGID (4 bytes, big-endian)
Bytes 13–29:   Unknown / reserved / sequence-related fields
Byte  30:      Burst Data Type (see section 2.2)
Bytes 31–64:   34-byte byte-swapped DMR payload (see section 2.3)
[last 10 bytes: HMAC digest appended if auth enabled]
```

> **⚠️ TEST CHECKPOINT**: Exact offsets of fields between bytes 13–29 must be verified against DMRlink's `dmrlink.py` source or a live Wireshark capture during development. The fields at bytes 1–4, 5–8, 9–12, and burst type at byte 30 are confirmed from DMRlink log output and ipsc_const.py usage patterns.

### 4.2 HBP DMRD Packet

Total length: 53 bytes.

```
Bytes  0– 3:  b'DMRD'  (4-byte magic)
Byte      4:  Sequence number (0–255, wraps, per-call counter)
Bytes  5– 7:  Source Radio ID (3 bytes, big-endian)
Bytes  8–10:  Destination TGID (3 bytes, big-endian)
Bytes 11–14:  Repeater ID (4 bytes, big-endian)
Byte     15:  Flags:
                Bit 7:    reserved (0)
                Bit 6:    Timeslot (0=TS1, 1=TS2)
                Bit 5:    Call type (0=group, 1=private) — always 0 for this project
                Bits 4–3: Frame type: 00=Voice, 01=VoiceSync, 10=DataSync
                Bits 2–0: Data type / voice sequence (for DataSync frames)
Bytes 16–19:  Stream ID (4 bytes, random per call via os.urandom(4))
Bytes 20–52:  33-byte DMR payload
```

### 4.3 IPSC → HBP Flag Byte Construction

```python
ts_bit = 0x40 if timeslot == 2 else 0x00

if burst_type == VOICE_HEAD:
    frame_bits = 0x10  # DataSync (0x2 << 3), dtype=1 (HBPF_SLT_VHEAD)
elif burst_type == VOICE_TERM:
    frame_bits = 0x12  # DataSync (0x2 << 3), dtype=2 (HBPF_SLT_VTERM)
elif burst_type in (SLOT1_VOICE, SLOT2_VOICE):
    # Track burst_count % 6 to determine superframe position:
    # Position 0 → VoiceSync:  frame_bits = 0x08  (frame_type=01)
    # Position 1 → Voice seq=0: frame_bits = 0x00
    # Position 2 → Voice seq=1: frame_bits = 0x01
    # Position 3 → Voice seq=2: frame_bits = 0x02
    # Position 4 → Voice seq=3: frame_bits = 0x03
    # Position 5 → Voice seq=4: frame_bits = 0x04
    pass  # See section 5.3 for sequence tracking

flags = ts_bit | frame_bits
```

### 4.4 HBP → IPSC Burst Type Construction

```python
timeslot = 2 if (flags & 0x40) else 1
frame_type = (flags >> 3) & 0x03
dtype_vseq = flags & 0x07

if frame_type == 0x02 and dtype_vseq == 0x01:   # DataSync + VHEAD
    burst_type = VOICE_HEAD
elif frame_type == 0x02 and dtype_vseq == 0x02:  # DataSync + VTERM
    burst_type = VOICE_TERM
else:                                             # Voice or VoiceSync
    burst_type = SLOT2_VOICE if timeslot == 2 else SLOT1_VOICE
```

---

## 5. Protocol State Machines

### 5.1 IPSC Master State Machine

```
INIT
  │  (UDP socket bound, listening)
  ▼
WAITING_FOR_PEER
  │  MASTER_REG_REQ received from repeater
  │  → validate (STRICT or LOOSE per config)
  │  → if STRICT and ID mismatch: log WARNING, drop packet, stay in WAITING
  │  → if valid: send MASTER_REG_REPLY, send PEER_LIST_REPLY
  ▼
PEER_REGISTERED
  │  → notify CallTranslator: peer_registered(radio_id, ip, port)
  │  → start watchdog timer
  │  
  │  MASTER_ALIVE_REQ received → send MASTER_ALIVE_REPLY, update last_keepalive
  │  GROUP_VOICE received → pass to CallTranslator.ipsc_voice_received()
  │  DE_REG_REQ received → send DE_REG_REPLY → notify CallTranslator: peer_lost()
  │
  │  [watchdog fires: last_keepalive too old]
  │  → log WARNING, notify CallTranslator: peer_lost()
  ▼
WAITING_FOR_PEER
```

**MASTER_REG_REPLY format:**
```
Byte  0:     0x91 (opcode)
Bytes 1–4:   Our IPSC master Radio ID (ipsc_master_id from config, 4 bytes big-endian)
Bytes 5–8:   Flags (match what repeater sent, with master bit set in byte 8)
Bytes 9–12:  Protocol version (IPSC_VER constant)
[+ auth digest if auth enabled]
```

**PEER_LIST_REPLY format:**
```
Byte  0:     0x93 (opcode)
Bytes 1–4:   Our IPSC master Radio ID
Bytes 5–6:   Peer list length (big-endian uint16) — total bytes of peer entries following
Bytes 7–10:  Repeater's Radio ID (4 bytes big-endian)
Bytes 11–14: Repeater's IP address (4 bytes, big-endian packed via socket.inet_aton)
Bytes 15–16: Repeater's UDP port (big-endian uint16)
Bytes 17–20: Repeater's capability flags (echo back what repeater sent)
[+ auth digest if auth enabled]
```

### 5.2 HBP Peer State Machine

```
DISCONNECTED
  │  (trigger: peer registered, if TRACKING mode)
  │  (trigger: startup, if PERSISTENT mode)
  │  → send RPTL packet
  ▼
LOGIN_SENT
  │  RPTACK received → send RPTK (passphrase)
  │  timeout (10s) → DISCONNECTED, begin backoff
  ▼
AUTH_SENT
  │  RPTACK received → send RPTC (config blob)
  │  RPTNAK received → log ERROR "bad passphrase" → DISCONNECTED (long backoff)
  │  timeout (10s) → DISCONNECTED, begin backoff
  ▼
CONFIG_SENT
  │  MSTACK received → CONNECTED
  │  timeout (10s) → DISCONNECTED, begin backoff
  ▼
CONNECTED
  │  → start RPTPING task (every 5 seconds)
  │  → reset missed_pongs = 0
  │
  │  MSTPONG received → reset missed_pongs = 0
  │  RPTPING timer fires → send RPTPING, missed_pongs += 1
  │  missed_pongs > 5 → log WARNING "master lost" → DISCONNECTED → backoff → retry
  │  DMRD received from master → pass to CallTranslator.hbp_voice_received()
  │  RPTCL received from master → log INFO → DISCONNECTED
  │
  │  [SIGTERM received] → send RPTCL → DISCONNECTED → exit
  │  [IPSC peer lost, TRACKING mode] → send RPTCL → DISCONNECTED
  │  [IPSC peer registered, TRACKING mode, was DISCONNECTED] → initiate connection
  ▼
DISCONNECTED → retry with exponential backoff: 5s → 10s → 20s → 40s → 60s (cap)
```

**RPTC (config blob) format — 302 bytes total:**
```
Bytes  0– 3:  b'RPTC'
Bytes  4– 7:  Repeater ID (4 bytes big-endian)
Bytes  8–15:  Callsign (8 bytes, space-padded right, ASCII)
Bytes 16–24:  RX Frequency (9 bytes, ASCII digits, Hz, zero-padded left)
Bytes 25–33:  TX Frequency (9 bytes, ASCII digits, Hz, zero-padded left)
Bytes 34–35:  TX Power (2 bytes, ASCII decimal, zero-padded left)
Bytes 36–38:  Color Code (3 bytes, ASCII — send "01"; not operationally used by most masters)
Bytes 39–46:  Latitude (8 bytes, ASCII float, e.g. "38.8500 ")
Bytes 47–55:  Longitude (9 bytes, ASCII float, e.g. "-097.6114")
Bytes 56–58:  Height (3 bytes, ASCII decimal, meters, zero-padded left)
Bytes 59–78:  Location (20 bytes, space-padded right, ASCII)
Bytes 79–98:  Description (20 bytes, space-padded right, ASCII)
Bytes 99–122: URL (24 bytes, space-padded right, ASCII)
Bytes 123–162: Software ID (40 bytes, space-padded right, ASCII) — use "ipsc2hbp"
Bytes 163–202: Package ID (40 bytes, space-padded right, ASCII) — use version string
```

> All fields must be exactly the right width. Truncate if too long, space-pad if too short. Some masters (particularly BrandMeister) are strict about RPTC field widths and will reject malformed blobs.

### 5.3 Voice Superframe Sequence Tracking

Within a call, IPSC delivers voice bursts as `SLOT1_VOICE` or `SLOT2_VOICE` without distinguishing superframe position. HBP requires the flags byte to reflect the position within the DMR voice superframe (A/sync through F). Position is inferred by counting bursts since `VOICE_HEAD`.

```python
# burst_count is incremented for each SLOT1_VOICE / SLOT2_VOICE received
# position = burst_count % 6:
#   0 → VoiceSync burst (DMR "F" burst carrying sync pattern)
#   1 → Voice burst A, seq=0
#   2 → Voice burst B, seq=1  ← embed LC fragment 1
#   3 → Voice burst C, seq=2  ← embed LC fragment 2
#   4 → Voice burst D, seq=3  ← embed LC fragment 3
#   5 → Voice burst E, seq=4  ← embed LC fragment 4
```

For positions 2–5 (DMR bursts B–E), insert the precomputed embedded LC fragments from `build_embedded_lc()` into the appropriate bit positions of the 33-byte payload before sending. The `encode_emblc()` function returns fragments keyed as `{1: ..., 2: ..., 3: ..., 4: ...}` corresponding to bursts B through E respectively.

> **⚠️ TEST CHECKPOINT**: The exact sync/voice position mapping should be verified against a known-good HBP stream capture (e.g., from an MMDVM hotspot) during Phase 6 testing.

---

## 6. Bidirectional Translation — Step By Step

### 6.1 Outbound Path: IPSC → HBP

1. IPSC datagram received; auth check passes (or auth disabled)
2. Opcode is `GROUP_VOICE` (0x80)
3. Parse: `peer_id` (bytes 1–4), `src_sub` (bytes 5–8), `dst_group` (bytes 9–12), `burst_type` (byte 30), `raw_payload` (bytes 31–64, 34 bytes)
4. Determine timeslot: `ts = 2 if (burst_type & 0x80) else 1`; for `VOICE_HEAD`/`VOICE_TERM`, read from IPSC header (see note in section 4.1)
5. Apply byte swap: `dmr_payload = swap_payload_bytes(raw_payload)` → 34 bytes → take first 33 bytes for HBP
6. Pass `(src_sub, dst_group, ts, burst_type, dmr_payload_33)` to `CallTranslator.ipsc_voice_received()`

In `CallTranslator.ipsc_voice_received()`:

- **If `VOICE_HEAD`**:
  - Decode LC: `lc = decode_lc_from_voice_head(dmr_payload_33)`
  - If `lc is None`: log WARNING, drop entire call, return
  - Generate stream ID: `stream_id = os.urandom(4)`
  - Build embedded LC: `emb_lc = build_embedded_lc(lc)`
  - Initialize call state for this timeslot; set `burst_count = 0`
  - Build and send HBP DMRD voice head packet via HBP protocol
  - Log call start at INFO level

- **If `SLOT1_VOICE` or `SLOT2_VOICE`**:
  - If no active call on this timeslot: drop (late packet, no state), return
  - Increment `burst_count`, compute `position = burst_count % 6`
  - If `position` in 2–5: embed appropriate LC fragment into `dmr_payload_33`
  - Build and send HBP DMRD voice packet
  - Update `last_burst_time`

- **If `VOICE_TERM`**:
  - If no active call on this timeslot: drop, return
  - Build and send HBP DMRD voice terminator packet
  - Log call end with duration at INFO level
  - Clear call state for this timeslot

### 6.2 Inbound Path: HBP → IPSC

1. HBP DMRD packet received (only process if HBP state is `CONNECTED`)
2. Verify magic: `data[0:4] == b'DMRD'`
3. Parse: `seq` (byte 4), `src_id` (bytes 5–7), `dst_id` (bytes 8–10), `rptr_id` (bytes 11–14), `flags` (byte 15), `stream_id` (bytes 16–19), `dmr_payload_33` (bytes 20–52)
4. Determine `timeslot` from flags byte; determine `burst_type` per section 4.4
5. Pass to `CallTranslator.hbp_voice_received()`

In `CallTranslator.hbp_voice_received()`:

- If TRACKING mode and IPSC peer not registered: drop, return
- Build IPSC GROUP_VOICE packet:
  - Opcode: `0x80`
  - Source peer ID: `ipsc_master_id` (we are the IPSC node injecting this traffic)
  - Source subscriber: `src_id` from DMRD (3 bytes, zero-pad left to 4 bytes)
  - Destination group: `dst_id` from DMRD (3 bytes, zero-pad left to 4 bytes)
  - Burst type byte: derived from HBP flags (section 4.4)
  - DMR payload: `swap_payload_bytes(b'\x00' + dmr_payload_33)` → 34 bytes
- Add auth digest if enabled
- Send via `IPSCProtocol.send_to_peer()`

---

## 7. Configuration File

**Default location**: `/etc/ipsc2hbp/ipsc2hbp.cfg`

**CLI override**: `-c /path/to/file`

**Format**: INI, parsed by Python `configparser`

```ini
[GLOBAL]
# Logging level: DEBUG | INFO | WARNING | ERROR
# DEBUG is very noisy (logs every burst). Use INFO for normal operation.
log_level: INFO

[IPSC]
# IP address to bind the IPSC master UDP socket
# Use 0.0.0.0 to listen on all interfaces
bind_ip: 0.0.0.0

# UDP port to listen on (must match repeater's codeplug IPSC master port)
bind_port: 50000

# Radio ID for this translator's IPSC master node (NOT the repeater's ID)
# This is the ID the Pi presents in MASTER_REG_REPLY and when injecting inbound traffic
# Must be a valid 7-8 digit DMR ID or a unique value for private/closed systems
ipsc_master_id: 9999999

# Radio ID of the Motorola repeater (the IPSC peer)
# This is also used as the HBP Repeater ID by default (see hbp_repeater_id below)
ipsc_peer_id: 3120000

# STRICT: reject registration if peer radio ID != ipsc_peer_id (log WARNING and drop)
# LOOSE:  accept any peer, log WARNING if ID doesn't match configured value
registration_mode: STRICT

# IPSC authentication
auth_enabled: False

# Auth key: hex string, up to 40 hex characters (20 bytes)
# Shorter keys are automatically left-zero-padded to 40 hex chars
# Must match exactly what is programmed in the repeater's codeplug
auth_key:

# Watchdog timeout in seconds: how long to wait without a keep-alive before
# declaring the repeater lost. Set generously to accommodate variable
# firewall open timer settings programmed in the repeater.
# Recommended: 60 seconds
keepalive_watchdog: 60

[HBP]
# HBP master server to connect to
master_ip: 127.0.0.1
master_port: 62031

# HBP Repeater ID used in all HBP packets (RPTL, RPTK, RPTC, DMRD)
# Default (comment out or set to 0): use ipsc_peer_id — this is the recommended
# "passthrough" mode and enforces the translator philosophy
# hbp_repeater_id: 3120000

# If hbp_repeater_id is set to a different value than ipsc_peer_id:
# MATCH: refuse to start if they don't match (enforces passthrough)
# ALLOW: allow different values (flexible mode for special deployments)
id_match: MATCH

# Passphrase for the HBP master (must match master's configuration)
passphrase: passw0rd

# HBP connection mode:
# TRACKING:   Connect HBP only when a valid IPSC peer is registered.
#             Disconnect HBP when IPSC peer is lost.
#             Recommended for most deployments.
# PERSISTENT: Maintain HBP connection regardless of IPSC peer state.
#             Voice is only forwarded when both sides are active.
#             Useful to keep the repeater appearing "online" on network dashboards.
hbp_mode: TRACKING

# RPTC configuration fields (sent to HBP master during handshake)
callsign: W1ABC
rx_freq: 444000000
tx_freq: 449000000
tx_power: 25
latitude: 38.8500
longitude: -097.6114
height: 10
location: Smalltown KS
description: IPSC-HBP Bridge
url:
software_id: ipsc2hbp
package_id: 1.0.0
```

---

## 8. Logging Specification

**Transport**: stderr only. Systemd captures stderr into journald automatically when run as a service. No separate log file handler required.

**Format**: `%(asctime)s %(levelname)s [%(name)s] %(message)s`

**Log levels by event:**

| Event | Level |
|---|---|
| Startup / shutdown | INFO |
| SIGTERM received | INFO |
| IPSC peer registered | INFO |
| IPSC peer lost (watchdog or DE_REG) | WARNING |
| IPSC peer rejected — STRICT mode ID mismatch | WARNING |
| IPSC auth failure | WARNING |
| HBP connected (MSTACK received) | INFO |
| HBP disconnected (missed pongs) | WARNING |
| HBP bad passphrase (RPTNAK) | ERROR |
| HBP reconnect attempt | INFO |
| Call start (VOICE_HEAD received) | INFO |
| Call end (VOICE_TERM received or watchdog) | INFO |
| Call dropped — LC decode failure | WARNING |
| Individual voice burst received/sent | DEBUG |
| XCMP/XNL packet received (silently ignored) | DEBUG |
| Unknown opcode received | DEBUG |
| Inbound DMRD received from master | DEBUG |

---

## 9. Scope Boundaries

The following are permanently out of scope for this project.

| Out of Scope | Reason |
|---|---|
| Timeslot (TS) translation or rewriting | Intentional design constraint — translator only |
| TGID translation or rewriting | Intentional design constraint — translator only |
| Private voice calls | Group voice only in v1 |
| Data calls (GROUP_DATA, PVT_DATA) | Not translated; dropped silently |
| XNL / XCMP processing | Never. These can damage repeaters. Not implemented. |
| Multiple IPSC peers | Not supported (see Known Limitations) |
| Multiple HBP upstream masters | Intentional — single upstream only |
| HBP master mode | This is always an HBP peer |
| IPSC peer mode | This is always the IPSC master |
| Conference bridging / routing | Not this tool |
| ACL / filtering | Upstream master's responsibility |
| Alias CSV lookups | Not needed |
| Reporting socket / dashboard | Not included |

---

## 10. Known Limitations and Future Work

| Item | Notes |
|---|---|
| Private voice calls | Not translated. Dropped silently. |
| Data calls | Not translated. Dropped silently. |
| Multiple IPSC peers | Not supported. Motorola RDAC, remote programming software, and other XNL/XCMP-speaking console applications join IPSC as additional peers and are incompatible with this implementation. A future multi-peer mode could accommodate them for keep-alive/presence purposes only. |
| RDAC / XNL / XCMP | Requires multi-peer support. Out of scope. |
| LC decode failure recovery | v1 drops the call. Future enhancement: synthesize LC from known header fields (late-entry handling). |
| Payload size boundary (34↔33 bytes) | Must be verified with live hardware capture — marked as test checkpoint. |
| Exact IPSC field offsets | Must be verified against DMRlink source or live capture — marked as test checkpoint. |

---

## 11. systemd Unit File

**Location**: `/etc/systemd/system/ipsc2hbp.service`

```ini
[Unit]
Description=IPSC to HomeBrew Protocol Translator
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=ipsc2hbp
Group=ipsc2hbp
ExecStart=/opt/ipsc2hbp/venv/bin/python /opt/ipsc2hbp/ipsc2hbp.py -c /etc/ipsc2hbp/ipsc2hbp.cfg
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ipsc2hbp

[Install]
WantedBy=multi-user.target
```

---

## 12. Test Tools

### `tests/fake_ipsc_peer.py`

Simulates a Motorola repeater connecting to the IPSC master.

**Arguments**: `--host`, `--port`, `--radio-id`, `--auth-key`, `--burst-count`

**Behavior**:
1. Send `MASTER_REG_REQ` to the translator
2. Wait for `MASTER_REG_REPLY` and `PEER_LIST_REPLY`
3. Send periodic `MASTER_ALIVE_REQ` every 5 seconds
4. On stdin command: generate a synthetic GROUP_VOICE burst sequence (VOICE_HEAD + N voice bursts + VOICE_TERM) using valid BPTC-encoded LC built from configurable source/destination IDs

### `tests/fake_hbp_master.py`

Simulates an HBP master (BrandMeister, HBlink4, etc.).

**Arguments**: `--port`, `--passphrase`

**Behavior**:
1. Listen for `RPTL` → respond `RPTACK` → expect `RPTK` → validate passphrase → `RPTACK` or `RPTNAK` → expect `RPTC` → log config fields → respond `MSTACK`
2. Respond to `RPTPING` with `MSTPONG`
3. Log all received `DMRD` packets with decoded fields (src, dst, ts, frame_type, seq, stream_id) to stdout
4. On stdin command: inject a synthetic `DMRD` call sequence toward the translator (exercises the inbound/HBP→IPSC path)

---

## 13. Build Order and Testing Sequence

Implement and test in this exact order. **Do not proceed to the next phase until the current phase passes.**

### Phase 1: Foundation

1. `ipsc/const.py` — constants only, no logic
2. `hbp/const.py` — constants only, no logic
3. `config.py` — parse and validate config, return typed Config dataclass
   - Unit test: load sample config, verify all fields parse correctly, verify validation rejects missing required fields
4. `translate/lc.py` — LC encode/decode wrappers over dmr_utils3
   - Unit test: encode a known LC, decode it back, verify round-trip

### Phase 2: IPSC Stack

5. `ipsc/protocol.py` — IPSC master: registration, keep-alive, watchdog; no translation yet (stub CallTranslator callbacks)
6. `tests/fake_ipsc_peer.py`
7. **Integration test**: start `ipsc2hbp.py` with HBP disabled (stub), start fake IPSC peer. Verify:
   - Registration handshake completes in logs
   - Keep-alive responses are sent
   - Watchdog fires after configured timeout and logs WARNING
   - Re-registration after watchdog works without restart

### Phase 3: HBP Stack

8. `hbp/protocol.py` — HBP peer: full handshake state machine, keep-alive, reconnect/backoff
9. `tests/fake_hbp_master.py`
10. **Integration test**: start `ipsc2hbp.py` with IPSC disabled (stub), start fake HBP master. Verify:
    - Full handshake (RPTL → RPTACK → RPTK → RPTACK → RPTC → MSTACK) completes
    - RPTPING/MSTPONG exchange in logs
    - Reconnect triggers after master drops (stop fake master, verify backoff timing)
    - RPTCL sent on SIGTERM

### Phase 4: Translation — Outbound

11. `translate/bridge.py` — outbound path only (IPSC → HBP)
12. `ipsc2hbp.py` — wire all components together (full wiring for the first time)
13. **Integration test (outbound)**: both test tools running. Fake IPSC peer sends a GROUP_VOICE burst sequence. Verify:
    - Fake HBP master logs correctly structured DMRD packets
    - Source/destination IDs match what was sent
    - Flag bytes correctly encode timeslot, frame type, and voice sequence
    - Stream ID is consistent across all bursts in a call
    - Sequence number increments correctly
    - Call start and end logged at INFO

### Phase 5: Translation — Inbound

14. Extend `translate/bridge.py` — inbound path (HBP → IPSC)
15. **Integration test (inbound)**: fake HBP master injects a DMRD call sequence. Verify:
    - Fake IPSC peer receives correctly formed GROUP_VOICE packets
    - Byte-swapped payload reconstructed correctly
    - Source peer ID in received packets is `ipsc_master_id`, not the HBP source

### Phase 6: Resilience

16. Test TRACKING mode: IPSC peer goes offline → HBP sends RPTCL → HBP disconnects. IPSC peer re-registers → HBP reconnects automatically.
17. Test PERSISTENT mode: IPSC peer goes offline → HBP stays connected → no voice forwarded while IPSC down.
18. Test SIGTERM graceful shutdown: RPTCL sent to HBP master, clean exit.
19. Test HBP master dropout and reconnect: verify backoff timing is correct (5/10/20/40/60s).
20. Test burst watchdog: start a call, stop sending bursts (without VOICE_TERM), verify watchdog synthesizes terminator after 360ms.

### Phase 7: Hardware

21. Replace fake IPSC peer with real Motorola repeater
22. Replace fake HBP master with local HBlink4 instance
23. Make a voice call through the repeater; verify audio arrives on HBlink4
24. Inject a call from HBlink4; verify audio arrives on the repeater
25. Capture traffic with Wireshark; verify payload byte offsets match spec (resolve test checkpoints)

---

## 14. Environment and Installation

**Target platform**: Raspberry Pi OS Bookworm or Bullseye (ARM or x86). Also tested on Debian-based x86 for development.

**Python**: 3.8+ minimum. Must run in a virtual environment to isolate from system Python.

**`requirements.txt`**:
```
dmr-utils3>=0.1.29
bitarray>=2.5.0
```

**Installation paths**:
- Application: `/opt/ipsc2hbp/`
- Virtual environment: `/opt/ipsc2hbp/venv/`
- Config: `/etc/ipsc2hbp/ipsc2hbp.cfg`
- systemd unit: `/etc/systemd/system/ipsc2hbp.service`

**`install.sh` must**:
1. Create system user `ipsc2hbp` (no login shell, no home directory)
2. Create `/opt/ipsc2hbp/` and `/etc/ipsc2hbp/`
3. Copy application files to `/opt/ipsc2hbp/`
4. Create venv: `python3 -m venv /opt/ipsc2hbp/venv`
5. Install pip requirements inside venv: `/opt/ipsc2hbp/venv/bin/pip install -r requirements.txt`
6. Copy sample config: `cp ipsc2hbp.cfg.sample /etc/ipsc2hbp/ipsc2hbp.cfg.sample`
7. Install systemd unit and run `systemctl daemon-reload`
8. Print: `"Edit /etc/ipsc2hbp/ipsc2hbp.cfg before starting the service with: systemctl start ipsc2hbp"`

> **Note**: `bitarray` has a C extension. On Raspberry Pi, the first `pip install` will compile it. This requires `python3-dev` and `gcc`. The install script should check for these and install them via `apt` if missing.

---

## 15. Attribution

This project is a clean-room Python 3 reimplementation inspired by the architecture of:
- **DMRlink** (IPSC stack) by Cortney T. Buffington, N0MJS — https://github.com/n0mjs710/DMRlink
- **HBlink** (HomeBrew Repeater Protocol stack) by Cortney T. Buffington, N0MJS — https://github.com/n0mjs710/hblink
- **dmr_utils** / **dmr_utils3** by Cortney T. Buffington, N0MJS — https://github.com/n0mjs710/dmr_utils

The HomeBrew Repeater Protocol is documented by Jonathan Naylor G4KLX, Hans Barthen DL5DI, and Torsten Schultze DG1HT.

The IPSC protocol is a reverse-engineered interpretation of the Motorola MOTOTRBO IPSC protocol, used here for amateur radio interoperability purposes only.

---

*End of specification — v1.0*
