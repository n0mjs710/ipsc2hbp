#!/usr/bin/env python3
"""
Fake IPSC peer — simulates a Motorola MOTOTRBO repeater.

Connects to ipsc2hbp acting as the IPSC peer (repeater side).
Sends MASTER_REG_REQ, responds to PEER_LIST_REPLY, sends periodic
MASTER_ALIVE_REQ keepalives.  On stdin 'call' command generates a
synthetic GROUP_VOICE burst sequence.

Usage:
    python tests/fake_ipsc_peer.py [--host HOST] [--port PORT]
        [--radio-id ID] [--tgid TGID] [--src-id SRC]
        [--auth-key HEXKEY] [--burst-count N]
"""

import argparse
import asyncio
import binascii
import hmac as hmac_mod
import os
import socket
import stat
import struct
import sys
from hashlib import sha1
from time import time

sys.stdout.reconfigure(line_buffering=True)

# Allow running from the project root without installing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipsc.const import (
    MASTER_REG_REQ, MASTER_REG_REPLY,
    PEER_LIST_REPLY, MASTER_ALIVE_REQ, MASTER_ALIVE_REPLY,
    DE_REG_REQ, DE_REG_REPLY, PEER_LIST_REQ,
    GROUP_VOICE, VOICE_HEAD, VOICE_TERM, SLOT1_VOICE, SLOT2_VOICE,
    IPSC_VER, TS_CALL_MSK, AUTH_DIGEST_LEN,
    VOICE_CALL_MSK, DATA_CALL_MSK,
)

# Peer mode byte: operational (0x40) + digital (0x20) + TS1 on (0x08) + TS2 on (0x02)
_PEER_MODE  = b'\x6A'
# Peer flags: voice + data calls supported (no auth bit, no master bit)
_PEER_FLAGS = b'\x00\x00\x00\x0C'  # VOICE_CALL_MSK | DATA_CALL_MSK


def _auth_suffix(key: bytes, packet: bytes) -> bytes:
    if not key:
        return b''
    return binascii.unhexlify(hmac_mod.new(key, packet, sha1).hexdigest()[:20])


def _strip_auth(key: bytes, data: bytes):
    """Strip and validate auth digest. Returns stripped data or None on failure."""
    if not key:
        return data
    if len(data) <= AUTH_DIGEST_LEN:
        return None
    payload  = data[:-AUTH_DIGEST_LEN]
    received = data[-AUTH_DIGEST_LEN:]
    expected = binascii.unhexlify(hmac_mod.new(key, payload, sha1).hexdigest()[:20])
    if received != expected:
        return None
    return payload


def _make_voice_burst(radio_id: int, src_id: int, tgid: int,
                      burst_type: int, timeslot: int,
                      seq: int) -> bytes:
    """
    Build a minimal GROUP_VOICE packet with a zeroed DMR payload.

    Layout confirmed from DMRlink IPSC_Bridge.py dumpIPSCFrame():
      [0]      opcode   0x80
      [1:5]    peer_id  (4 bytes)
      [5]      ipsc_seq (1 byte)
      [6:9]    src_sub  (3 bytes)
      [9:12]   dst_sub  (3 bytes)
      [12]     call_type
      [13:17]  call_ctrl (4 bytes, zeroed)
      [17]     call_info (TS + END bits)
      [18:30]  RTP header (12 bytes, zeroed)
      [30]     burst_type (payload type)
      [31:65]  34-byte DMR payload (zeroed)
    """
    peer_id_b = radio_id.to_bytes(4, 'big')
    src_b     = src_id.to_bytes(3, 'big')
    tgid_b    = tgid.to_bytes(3, 'big')

    call_info = TS_CALL_MSK if timeslot == 2 else 0x00
    rtp_seq   = struct.pack('>H', seq)

    pkt = (
        bytes([GROUP_VOICE])
        + peer_id_b            # bytes 1-4:  peer radio ID
        + bytes([seq & 0xFF])  # byte 5:     IPSC sequence
        + src_b                # bytes 6-8:  source subscriber (3 bytes)
        + tgid_b               # bytes 9-11: destination group (3 bytes)
        + b'\x00'              # byte 12:    call type
        + b'\x00\x00\x00\x00' # bytes 13-16: call ctrl info
        + bytes([call_info])   # byte 17:    call info (TS bit)
        + b'\x80\x00'         # bytes 18-19: RTP byte1, byte2
        + rtp_seq              # bytes 20-21: RTP seq
        + b'\x00\x00\x00\x00' # bytes 22-25: RTP timestamp
        + b'\x00\x00\x00\x00' # bytes 26-29: RTP SSRC
        + bytes([burst_type])  # byte 30:    payload/burst type
        + b'\x00' * 34         # bytes 31-64: 34-byte DMR payload (zeroed)
    )
    return pkt


class FakeIPSCPeer(asyncio.DatagramProtocol):

    def __init__(self, args):
        self._args      = args
        self._radio_id  = args.radio_id
        self._radio_id_b = args.radio_id.to_bytes(4, 'big')
        self._auth_key  = args.auth_key
        self._host      = args.host
        self._port      = args.port
        self._transport = None
        self._registered = False
        self._seq       = 0
        self._ka_task   = None
        self._stdin_task = None

    def connection_made(self, transport):
        self._transport = transport
        print(f'[fake-peer] UDP socket ready — sending MASTER_REG_REQ to {self._host}:{self._port}')
        self._send_reg_req()
        loop = asyncio.get_event_loop()
        self._ka_task    = loop.create_task(self._keepalive_loop())
        if self._args.auto_call:
            self._stdin_task = loop.create_task(self._auto_call_loop())
        else:
            self._stdin_task = loop.create_task(self._stdin_loop())

    def connection_lost(self, exc):
        print(f'[fake-peer] Connection lost: {exc}')

    def error_received(self, exc):
        print(f'[fake-peer] Socket error: {exc}')

    def datagram_received(self, data: bytes, addr):
        if self._auth_key:
            data = _strip_auth(self._auth_key, data)
            if data is None:
                print('[fake-peer] Auth failure on received packet — dropped')
                return

        if not data:
            return

        opcode = data[0]

        if opcode == MASTER_REG_REPLY:
            num_peers = struct.unpack('>H', data[10:12])[0] if len(data) >= 12 else '?'
            master_id = int.from_bytes(data[1:5], 'big')
            print(f'[fake-peer] MASTER_REG_REPLY received — master_id={master_id}  num_peers={num_peers}')
            self._registered = True

        elif opcode == PEER_LIST_REPLY:
            list_len = struct.unpack('>H', data[5:7])[0] if len(data) >= 7 else 0
            n_peers  = list_len // 11
            print(f'[fake-peer] PEER_LIST_REPLY received — {n_peers} peer(s) listed')

        elif opcode == MASTER_ALIVE_REPLY:
            print('[fake-peer] MASTER_ALIVE_REPLY received')

        elif opcode == DE_REG_REPLY:
            print('[fake-peer] DE_REG_REPLY received')

        elif opcode == GROUP_VOICE:
            if len(data) >= 31:
                src    = int.from_bytes(data[6:9], 'big')
                dst    = int.from_bytes(data[9:12], 'big')
                btype  = data[30]
                ts     = 2 if (data[17] & TS_CALL_MSK) else 1
                print(f'[fake-peer] GROUP_VOICE received  burst=0x{btype:02x}  src={src}  tg={dst}  ts={ts}')
            else:
                print(f'[fake-peer] GROUP_VOICE received  len={len(data)} (too short)')

        else:
            print(f'[fake-peer] Unknown opcode 0x{opcode:02x} received')

    # ------------------------------------------------------------------
    # Packet helpers
    # ------------------------------------------------------------------

    def _send(self, pkt: bytes):
        out = pkt + _auth_suffix(self._auth_key, pkt)
        self._transport.sendto(out, (self._host, self._port))

    def _send_reg_req(self):
        pkt = (
            bytes([MASTER_REG_REQ])
            + self._radio_id_b
            + _PEER_MODE
            + _PEER_FLAGS
            + IPSC_VER
        )
        self._send(pkt)
        print('[fake-peer] MASTER_REG_REQ sent')

    def _send_alive(self):
        pkt = (
            bytes([MASTER_ALIVE_REQ])
            + self._radio_id_b
            + _PEER_MODE
            + _PEER_FLAGS
            + IPSC_VER
        )
        self._send(pkt)
        print('[fake-peer] MASTER_ALIVE_REQ sent')

    def _send_dereg(self):
        pkt = bytes([DE_REG_REQ]) + self._radio_id_b
        self._send(pkt)
        print('[fake-peer] DE_REG_REQ sent')

    def _send_call(self, timeslot: int = 1):
        burst_count = self._args.burst_count
        src_id      = self._args.src_id
        tgid        = self._args.tgid

        print(f'[fake-peer] Sending call: src={src_id} tgid={tgid} ts={timeslot} bursts={burst_count}')

        # VOICE_HEAD
        pkt = _make_voice_burst(self._radio_id, src_id, tgid,
                                VOICE_HEAD, timeslot, self._seq)
        self._send(pkt)
        self._seq = (self._seq + 1) & 0xFF
        print('[fake-peer]   → VOICE_HEAD')

        # Voice bursts (SLOT1_VOICE or SLOT2_VOICE)
        voice_type = SLOT2_VOICE if timeslot == 2 else SLOT1_VOICE
        for i in range(burst_count):
            pkt = _make_voice_burst(self._radio_id, src_id, tgid,
                                    voice_type, timeslot, self._seq)
            self._send(pkt)
            self._seq = (self._seq + 1) & 0xFF

        print(f'[fake-peer]   → {burst_count} voice bursts')

        # VOICE_TERM
        pkt = _make_voice_burst(self._radio_id, src_id, tgid,
                                VOICE_TERM, timeslot, self._seq)
        self._send(pkt)
        self._seq = (self._seq + 1) & 0xFF
        print('[fake-peer]   → VOICE_TERM')

    # ------------------------------------------------------------------
    # Async tasks
    # ------------------------------------------------------------------

    async def _auto_call_loop(self):
        """Send a call on each timeslot then exit — used for background testing."""
        await asyncio.sleep(2)   # wait for registration
        if self._registered:
            self._send_call(timeslot=1)
            await asyncio.sleep(0.5)
            self._send_call(timeslot=2)
        loop = asyncio.get_event_loop()
        await asyncio.sleep(2)
        loop.stop()

    async def _keepalive_loop(self):
        while True:
            await asyncio.sleep(5)
            if self._registered:
                self._send_alive()

    async def _stdin_loop(self):
        try:
            mode = os.fstat(sys.stdin.fileno()).st_mode
            if not (stat.S_ISFIFO(mode) or sys.stdin.isatty()):
                return
        except Exception:
            return
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        print('[fake-peer] Commands: call [ts1|ts2] | dereg | quit')
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode().strip().lower()
                if cmd in ('call', 'call ts1'):
                    self._send_call(timeslot=1)
                elif cmd == 'call ts2':
                    self._send_call(timeslot=2)
                elif cmd == 'dereg':
                    self._send_dereg()
                elif cmd in ('quit', 'exit', 'q'):
                    self._send_dereg()
                    await asyncio.sleep(0.2)
                    loop.stop()
                else:
                    print('[fake-peer] Unknown command. Try: call | call ts2 | dereg | quit')
            except Exception as exc:
                print(f'[fake-peer] stdin error: {exc}')
                break


def main():
    ap = argparse.ArgumentParser(description='Fake IPSC peer (simulates Motorola repeater)')
    ap.add_argument('--host',        default='127.0.0.1', help='ipsc2hbp host (default 127.0.0.1)')
    ap.add_argument('--port',        default=50000, type=int, help='ipsc2hbp IPSC port (default 50000)')
    ap.add_argument('--radio-id',    default=3120000, type=int, dest='radio_id',
                    help='Repeater radio ID (default 3120000)')
    ap.add_argument('--src-id',      default=3120001, type=int, dest='src_id',
                    help='Source subscriber ID for test calls (default 3120001)')
    ap.add_argument('--tgid',        default=91, type=int, help='Destination TGID (default 91)')
    ap.add_argument('--auth-key',    default='', dest='auth_key',
                    help='Auth key as hex string (empty = no auth)')
    ap.add_argument('--burst-count', default=6, type=int, dest='burst_count',
                    help='Voice bursts per test call (default 6)')
    ap.add_argument('--auto-call', action='store_true', dest='auto_call',
                    help='Send TS1+TS2 calls automatically after registration then exit')
    args = ap.parse_args()

    # Parse auth key
    if args.auth_key:
        try:
            args.auth_key = binascii.unhexlify(args.auth_key.strip().zfill(40))
        except Exception as e:
            sys.exit(f'Invalid auth key: {e}')
    else:
        args.auth_key = b''

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print(f'[fake-peer] Starting — radio_id={args.radio_id}  target={args.host}:{args.port}')

    coro = loop.create_datagram_endpoint(
        lambda: FakeIPSCPeer(args),
        remote_addr=(args.host, args.port),
    )

    try:
        loop.run_until_complete(coro)
        loop.run_forever()
    except KeyboardInterrupt:
        print('\n[fake-peer] Interrupted')
    finally:
        loop.close()


if __name__ == '__main__':
    main()
