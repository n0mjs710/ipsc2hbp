#!/usr/bin/env python3
"""
Fake HBP master — simulates a BrandMeister/HBlink master server.

Listens for an HBP peer connection, performs the full handshake,
sends periodic MSTPONG responses, and optionally injects test DMRD frames.

Usage:
    python tests/fake_hbp_master.py [--port PORT] [--passphrase PASS]

Stdin commands (once a peer is connected):
    dmrd          — send one synthetic DMRD frame to the peer
    nak           — send MSTNAK to peer (simulates server rejection)
    close         — send MSTCL to peer (simulates server-initiated close)
    quit          — shut down
"""

import argparse
import asyncio
import os
import struct
import sys
from hashlib import sha256

# Force line-buffered stdout so output appears even when redirected to a file
sys.stdout.reconfigure(line_buffering=True)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hbp.const import (
    HBPF_RPTL, HBPF_RPTK, HBPF_RPTC, HBPF_RPTPING, HBPF_RPTCL,
    HBPF_RPTACK, HBPF_MSTNAK, HBPF_MSTPONG, HBPF_MSTCL,
    HBPF_DMRD, DMRD_LEN,
    HBPF_TGID_TS2, HBPF_FRAMETYPE_VOICESYNC,
)


class FakeHBPMaster(asyncio.DatagramProtocol):

    def __init__(self, args):
        self._passphrase = args.passphrase.encode()
        self._transport  = None
        self._peer_addr  = None
        self._peer_id    = None
        self._state      = 'IDLE'   # IDLE → WAIT_RPTK → WAIT_RPTC → CONNECTED
        self._salt       = os.urandom(4)
        self._stdin_task = None

    def connection_made(self, transport):
        self._transport = transport
        host, port = transport.get_extra_info('sockname')
        print(f'[fake-master] Listening on {host}:{port}')
        loop = asyncio.get_event_loop()
        self._stdin_task = loop.create_task(self._stdin_loop())

    def connection_lost(self, exc):
        print(f'[fake-master] Connection lost: {exc}')

    def error_received(self, exc):
        print(f'[fake-master] Socket error: {exc}')

    def datagram_received(self, data: bytes, addr):
        if len(data) < 4:
            return

        # Longest-prefix dispatch
        if len(data) >= 4 and data[:4] == HBPF_RPTL:
            self._on_rptl(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTK:
            self._on_rptk(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTC:
            self._on_rptc(data, addr)
        elif len(data) >= 7 and data[:7] == HBPF_RPTPING:
            self._on_rptping(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTCL:
            peer_id = int.from_bytes(data[4:8], 'big') if len(data) >= 8 else 0
            print(f'[fake-master] ← RPTCL from peer_id={peer_id} — peer disconnected')
            self._state = 'IDLE'
            self._peer_addr = None
            self._peer_id   = None
        elif len(data) >= 4 and data[:4] == HBPF_DMRD:
            self._on_dmrd(data, addr)
        else:
            print(f'[fake-master] Unknown packet cmd={data[:4]}  len={len(data)}')

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _on_rptl(self, data: bytes, addr):
        if len(data) < 8:
            print('[fake-master] RPTL too short')
            return
        peer_id = data[4:8]
        peer_id_int = int.from_bytes(peer_id, 'big')
        print(f'[fake-master] ← RPTL  peer_id={peer_id_int}  from {addr}')
        self._peer_addr = addr
        self._peer_id   = peer_id
        self._state     = 'WAIT_RPTK'
        self._salt      = os.urandom(4)
        # Challenge: RPTACK + salt(4) only — confirmed from hblink4 _handle_repeater_login
        reply = HBPF_RPTACK + self._salt
        self._send(reply, addr)
        print(f'[fake-master] → RPTACK+salt  salt=0x{self._salt.hex()}')

    def _on_rptk(self, data: bytes, addr):
        if self._state != 'WAIT_RPTK':
            print(f'[fake-master] RPTK in unexpected state {self._state}')
            return
        if len(data) < 40:
            print('[fake-master] RPTK too short')
            return
        peer_id   = data[4:8]
        recv_hash = data[8:40]
        # Verify
        expected = bytes.fromhex(sha256(self._salt + self._passphrase).hexdigest())
        if recv_hash == expected:
            print('[fake-master] ← RPTK  hash OK')
            reply = HBPF_RPTACK + peer_id
            self._send(reply, addr)
            print('[fake-master] → RPTACK (auth accepted)')
            self._state = 'WAIT_RPTC'
        else:
            print('[fake-master] ← RPTK  hash MISMATCH — sending MSTNAK')
            self._send(HBPF_MSTNAK + peer_id, addr)
            self._state = 'IDLE'

    def _on_rptc(self, data: bytes, addr):
        if self._state != 'WAIT_RPTC':
            print(f'[fake-master] RPTC in unexpected state {self._state}')
            return
        peer_id = data[4:8]
        callsign = data[8:16].rstrip(b'\x00').decode(errors='replace')
        print(f'[fake-master] ← RPTC  {len(data)} bytes  callsign={callsign!r}')
        reply = HBPF_RPTACK + peer_id
        self._send(reply, addr)
        print('[fake-master] → RPTACK (config accepted) — CONNECTED')
        self._state = 'CONNECTED'

    def _on_rptping(self, data: bytes, addr):
        if self._state != 'CONNECTED':
            return
        peer_id = data[7:11] if len(data) >= 11 else self._peer_id
        self._send(HBPF_MSTPONG + (peer_id or b'\x00\x00\x00\x00'), addr)
        log_peer = int.from_bytes(peer_id, 'big') if peer_id else '?'
        print(f'[fake-master] ← RPTPING → MSTPONG  peer_id={log_peer}')

    def _on_dmrd(self, data: bytes, addr):
        if len(data) >= 20:
            seq     = data[4]
            src_id  = int.from_bytes(data[5:8], 'big')
            dst_id  = int.from_bytes(data[8:11], 'big')
            flags   = data[15]
            ts      = 2 if (flags & 0x80) else 1
            stream  = data[16:20].hex()
            print(f'[fake-master] ← DMRD  seq={seq} src={src_id} dst={dst_id} ts={ts} stream={stream}')
        else:
            print(f'[fake-master] ← DMRD  len={len(data)}')

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def _send(self, data: bytes, addr):
        self._transport.sendto(data, addr)

    def _send_dmrd(self):
        if self._state != 'CONNECTED' or not self._peer_addr:
            print('[fake-master] Not connected — cannot send DMRD')
            return
        # Minimal synthetic DMRD frame (53 bytes)
        flags = HBPF_TGID_TS2 | HBPF_FRAMETYPE_VOICESYNC
        frame = (
            HBPF_DMRD
            + bytes([1])             # seq
            + (3120001).to_bytes(3, 'big')  # src
            + (91).to_bytes(3, 'big')       # dst TGID
            + (self._peer_id or b'\x00\x00\x00\x00')  # repeater ID
            + bytes([flags])         # flags byte
            + os.urandom(4)          # stream ID
            + b'\x00' * 33          # payload
        )
        self._send(frame, self._peer_addr)
        print(f'[fake-master] → DMRD  {len(frame)} bytes to peer')

    def _send_nak(self):
        if not self._peer_addr:
            print('[fake-master] No peer connected')
            return
        self._send(HBPF_MSTNAK + (self._peer_id or b'\x00\x00\x00\x00'), self._peer_addr)
        print('[fake-master] → MSTNAK sent')
        self._state = 'IDLE'

    def _send_mstcl(self):
        if not self._peer_addr:
            print('[fake-master] No peer connected')
            return
        self._send(HBPF_MSTCL + (self._peer_id or b'\x00\x00\x00\x00'), self._peer_addr)
        print('[fake-master] → MSTCL sent')
        self._state = 'IDLE'

    # ------------------------------------------------------------------
    # Stdin command loop
    # ------------------------------------------------------------------

    async def _stdin_loop(self):
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        except Exception as exc:
            print(f'[fake-master] stdin unavailable: {exc}')
            return

        print('[fake-master] Commands: dmrd | nak | close | quit')
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode().strip().lower()
                if cmd == 'dmrd':
                    self._send_dmrd()
                elif cmd == 'nak':
                    self._send_nak()
                elif cmd in ('close', 'mstcl'):
                    self._send_mstcl()
                elif cmd in ('quit', 'exit', 'q'):
                    loop.stop()
                    break
                else:
                    print('[fake-master] Unknown command. Try: dmrd | nak | close | quit')
            except Exception as exc:
                print(f'[fake-master] stdin error: {exc}')
                break


def main():
    ap = argparse.ArgumentParser(description='Fake HBP master (simulates BrandMeister/HBlink4)')
    ap.add_argument('--port',       default=62031, type=int, help='UDP port to listen on (default 62031)')
    ap.add_argument('--bind',       default='127.0.0.1', help='Bind address (default 127.0.0.1)')
    ap.add_argument('--passphrase', default='passw0rd', help='HBP passphrase (default passw0rd)')
    args = ap.parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print(f'[fake-master] Starting — {args.bind}:{args.port}  passphrase={args.passphrase!r}')

    coro = loop.create_datagram_endpoint(
        lambda: FakeHBPMaster(args),
        local_addr=(args.bind, args.port),
    )

    try:
        loop.run_until_complete(coro)
        loop.run_forever()
    except KeyboardInterrupt:
        print('\n[fake-master] Interrupted')
    finally:
        loop.close()


if __name__ == '__main__':
    main()
