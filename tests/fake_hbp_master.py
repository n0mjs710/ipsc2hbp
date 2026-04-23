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
import stat
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
    HBPF_TGID_TS2,
    HBPF_FRAMETYPE_VOICE, HBPF_FRAMETYPE_VOICESYNC, HBPF_FRAMETYPE_DATASYNC,
    HBPF_SLT_VHEAD, HBPF_SLT_VTERM,
)


class FakeHBPMaster(asyncio.DatagramProtocol):

    def __init__(self, args):
        self._passphrase       = args.passphrase.encode()
        self._auto_dmrd        = args.auto_dmrd
        self._auto_nak_after   = args.auto_nak_after
        self._auto_close_after = args.auto_close_after
        self._transport        = None
        self._peer_addr        = None
        self._peer_id          = None
        self._state            = 'IDLE'   # IDLE → WAIT_RPTK → WAIT_RPTC → CONNECTED
        self._salt             = os.urandom(4)
        self._stdin_task       = None
        self._auto_task        = None

    def connection_made(self, transport):
        self._transport = transport
        host, port = transport.get_extra_info('sockname')
        print(f'[fake-master] Listening on {host}:{port}')
        loop = asyncio.get_event_loop()
        if self._auto_dmrd or self._auto_nak_after or self._auto_close_after:
            self._auto_task = loop.create_task(self._auto_sequence_loop())
        else:
            self._stdin_task = loop.create_task(self._stdin_loop())

    def connection_lost(self, exc):
        print(f'[fake-master] Connection lost: {exc}')

    def error_received(self, exc):
        print(f'[fake-master] Socket error: {exc}')

    def datagram_received(self, data: bytes, addr):
        if len(data) < 4:
            return

        # Longest-prefix dispatch (longer prefixes must be checked before shorter ones)
        if len(data) >= 7 and data[:7] == HBPF_RPTPING:
            self._on_rptping(data, addr)
        elif len(data) >= len(HBPF_RPTCL) and data[:len(HBPF_RPTCL)] == HBPF_RPTCL:
            peer_id = int.from_bytes(data[len(HBPF_RPTCL):len(HBPF_RPTCL)+4], 'big') \
                      if len(data) >= len(HBPF_RPTCL) + 4 else 0
            print(f'[fake-master] ← RPTCL from peer_id={peer_id} — peer disconnected')
            self._state = 'IDLE'
            self._peer_addr = None
            self._peer_id   = None
        elif len(data) >= 4 and data[:4] == HBPF_RPTL:
            self._on_rptl(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTK:
            self._on_rptk(data, addr)
        elif len(data) >= 4 and data[:4] == HBPF_RPTC:
            self._on_rptc(data, addr)
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

    def _build_dmrd(self, seq: int, flags: int, stream_id: bytes) -> bytes:
        return (
            HBPF_DMRD
            + bytes([seq])
            + (3120001).to_bytes(3, 'big')   # src
            + (91).to_bytes(3, 'big')        # dst TGID
            + (self._peer_id or b'\x00\x00\x00\x00')
            + bytes([flags])
            + stream_id
            + b'\x00' * 33                   # payload
        )

    def _send_call(self, ts: int = 1, burst_count: int = 6):
        """Send a full VOICE_HEAD + N VOICE + VOICE_TERM sequence."""
        if self._state != 'CONNECTED' or not self._peer_addr:
            print('[fake-master] Not connected — cannot send call')
            return
        ts_flag    = HBPF_TGID_TS2 if ts == 2 else 0x00
        stream_id  = os.urandom(4)
        seq        = 0

        # VOICE_HEAD
        flags = ts_flag | HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VHEAD
        self._send(self._build_dmrd(seq, flags, stream_id), self._peer_addr)
        print(f'[fake-master] → DMRD VOICE_HEAD  ts={ts}  stream={stream_id.hex()}')
        seq += 1

        # Voice frames (VOICESYNC + VOICE × (burst_count-1))
        for i in range(burst_count):
            if i % 6 == 0:
                flags = ts_flag | HBPF_FRAMETYPE_VOICESYNC
            else:
                flags = ts_flag | HBPF_FRAMETYPE_VOICE | ((i % 6) - 1)
            self._send(self._build_dmrd(seq, flags, stream_id), self._peer_addr)
            seq += 1

        print(f'[fake-master] → DMRD {burst_count} voice frames  ts={ts}')

        # VOICE_TERM
        flags = ts_flag | HBPF_FRAMETYPE_DATASYNC | HBPF_SLT_VTERM
        self._send(self._build_dmrd(seq, flags, stream_id), self._peer_addr)
        print(f'[fake-master] → DMRD VOICE_TERM  ts={ts}')

    def _send_dmrd(self):
        """Send a single synthetic DMRD frame (interactive command)."""
        if self._state != 'CONNECTED' or not self._peer_addr:
            print('[fake-master] Not connected — cannot send DMRD')
            return
        flags  = HBPF_TGID_TS2 | HBPF_FRAMETYPE_VOICESYNC
        stream = os.urandom(4)
        frame  = self._build_dmrd(1, flags, stream)
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
    # Auto-sequence loop (background testing)
    # ------------------------------------------------------------------

    async def _wait_connected(self, timeout: float = 15.0) -> bool:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if self._state == 'CONNECTED':
                return True
            await asyncio.sleep(0.2)
        return False

    async def _auto_sequence_loop(self):
        """Background test driver: send auto-dmrd, auto-nak, or auto-close."""
        if not await self._wait_connected():
            print('[fake-master] auto: timed out waiting for connection')
            return

        if self._auto_dmrd:
            # Extra delay to allow IPSC peer to register with bridge before forwarding
            await asyncio.sleep(4)
            self._send_call(ts=1)
            await asyncio.sleep(0.5)
            self._send_call(ts=2)

        if self._auto_nak_after:
            await asyncio.sleep(self._auto_nak_after)
            print(f'[fake-master] auto: sending MSTNAK after {self._auto_nak_after}s')
            self._send_nak()

        if self._auto_close_after:
            await asyncio.sleep(self._auto_close_after)
            print(f'[fake-master] auto: sending MSTCL after {self._auto_close_after}s')
            self._send_mstcl()

    # ------------------------------------------------------------------
    # Stdin command loop
    # ------------------------------------------------------------------

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
        try:
            await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        except Exception as exc:
            print(f'[fake-master] stdin unavailable: {exc}')
            return

        print('[fake-master] Commands: call [ts1|ts2] | dmrd | nak | close | quit', flush=True)
        while True:
            try:
                line = await reader.readline()
                if not line:
                    break
                cmd = line.decode().strip().lower()
                if cmd in ('call', 'call ts1'):
                    self._send_call(ts=1)
                elif cmd == 'call ts2':
                    self._send_call(ts=2)
                elif cmd == 'dmrd':
                    self._send_dmrd()
                elif cmd == 'nak':
                    self._send_nak()
                elif cmd in ('close', 'mstcl'):
                    self._send_mstcl()
                elif cmd in ('quit', 'exit', 'q'):
                    loop.stop()
                    break
                else:
                    print('[fake-master] Unknown command. Try: call [ts1|ts2] | dmrd | nak | close | quit')
            except Exception as exc:
                print(f'[fake-master] stdin error: {exc}')
                break


def main():
    ap = argparse.ArgumentParser(description='Fake HBP master (simulates BrandMeister/HBlink4)')
    ap.add_argument('--port',       default=62031, type=int, help='UDP port to listen on (default 62031)')
    ap.add_argument('--bind',       default='127.0.0.1', help='Bind address (default 127.0.0.1)')
    ap.add_argument('--passphrase', default='passw0rd', help='HBP passphrase (default passw0rd)')
    ap.add_argument('--auto-dmrd', action='store_true', dest='auto_dmrd',
                    help='Send TS1+TS2 voice calls automatically after connection')
    ap.add_argument('--auto-nak-after', default=0, type=float, dest='auto_nak_after',
                    help='Send MSTNAK N seconds after connection (0=disabled)')
    ap.add_argument('--auto-close-after', default=0, type=float, dest='auto_close_after',
                    help='Send MSTCL N seconds after connection (0=disabled)')
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
