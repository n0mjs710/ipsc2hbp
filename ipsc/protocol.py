"""
IPSC master stack — asyncio DatagramProtocol.

Handles up to 14 Motorola MOTOTRBO repeaters connecting as IPSC peers
(IPSC supports 15 peers maximum; the master counts as one).

Manages registration, peer list distribution, per-peer keepalive watchdog,
and GROUP_VOICE dispatch.

Packet layout confirmed from DMRlink IPSC_Bridge.py / dmrlink.py source.
"""

import asyncio
import hmac as hmac_mod
import logging
import socket
import struct
from hashlib import sha1
from time import time

from config import Config
from ipsc.const import (
    MASTER_REG_REQ, MASTER_REG_REPLY,
    PEER_LIST_REQ, PEER_LIST_REPLY,
    MASTER_ALIVE_REQ, MASTER_ALIVE_REPLY,
    DE_REG_REQ, DE_REG_REPLY, OPCODE_0xF0,
    GROUP_VOICE, PVT_VOICE, GROUP_DATA, PVT_DATA,
    UNKNOWN_COLLISION, XCMP_XNL,
    VOICE_HEAD, VOICE_TERM,
    IPSC_VER, TS_CALL_MSK,
    VOICE_CALL_MSK, PKT_AUTH_MSK, MSTR_PEER_MSK,
    GV_CALL_INFO_OFF, GV_BURST_TYPE_OFF,
    GV_MIN_LEN, AUTH_DIGEST_LEN,
)

log = logging.getLogger(__name__)
_wire = logging.getLogger('ipsc.wire')   # enable with --wire; logs raw hex only

# Opcodes known from DMRlink that ipsc2hbp receives but does not process.
# Logged at DEBUG so they're visible without polluting WARNING.
_KNOWN_UNHANDLED = {
    0x05: 'CALL_CONFIRMATION',   # confirmed-call acknowledgement from recipient
    0x54: 'TXT_MESSAGE_ACK',     # text message ack (sent on success OR failure)
    0x61: 'CALL_MON_STATUS',     # call monitor — exact meaning unknown
    0x62: 'CALL_MON_RPT',        # call monitor — exact meaning unknown
    0x63: 'CALL_MON_NACK',       # call monitor — exact meaning unknown
    0x85: 'RPT_WAKE_UP',         # similar to OTA DMR wake-up
    0x91: 'MASTER_REG_REPLY',    # peer→master registration reply (we are master, not peer)
    0x93: 'PEER_LIST_REPLY',     # peer list reply (we are master, not peer)
    0x94: 'PEER_REG_REQ',        # peer-to-peer registration request
    0x95: 'PEER_REG_REPLY',      # peer-to-peer registration reply
    0x97: 'MASTER_ALIVE_REPLY',  # keepalive reply (we are master, not peer)
    0x98: 'PEER_ALIVE_REQ',      # peer keepalive request
    0x99: 'PEER_ALIVE_REPLY',    # peer keepalive reply
    0x9B: 'DE_REG_REPLY',        # de-registration reply (we are master, not peer)
}

# Our MODE byte: operational (0x40) + digital (0x20) + TS1 on (0x08) + TS2 on (0x02)
_OUR_MODE = b'\x6A'

# IPSC supports 15 peers maximum; master counts as one, so 14 non-master peers.
_MAX_PEERS = 14


class IPSCProtocol(asyncio.DatagramProtocol):

    def __init__(self, config: Config, translator):
        self._cfg        = config
        self._translator = translator
        self._transport  = None
        self._watchdog_task = None

        # Multi-peer state: keyed by 4-byte peer_id (bytes).
        # Each value: {'ip': str, 'port': int, 'mode': bytes, 'last_ka': float}
        self._peers: dict[bytes, dict] = {}

        # Precompute constant fields
        self._master_id = config.ipsc_master_id.to_bytes(4, 'big')

        flags_byte4 = VOICE_CALL_MSK | MSTR_PEER_MSK
        if config.auth_enabled:
            flags_byte4 |= PKT_AUTH_MSK
        self._our_flags = b'\x00\x00\x00' + bytes([flags_byte4])
        self._ts_flags  = _OUR_MODE + self._our_flags  # 5 bytes

        # Static reply packets (master_id constant; peer_count inserted dynamically)
        self._alive_reply = (
            bytes([MASTER_ALIVE_REPLY]) + self._master_id + self._ts_flags + IPSC_VER
        )
        self._dereg_reply = bytes([DE_REG_REPLY]) + self._master_id

    # ------------------------------------------------------------------
    # asyncio protocol interface
    # ------------------------------------------------------------------

    def connection_made(self, transport):
        self._transport = transport
        log.info('IPSC master listening on %s:%d  (max %d peers)',
                 self._cfg.ipsc_bind_ip, self._cfg.ipsc_bind_port, _MAX_PEERS)
        self._watchdog_task = asyncio.get_running_loop().create_task(self._watchdog_loop())

    def connection_lost(self, exc):
        if self._watchdog_task:
            self._watchdog_task.cancel()

    def error_received(self, exc):
        log.warning('IPSC socket error: %s', exc)

    def datagram_received(self, data: bytes, addr):
        host, port = addr[0], addr[1]

        if self._cfg.auth_enabled:
            if not self._check_auth(data):
                log.warning('IPSC auth failure from %s:%d — packet dropped', host, port)
                return
            data = data[:-AUTH_DIGEST_LEN]

        if not data:
            return

        _wire.debug('IPSC RECV %d %s', len(data), data.hex())

        opcode = data[0]

        # XNL/XCMP: never process, log only at DEBUG
        if opcode == XCMP_XNL:
            log.debug('XCMP/XNL received from %s:%d — ignored', host, port)
            return

        # Any packet from a registered peer proves it is still alive; reset
        # that peer's watchdog.  Peer identity is in bytes 1–4 for all
        # management and voice opcodes.  IP must match to prevent spoofing.
        if len(data) >= 5:
            pid = data[1:5]
            if pid in self._peers and self._peers[pid]['ip'] == host:
                self._peers[pid]['last_ka'] = time()

        if opcode == MASTER_REG_REQ:
            self._on_reg_req(data, host, port)
        elif opcode == MASTER_ALIVE_REQ:
            self._on_alive_req(data, host, port)
        elif opcode == PEER_LIST_REQ:
            self._on_peer_list_req(data, host, port)
        elif opcode == DE_REG_REQ:
            self._on_de_reg_req(data, host, port)
        elif opcode == GROUP_VOICE:
            self._on_group_voice(data, host, port)
        elif opcode == PVT_VOICE:
            log.debug('PVT_VOICE from %s:%d — ignored', host, port)
        elif opcode in (GROUP_DATA, PVT_DATA):
            log.debug('Data packet 0x%02x from %s:%d — ignored', opcode, host, port)
        elif opcode == UNKNOWN_COLLISION:
            log.debug('UNKNOWN_COLLISION from %s:%d', host, port)
        elif opcode == OPCODE_0xF0:
            log.debug('0xF0 from %s:%d — observed, benign, no response sent', host, port)
        elif opcode in _KNOWN_UNHANDLED:
            log.debug('%s (0x%02x) from %s:%d — received, not handled',
                      _KNOWN_UNHANDLED[opcode], opcode, host, port)
        else:
            log.warning('unknown opcode 0x%02x from %s:%d len=%d — no handler  raw=%s',
                        opcode, host, port, len(data), data.hex())

    # ------------------------------------------------------------------
    # Opcode handlers
    # ------------------------------------------------------------------

    def _on_reg_req(self, data: bytes, host: str, port: int):
        if len(data) < 10:
            log.warning('MASTER_REG_REQ too short (%d bytes) from %s:%d', len(data), host, port)
            return

        peer_id     = data[1:5]
        peer_id_int = int.from_bytes(peer_id, 'big')
        peer_mode   = data[5:6]   # 1-byte MODE
        # peer_flags data[6:10] reserved for future capability negotiation

        # IP allowlist check
        if self._cfg.allowed_peer_ips and host not in self._cfg.allowed_peer_ips:
            log.warning('MASTER_REG_REQ from %s:%d rejected — not in allowed_peer_ips', host, port)
            return

        # Radio ID allowlist check
        if self._cfg.allowed_peer_ids and peer_id_int not in self._cfg.allowed_peer_ids:
            log.warning('MASTER_REG_REQ radio ID %d from %s:%d rejected — not in allowed_peer_ids',
                        peer_id_int, host, port)
            return

        is_new_peer = peer_id not in self._peers

        # Capacity check: only applies to genuinely new peers
        if is_new_peer and len(self._peers) >= _MAX_PEERS:
            log.warning(
                'MASTER_REG_REQ from %s:%d (id=%d) rejected — IPSC system full '
                '(%d peers registered; IPSC maximum is 15 including the master)',
                host, port, peer_id_int, len(self._peers),
            )
            return

        # Hijack protection: reject a different IP claiming an already-registered peer ID
        if not is_new_peer and self._peers[peer_id]['ip'] != host:
            log.warning(
                'MASTER_REG_REQ from %s:%d (id=%d) rejected — peer ID already '
                'registered from %s',
                host, port, peer_id_int, self._peers[peer_id]['ip'],
            )
            return

        was_empty = len(self._peers) == 0

        self._peers[peer_id] = {
            'ip':      host,
            'port':    port,
            'mode':    peer_mode,
            'last_ka': time(),
        }

        # MASTER_REG_REPLY: 0x91 + master_id(4) + ts_flags(5) + num_peers(2) + IPSC_VER(4)
        reg_reply = (
            bytes([MASTER_REG_REPLY])
            + self._master_id
            + self._ts_flags
            + struct.pack('>H', len(self._peers))
            + IPSC_VER
        )
        self._send(reg_reply, host, port)
        self._send_peer_list(host, port)

        if is_new_peer:
            log.info('IPSC peer registered: id=%d  %s:%d  (%d/%d peers)',
                     peer_id_int, host, port, len(self._peers), _MAX_PEERS)
            # Broadcast updated peer list to all other registered peers
            for pid, p in self._peers.items():
                if pid != peer_id:
                    self._send_peer_list(p['ip'], p['port'])
            if was_empty:
                self._translator.peer_joined()
        else:
            log.info('IPSC peer re-registered: id=%d  %s:%d', peer_id_int, host, port)

    def _send_peer_list(self, host: str, port: int):
        """Build and send PEER_LIST_REPLY to a specific host:port."""
        entries = b''
        for pid, p in self._peers.items():
            try:
                packed_ip = socket.inet_aton(p['ip'])
            except OSError:
                packed_ip = b'\x00\x00\x00\x00'
            entries += pid + packed_ip + struct.pack('>H', p['port']) + p['mode']

        peer_list_reply = (
            bytes([PEER_LIST_REPLY])
            + self._master_id
            + struct.pack('>H', len(entries))
            + entries
        )
        self._send(peer_list_reply, host, port)

    def _on_alive_req(self, data: bytes, host: str, port: int):
        if len(data) < 5:
            return
        peer_id = data[1:5]
        if peer_id not in self._peers:
            log.debug('MASTER_ALIVE_REQ from unregistered peer %d at %s:%d — ignored',
                      int.from_bytes(peer_id, 'big'), host, port)
            return
        self._peers[peer_id]['last_ka'] = time()
        self._send(self._alive_reply, host, port)
        log.debug('MASTER_ALIVE_REQ → MASTER_ALIVE_REPLY to %s:%d', host, port)

    def _on_peer_list_req(self, data: bytes, host: str, port: int):
        # Accept the request from any host that is a registered peer (by IP)
        if not any(p['ip'] == host for p in self._peers.values()):
            log.debug('PEER_LIST_REQ from unregistered host %s — ignored', host)
            return
        log.debug('PEER_LIST_REQ from %s:%d', host, port)
        self._send_peer_list(host, port)

    def _on_de_reg_req(self, data: bytes, host: str, port: int):
        peer_id     = data[1:5] if len(data) >= 5 else b'\x00\x00\x00\x00'
        peer_id_int = int.from_bytes(peer_id, 'big')
        log.info('IPSC peer de-registering: id=%d  %s:%d', peer_id_int, host, port)
        self._send(self._dereg_reply, host, port)
        self._remove_peer(peer_id)

    def _on_group_voice(self, data: bytes, host: str, port: int):
        if not self._peers:
            return

        peer_id = data[1:5] if len(data) >= 5 else None
        if peer_id not in self._peers:
            log.debug('GROUP_VOICE from unregistered peer at %s:%d — dropped', host, port)
            return

        if len(data) < GV_MIN_LEN:
            log.warning('GROUP_VOICE too short (%d bytes) from %s:%d', len(data), host, port)
            return

        burst_type = data[GV_BURST_TYPE_OFF]   # byte 30 — always present
        call_info  = data[GV_CALL_INFO_OFF]    # byte 17

        log.debug('GROUP_VOICE len=%d burst=0x%02x raw[0:32]=%s from %s:%d',
                  len(data), burst_type, data[:32].hex(), host, port)

        # Timeslot: for VOICE_HEAD/VOICE_TERM read from call_info byte 17;
        # for SLOT1/SLOT2_VOICE it is encoded in bit 7 of burst_type.
        if burst_type in (VOICE_HEAD, VOICE_TERM):
            ts = 2 if (call_info & TS_CALL_MSK) else 1
        else:
            ts = 2 if (burst_type & 0x80) else 1

        self._translator.ipsc_voice_received(data, ts, burst_type)

    # ------------------------------------------------------------------
    # Peer lifecycle
    # ------------------------------------------------------------------

    def _remove_peer(self, peer_id: bytes):
        """Remove a peer, broadcast updated peer list, notify translator if now empty."""
        if peer_id not in self._peers:
            return
        del self._peers[peer_id]
        if self._peers:
            for p in self._peers.values():
                self._send_peer_list(p['ip'], p['port'])
        else:
            self._translator.peer_lost()

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _check_auth(self, data: bytes) -> bool:
        if len(data) <= AUTH_DIGEST_LEN:
            return False
        payload  = data[:-AUTH_DIGEST_LEN]
        received = data[-AUTH_DIGEST_LEN:]
        expected = hmac_mod.new(self._cfg.auth_key, payload, sha1).digest()[:10]
        return received == expected

    def _auth_suffix(self, packet: bytes) -> bytes:
        if not self._cfg.auth_enabled:
            return b''
        return hmac_mod.new(self._cfg.auth_key, packet, sha1).digest()[:10]

    def _send(self, packet: bytes, host: str, port: int):
        out = packet + self._auth_suffix(packet)
        _wire.debug('IPSC SEND %d %s', len(packet), packet.hex())
        self._transport.sendto(out, (host, port))

    # ------------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------------

    async def _watchdog_loop(self):
        while True:
            await asyncio.sleep(5)
            now = time()
            timed_out = [
                pid for pid, p in self._peers.items()
                if now - p['last_ka'] > self._cfg.keepalive_watchdog
            ]
            for pid in timed_out:
                p = self._peers.get(pid)
                if p:
                    log.warning(
                        'IPSC watchdog: no keepalive for %.1fs (limit %ds) — '
                        'peer %d (%s:%d) lost',
                        now - p['last_ka'], self._cfg.keepalive_watchdog,
                        int.from_bytes(pid, 'big'), p['ip'], p['port'],
                    )
                self._remove_peer(pid)
            self._translator.check_call_timeouts()

    # ------------------------------------------------------------------
    # Public interface for inbound path (HBP → IPSC)
    # ------------------------------------------------------------------

    def send_voice(self, packet: bytes):
        """Send a pre-built GROUP_VOICE packet to all registered IPSC peers."""
        for p in self._peers.values():
            self._send(packet, p['ip'], p['port'])

    def has_peers(self) -> bool:
        return bool(self._peers)
