"""
IPSC master stack — asyncio DatagramProtocol.

Handles one Motorola MOTOTRBO repeater connecting to us as the IPSC master.
Manages registration, keep-alive, watchdog, and GROUP_VOICE dispatch.

Packet layout confirmed from DMRlink IPSC_Bridge.py / dmrlink.py source.
"""

import asyncio
import binascii
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
    DE_REG_REQ, DE_REG_REPLY,
    GROUP_VOICE, PVT_VOICE, GROUP_DATA, PVT_DATA,
    RPT_WAKE_UP, UNKNOWN_COLLISION, XCMP_XNL,
    CALL_CONFIRMATION, TXT_MESSAGE_ACK,
    CALL_MON_STATUS, CALL_MON_RPT, CALL_MON_NACK,
    PEER_REG_REQ, PEER_REG_REPLY,
    PEER_ALIVE_REQ, PEER_ALIVE_REPLY,
    VOICE_HEAD, VOICE_TERM, SLOT1_VOICE, SLOT2_VOICE,
    IPSC_VER, TS_CALL_MSK, END_MSK,
    VOICE_CALL_MSK, DATA_CALL_MSK, PKT_AUTH_MSK, MSTR_PEER_MSK,
    GV_PEER_ID_OFF, GV_IPSC_SEQ_OFF,
    GV_SRC_SUB_OFF, GV_DST_GROUP_OFF,
    GV_CALL_INFO_OFF, GV_BURST_TYPE_OFF, GV_PAYLOAD_OFF,
    GV_MIN_LEN, AUTH_DIGEST_LEN,
)

log = logging.getLogger(__name__)

# Our MODE byte: operational (0x40) + digital (0x20) + TS1 on (0x08) + TS2 on (0x02)
_OUR_MODE = b'\x6A'


class IPSCProtocol(asyncio.DatagramProtocol):

    def __init__(self, config: Config, translator):
        self._cfg = config
        self._translator = translator
        self._transport = None
        self._watchdog_task = None

        # Peer state — cleared on loss/de-reg
        self._registered = False
        self._peer_id    = b'\x00\x00\x00\x00'
        self._peer_ip    = ''
        self._peer_port  = 0
        self._peer_mode  = b'\x00'
        self._last_ka    = 0.0

        # Precompute constant fields
        self._master_id = config.ipsc_master_id.to_bytes(4, 'big')

        flags_byte4 = VOICE_CALL_MSK | MSTR_PEER_MSK
        if config.auth_enabled:
            flags_byte4 |= PKT_AUTH_MSK
        self._our_flags = b'\x00\x00\x00' + bytes([flags_byte4])
        self._ts_flags  = _OUR_MODE + self._our_flags  # 5 bytes

        # Keepalive reply is static (peer_id varies in alive_req but reply uses master_id)
        self._alive_reply = (
            bytes([MASTER_ALIVE_REPLY]) + self._master_id + self._ts_flags + IPSC_VER
        )
        self._dereg_reply = bytes([DE_REG_REPLY]) + self._master_id

    # ------------------------------------------------------------------
    # asyncio protocol interface
    # ------------------------------------------------------------------

    def connection_made(self, transport):
        self._transport = transport
        log.info('IPSC master listening on %s:%d',
                 self._cfg.ipsc_bind_ip, self._cfg.ipsc_bind_port)
        loop = asyncio.get_event_loop()
        self._watchdog_task = loop.create_task(self._watchdog_loop())

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

        opcode = data[0]

        # XNL/XCMP: never process, log only at DEBUG
        if opcode == XCMP_XNL:
            log.debug('XCMP/XNL received from %s:%d — ignored', host, port)
            return

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
        # All other opcodes silently ignored

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
        peer_flags  = data[6:10]  # 4-byte FLAGS

        # Validate peer radio ID
        if peer_id_int != self._cfg.ipsc_peer_id:
            if self._cfg.registration_mode == 'STRICT':
                log.warning(
                    'STRICT: MASTER_REG_REQ radio ID %d does not match configured %d — dropped',
                    peer_id_int, self._cfg.ipsc_peer_id,
                )
                return
            else:
                log.warning(
                    'LOOSE: MASTER_REG_REQ radio ID %d does not match configured %d — accepted',
                    peer_id_int, self._cfg.ipsc_peer_id,
                )

        was_registered = self._registered
        self._registered = True
        self._peer_id   = peer_id
        self._peer_ip   = host
        self._peer_port = port
        self._peer_mode = peer_mode
        self._last_ka   = time()

        # MASTER_REG_REPLY:
        # 0x91 + master_id(4) + ts_flags(5) + num_peers(2) + IPSC_VER(4)
        reg_reply = (
            bytes([MASTER_REG_REPLY])
            + self._master_id
            + self._ts_flags
            + struct.pack('>H', 1)   # 1 peer
            + IPSC_VER
        )
        self._send(reg_reply, host, port)
        self._send_peer_list(host, port)

        if not was_registered:
            log.info('IPSC peer registered: id=%d  %s:%d', peer_id_int, host, port)
            self._translator.peer_registered(peer_id, host, port)
        else:
            log.info('IPSC peer re-registered: id=%d  %s:%d', peer_id_int, host, port)

    def _send_peer_list(self, host: str, port: int):
        # Peer entry: peer_id(4) + packed_ip(4) + port(2) + mode(1) = 11 bytes
        try:
            packed_ip = socket.inet_aton(self._peer_ip)
        except OSError:
            packed_ip = b'\x00\x00\x00\x00'
        peer_entry = (
            self._peer_id
            + packed_ip
            + struct.pack('>H', self._peer_port)
            + self._peer_mode
        )
        peer_list_reply = (
            bytes([PEER_LIST_REPLY])
            + self._master_id
            + struct.pack('>H', len(peer_entry))
            + peer_entry
        )
        self._send(peer_list_reply, host, port)

    def _on_alive_req(self, data: bytes, host: str, port: int):
        if not self._registered:
            return
        if len(data) >= 5 and data[1:5] != self._peer_id:
            log.debug('MASTER_ALIVE_REQ from unknown peer ID — ignored')
            return
        self._last_ka = time()
        self._send(self._alive_reply, host, port)
        log.debug('MASTER_ALIVE_REQ → MASTER_ALIVE_REPLY to %s:%d', host, port)

    def _on_peer_list_req(self, data: bytes, host: str, port: int):
        if not self._registered:
            return
        log.debug('PEER_LIST_REQ from %s:%d', host, port)
        self._send_peer_list(host, port)

    def _on_de_reg_req(self, data: bytes, host: str, port: int):
        peer_id_int = int.from_bytes(data[1:5], 'big') if len(data) >= 5 else 0
        log.warning('IPSC peer de-registering: id=%d  %s:%d', peer_id_int, host, port)
        self._send(self._dereg_reply, host, port)
        self._clear_peer()

    def _on_group_voice(self, data: bytes, host: str, port: int):
        if not self._registered:
            return
        if len(data) < GV_MIN_LEN:
            log.debug('GROUP_VOICE too short (%d bytes) from %s:%d', len(data), host, port)
            return

        burst_type = data[GV_BURST_TYPE_OFF]
        call_info  = data[GV_CALL_INFO_OFF]

        # Timeslot: for VOICE_HEAD/VOICE_TERM read from call_info byte 17;
        # for SLOT1/SLOT2_VOICE it is encoded in bit 7 of burst_type.
        if burst_type in (VOICE_HEAD, VOICE_TERM):
            ts = 2 if (call_info & TS_CALL_MSK) else 1
        else:
            ts = 2 if (burst_type & 0x80) else 1

        log.debug('GROUP_VOICE burst_type=0x%02x ts=%d from %s:%d', burst_type, ts, host, port)
        self._translator.ipsc_voice_received(data, ts, burst_type)

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _check_auth(self, data: bytes) -> bool:
        if len(data) <= AUTH_DIGEST_LEN:
            return False
        payload  = data[:-AUTH_DIGEST_LEN]
        received = data[-AUTH_DIGEST_LEN:]
        expected = binascii.unhexlify(
            hmac_mod.new(self._cfg.auth_key, payload, sha1).hexdigest()[:20]
        )
        return received == expected

    def _auth_suffix(self, packet: bytes) -> bytes:
        if not self._cfg.auth_enabled:
            return b''
        return binascii.unhexlify(
            hmac_mod.new(self._cfg.auth_key, packet, sha1).hexdigest()[:20]
        )

    def _send(self, packet: bytes, host: str, port: int):
        out = packet + self._auth_suffix(packet)
        self._transport.sendto(out, (host, port))

    # ------------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------------

    async def _watchdog_loop(self):
        while True:
            await asyncio.sleep(5)
            if self._registered:
                elapsed = time() - self._last_ka
                if elapsed > self._cfg.keepalive_watchdog:
                    log.warning(
                        'IPSC watchdog: no keepalive for %.1fs (limit %ds) — peer lost',
                        elapsed, self._cfg.keepalive_watchdog,
                    )
                    self._clear_peer()

    def _clear_peer(self):
        if self._registered:
            self._registered = False
            self._translator.peer_lost()

    # ------------------------------------------------------------------
    # Public interface for inbound path (HBP → IPSC)
    # ------------------------------------------------------------------

    def send_to_peer(self, packet: bytes):
        """Send a pre-built GROUP_VOICE packet to the registered repeater."""
        if self._registered and self._transport:
            self._send(packet, self._peer_ip, self._peer_port)

    def is_peer_registered(self) -> bool:
        return self._registered
