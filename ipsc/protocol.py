"""
IPSC protocol stacks — asyncio DatagramProtocol.

Two classes:
  IPSCMasterProtocol — ipsc2hbp acts as the IPSC master; repeaters register
      with it.  Handles up to 14 simultaneous IPSC peers.
  IPSCPeerProtocol   — ipsc2hbp registers with an existing IPSC master (e.g.
      a repeater acting as master).  Single upstream connection with automatic
      re-registration on watchdog timeout.

Both present the same send_voice / has_peers / stop interface to the
translator layer, which is unaffected by the mode choice.

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
    PEER_REG_REQ, PEER_REG_REPLY,
    PEER_ALIVE_REQ, PEER_ALIVE_REPLY,
    MASTER_ALIVE_REQ, MASTER_ALIVE_REPLY,
    DE_REG_REQ, DE_REG_REPLY, OPCODE_0xF0,
    GROUP_VOICE, PVT_VOICE, GROUP_DATA, PVT_DATA,
    REPEATER_BLOCKED, CALL_INTERRUPT_REQ, XCMP_XNL,
    SYSTEM_MAP_REQ, SYSTEM_MAP_REPLY,
    VOICE_HEAD, VOICE_TERM,
    TS_CALL_MSK,
    GV_CALL_INFO_OFF, GV_BURST_TYPE_OFF,
    GV_MIN_LEN, AUTH_DIGEST_LEN,
)

log = logging.getLogger(__name__)
_wire = logging.getLogger('ipsc.wire')   # enable with --wire; logs raw hex only

# In a full mesh, one call can be delivered from two sources at once (a c-Bridge
# or DMRgateway re-injecting it). We lock a timeslot to the first source; while it
# is actively talking (a frame within VOICE_LOCK_TIMEOUT) all other sources are
# dropped. A lagging duplicate keeps sending its tail after the first copy ends,
# so for VOICE_DUP_GUARD after the last owner frame we keep dropping *mid-call*
# bursts from other sources (a genuine new call opens with VOICE_HEAD, which is
# always allowed through).
VOICE_LOCK_TIMEOUT = 0.5   # seconds — active-call window (frames are 60 ms)
VOICE_DUP_GUARD    = 2.0    # seconds — suppress duplicate-tail bursts after a call

# Opcodes known from DMRlink that ipsc2hbp receives but does not process.
# Logged at DEBUG so they're visible without polluting WARNING.
_KNOWN_UNHANDLED = {
    0x05: 'CALL_CONFIRMATION',   # confirmed-call acknowledgement from recipient
    0x54: 'TXT_MESSAGE_ACK',     # text message ack (sent on success OR failure)
    0x61: 'CALL_MON_STATUS',     # Motorola call monitor: call event notification
    0x62: 'CALL_MON_RPT',        # Motorola call monitor: per-slot state report
    0x63: 'REPEATER_BLOCKED',    # signal interference / BSI blocking event
    0x85: 'RPT_WAKE_UP',         # repeater wake-up: seq(4)+slots(1)+type(1)
    0x86: 'CALL_INTERRUPT_REQ',  # call interrupt request
    0x91: 'MASTER_REG_REPLY',    # peer→master registration reply (we are master, not peer)
    0x93: 'PEER_LIST_REPLY',     # peer list reply (we are master, not peer)
    0x94: 'PEER_REG_REQ',        # peer-to-peer registration request
    0x95: 'PEER_REG_REPLY',      # peer-to-peer registration reply
    0x97: 'MASTER_ALIVE_REPLY',  # keepalive reply (we are master, not peer)
    0x98: 'PEER_ALIVE_REQ',      # peer keepalive request
    0x99: 'PEER_ALIVE_REPLY',    # peer keepalive reply
    0x9B: 'DE_REG_REPLY',        # de-registration reply (we are master, not peer)
    0x9C: 'SYSTEM_MAP_REQ',      # system topology query; distinct from peer list; purpose not fully known
    0x9D: 'SYSTEM_MAP_REPLY',    # system topology reply
    0x9E: 'UNKNOWN_9E',          # possibly extended peer registration; unknown
    0xB2: 'WIRELINE',            # MNIS data sub-protocol
    0xE0: 'REMOTE_PROG_REQ',     # CPS remote programming session request
    0xE1: 'REMOTE_PROG_REPLY',   # CPS remote programming session reply
}

# IPSC supports 15 peers maximum; master counts as one, so 14 non-master peers.
_MAX_PEERS = 14


class IPSCMasterProtocol(asyncio.DatagramProtocol):

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

        self._ts_flags  = config.ipsc_mode_byte + config.ipsc_flags_bytes  # 5 bytes

        # Static reply packets (master_id constant; peer_count inserted dynamically)
        self._alive_reply = (
            bytes([MASTER_ALIVE_REPLY]) + self._master_id + self._ts_flags + config.ipsc_version
        )
        self._dereg_reply = bytes([DE_REG_REPLY]) + self._master_id

    # ------------------------------------------------------------------
    # asyncio protocol interface
    # ------------------------------------------------------------------

    def connection_made(self, transport):
        self._transport = transport
        log.info('IPSC master listening — %s:%d  (max %d peers)',
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

        _wire.debug('IPSC RECV %s %d %s', host, len(data), data.hex())

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
        elif opcode == REPEATER_BLOCKED:
            log.debug('REPEATER_BLOCKED from %s:%d', host, port)
        elif opcode == CALL_INTERRUPT_REQ:
            log.debug('CALL_INTERRUPT_REQ from %s:%d', host, port)
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
            + self._cfg.ipsc_version
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
        _wire.debug('IPSC SEND %s %d %s', host, len(packet), packet.hex())
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

    def stop(self):
        """No-op in master mode; peers de-register themselves or time out."""

    def send_voice(self, packet: bytes):
        """Send a pre-built GROUP_VOICE packet to all registered IPSC peers."""
        for p in self._peers.values():
            self._send(packet, p['ip'], p['port'])

    def has_peers(self) -> bool:
        return bool(self._peers)


# ---------------------------------------------------------------------------
# Opcodes IPSCPeerProtocol receives from the master but does not act on.
# ---------------------------------------------------------------------------
_PEER_KNOWN_UNHANDLED = {
    0x05: 'CALL_CONFIRMATION',
    0x54: 'TXT_MESSAGE_ACK',
    0x61: 'CALL_MON_STATUS',
    0x62: 'CALL_MON_RPT',
    0x63: 'REPEATER_BLOCKED',
    0x81: 'PVT_VOICE',
    0x83: 'GROUP_DATA',
    0x84: 'PVT_DATA',
    0x85: 'RPT_WAKE_UP',
    0x86: 'CALL_INTERRUPT_REQ',
    0x94: 'PEER_REG_REQ',        # peer-to-peer mesh; not needed for this use case
    0x95: 'PEER_REG_REPLY',      # peer-to-peer mesh
    0x98: 'PEER_ALIVE_REQ',      # peer-to-peer keepalive
    0x99: 'PEER_ALIVE_REPLY',    # peer-to-peer keepalive
    0x9B: 'DE_REG_REPLY',        # master's ack of our DE_REG_REQ
    0x9E: 'UNKNOWN_9E',
    0xB2: 'WIRELINE',
    0xE0: 'REMOTE_PROG_REQ',
    0xE1: 'REMOTE_PROG_REPLY',
    0xF0: 'OPCODE_0xF0',
}


class IPSCPeerProtocol(asyncio.DatagramProtocol):
    """
    IPSC peer stack — registers with an existing IPSC master as a peer.

    Manages outbound registration, keepalive, watchdog-triggered
    re-registration, and GROUP_VOICE dispatch.  Presents the same
    send_voice / has_peers / stop interface as IPSCMasterProtocol so
    the translator layer is entirely unaffected by the mode choice.

    Notable: SYSTEM_MAP_REPLY (0x9D) is logged at INFO with full hex
    because this is the packet format we are actively trying to capture
    for analysis.  Connect to a repeater-as-master with a packet capture
    running on the CPS machine to observe the full exchange.
    """

    _IDLE        = 'IDLE'
    _REGISTERING = 'REGISTERING'
    _REGISTERED  = 'REGISTERED'   # peer list requested; keepalive not yet started
    _ACTIVE      = 'ACTIVE'       # fully established; keepalives running

    def __init__(self, config: Config, translator):
        self._cfg        = config
        self._translator = translator
        self._transport  = None
        self._keepalive_task = None

        self._state     = self._IDLE
        self._connected = False   # True after first successful registration
        self._missed    = 0       # consecutive keepalives/registration attempts without a reply

        self._our_id      = config.ipsc_master_id.to_bytes(4, 'big')
        self._ts_flags    = config.ipsc_mode_byte + config.ipsc_flags_bytes  # 5 bytes
        self._master_addr = (config.ipsc_master_ip, config.ipsc_master_port)

        # Full-mesh state: peers we learned from the master's PEER_LIST_REPLY.
        # IPSC voice/data travels peer-to-peer (unicast emulation of multicast),
        # so we must peer-register + keepalive with every one and accept their
        # traffic directly — the master only bootstraps the member list.
        # Each value: {'ip': str, 'port': int, 'mode': bytes,
        #              'connected': bool, 'outstanding': int}
        self._mesh = {}
        self._voice_src = {}   # {ts: {'src': peerid, 't': time}} — active-call source lock
        self._peer_reg_req_pkt     = bytes([PEER_REG_REQ])     + self._our_id + config.ipsc_version
        self._peer_reg_reply_pkt   = bytes([PEER_REG_REPLY])   + self._our_id + config.ipsc_version
        self._peer_alive_req_pkt   = bytes([PEER_ALIVE_REQ])   + self._our_id + self._ts_flags
        self._peer_alive_reply_pkt = bytes([PEER_ALIVE_REPLY]) + self._our_id + self._ts_flags

    # ------------------------------------------------------------------
    # asyncio protocol interface
    # ------------------------------------------------------------------

    def connection_made(self, transport):
        self._transport = transport
        log.info('IPSC peer socket bound — connecting to master %s:%d as id=%d',
                 self._cfg.ipsc_master_ip, self._cfg.ipsc_master_port,
                 self._cfg.ipsc_master_id)
        self._keepalive_task = asyncio.get_running_loop().create_task(
            self._registration_and_keepalive()
        )

    def connection_lost(self, exc):
        if self._keepalive_task:
            self._keepalive_task.cancel()

    def error_received(self, exc):
        log.warning('IPSC peer socket error: %s', exc)

    def datagram_received(self, data: bytes, addr):
        host, port = addr[0], addr[1]

        # Auth is a single system-wide key, so validate before we decide who
        # sent it (master vs. mesh peer).
        if self._cfg.auth_enabled:
            if not self._check_auth(data):
                log.warning('IPSC auth failure from %s:%d — packet dropped', host, port)
                return
            data = data[:-AUTH_DIGEST_LEN]

        if not data:
            return

        _wire.debug('IPSC RECV %s %d %s', host, len(data), data.hex())

        opcode = data[0]
        peerid = data[1:5]   # short/empty for sub-5-byte opcodes; never matches _mesh
        from_master = (host == self._cfg.ipsc_master_ip)
        known_peer  = peerid in self._mesh

        # IPSC is a full mesh: voice/data and the peer-to-peer management
        # handshake arrive DIRECTLY from every peer we learned in the master's
        # PEER_LIST_REPLY, not just from the master. Accept from the master or
        # any known peer; drop unknown sources (the old behaviour dropped every
        # non-master host, which silently discarded all real audio).
        if not (from_master or known_peer):
            log.debug('IPSC peer: 0x%02x from unknown source %s (id=%d) — dropped',
                      opcode, host, int.from_bytes(peerid, 'big'))
            return

        if opcode == XCMP_XNL:
            log.debug('XCMP/XNL from %s:%d — ignored', host, port)
            return

        # User traffic — accepted from the master OR any peer.
        if opcode == GROUP_VOICE:
            self._on_group_voice(data, host, port)
            return
        if opcode in (GROUP_DATA, PVT_DATA):
            log.debug('Data packet 0x%02x from %s:%d — ignored', opcode, host, port)
            return

        # Peer-to-peer mesh management (from another peer).
        if opcode == PEER_REG_REQ:
            self._on_peer_reg_req(peerid, host, port)
            return
        if opcode == PEER_REG_REPLY:
            self._on_peer_reg_reply(peerid)
            return
        if opcode == PEER_ALIVE_REQ:
            self._on_peer_alive_req(peerid, host, port)
            return
        if opcode == PEER_ALIVE_REPLY:
            self._on_peer_alive_reply(peerid)
            return

        # Master management (only meaningful from the master).
        if opcode == MASTER_REG_REPLY:
            self._on_reg_reply(data, host, port)
        elif opcode == PEER_LIST_REPLY:
            self._on_peer_list_reply(data, host, port)
        elif opcode == MASTER_ALIVE_REPLY:
            self._on_alive_reply(data, host, port)
        elif opcode == SYSTEM_MAP_REPLY:
            log.info('SYSTEM_MAP_REPLY (0x9D) from master %s:%d len=%d raw=%s',
                     host, port, len(data), data.hex())
        elif opcode == SYSTEM_MAP_REQ:
            log.info('SYSTEM_MAP_REQ (0x9C) from master %s:%d len=%d raw=%s',
                     host, port, len(data), data.hex())
        elif opcode in _PEER_KNOWN_UNHANDLED:
            log.debug('%s (0x%02x) from %s:%d — received, not handled',
                      _PEER_KNOWN_UNHANDLED[opcode], opcode, host, port)
        else:
            log.warning('unknown opcode 0x%02x from %s:%d len=%d — no handler  raw=%s',
                        opcode, host, port, len(data), data.hex())

    # ------------------------------------------------------------------
    # Opcode handlers
    # ------------------------------------------------------------------

    def _on_reg_reply(self, data: bytes, host: str, port: int):
        if len(data) < 12:
            log.warning('IPSC peer: MASTER_REG_REPLY too short (%d bytes) from %s:%d',
                        len(data), host, port)
            return
        master_id  = int.from_bytes(data[1:5], 'big')
        peer_count = int.from_bytes(data[10:12], 'big')
        self._missed = 0
        self._state  = self._REGISTERED
        log.info('IPSC peer: registered with master id=%d at %s:%d  peers=%d',
                 master_id, host, port, peer_count)
        # Request peer list immediately
        self._send(bytes([PEER_LIST_REQ]) + self._our_id, *self._master_addr)
        # Notify translator on first connection or re-connection after watchdog
        if not self._connected:
            self._connected = True
            self._translator.peer_joined()

    def _on_peer_list_reply(self, data: bytes, host: str, port: int):
        self._missed = 0
        self._state  = self._ACTIVE
        # 0x93 + master_id(4) + entries_len(2) + N*[id(4) ip(4) port(2) mode(1)]
        if len(data) < 7:
            log.warning('IPSC peer: PEER_LIST_REPLY too short (%d bytes)', len(data))
            return
        entries_len = int.from_bytes(data[5:7], 'big')
        seen = set()
        for off in range(7, 7 + entries_len, 11):
            entry = data[off:off + 11]
            if len(entry) < 11:
                break
            pid = entry[0:4]
            if pid == self._our_id:
                continue                      # never mesh with ourselves
            ip    = socket.inet_ntoa(entry[4:8])
            pport = int.from_bytes(entry[8:10], 'big')
            mode  = entry[10:11]
            seen.add(pid)
            if pid in self._mesh:
                self._mesh[pid].update(ip=ip, port=pport, mode=mode)
            else:
                self._mesh[pid] = {'ip': ip, 'port': pport, 'mode': mode,
                                   'connected': False, 'outstanding': 0}
                log.info('IPSC peer: learned mesh peer %d at %s:%d',
                         int.from_bytes(pid, 'big'), ip, pport)
        for pid in [p for p in self._mesh if p not in seen]:
            log.info('IPSC peer: mesh peer %d removed (no longer in peer list)',
                     int.from_bytes(pid, 'big'))
            del self._mesh[pid]
        log.debug('PEER_LIST_REPLY from %s:%d — %d mesh peer(s)', host, port, len(self._mesh))

    # ------------------------------------------------------------------
    # Full-mesh peer-to-peer handlers (§ IPSC mesh; mirrors DMRlink3)
    # ------------------------------------------------------------------

    def _on_peer_reg_req(self, peerid: bytes, host: str, port: int):
        """Another peer is registering with us — reply so it marks us CONNECTED."""
        self._send(self._peer_reg_reply_pkt, host, port)
        p = self._mesh.get(peerid)
        if p:
            p['ip'], p['port'] = host, port
        log.debug('IPSC peer: PEER_REG_REQ from %d at %s:%d — replied',
                  int.from_bytes(peerid, 'big'), host, port)

    def _on_peer_reg_reply(self, peerid: bytes):
        p = self._mesh.get(peerid)
        if p and not p['connected']:
            p['connected'], p['outstanding'] = True, 0
            log.info('IPSC peer: mesh peer %d CONNECTED (%s:%d)',
                     int.from_bytes(peerid, 'big'), p['ip'], p['port'])

    def _on_peer_alive_req(self, peerid: bytes, host: str, port: int):
        self._send(self._peer_alive_reply_pkt, host, port)
        p = self._mesh.get(peerid)
        if p:
            p['outstanding'] = 0

    def _on_peer_alive_reply(self, peerid: bytes):
        p = self._mesh.get(peerid)
        if p:
            p['outstanding'] = 0

    def _service_mesh_peers(self):
        """Once per keepalive tick: register with new peers, keepalive connected
        ones, and drop peers that stop answering (they'll re-register if the
        master lists them again)."""
        for pid, p in self._mesh.items():
            if not p['connected']:
                self._send(self._peer_reg_req_pkt, p['ip'], p['port'])
                log.debug('IPSC peer: PEER_REG_REQ -> %d (%s:%d)',
                          int.from_bytes(pid, 'big'), p['ip'], p['port'])
            elif p['outstanding'] >= self._cfg.keepalive_missed_max:
                p['connected'], p['outstanding'] = False, 0
                log.warning('IPSC peer: mesh peer %d unresponsive — re-registering',
                            int.from_bytes(pid, 'big'))
            else:
                self._send(self._peer_alive_req_pkt, p['ip'], p['port'])
                p['outstanding'] += 1

    def _on_alive_reply(self, data: bytes, host: str, port: int):
        self._missed = 0
        log.debug('MASTER_ALIVE_REPLY from master %s:%d', host, port)

    def _on_group_voice(self, data: bytes, host: str, port: int):
        if not self._connected:
            return
        if len(data) < GV_MIN_LEN:
            log.warning('GROUP_VOICE too short (%d bytes) from %s:%d',
                        len(data), host, port)
            return

        burst_type = data[GV_BURST_TYPE_OFF]
        call_info  = data[GV_CALL_INFO_OFF]

        if burst_type in (VOICE_HEAD, VOICE_TERM):
            ts = 2 if (call_info & TS_CALL_MSK) else 1
        else:
            ts = 2 if (burst_type & 0x80) else 1

        # Per-timeslot source lock: the first source to key a timeslot owns it.
        # While it is actively talking, every other source is dropped. For a
        # guard window after its last frame we keep dropping *mid-call* bursts
        # from other sources — that's the lagging duplicate copy's tail, which
        # otherwise leaks in as a spurious "late entry" on unkey. A real new
        # call opens with VOICE_HEAD, which is always let through.
        src = data[1:5]
        now = time()
        lock = self._voice_src.get(ts)
        if lock and lock['src'] != src:
            age = now - lock['t']
            if age < VOICE_LOCK_TIMEOUT:
                log.debug('IPSC peer: duplicate voice on ts=%d from %d (locked to %d) — dropped',
                          ts, int.from_bytes(src, 'big'), int.from_bytes(lock['src'], 'big'))
                return
            if burst_type != VOICE_HEAD and age < VOICE_DUP_GUARD:
                log.debug('IPSC peer: duplicate tail on ts=%d from %d (%.2fs after %d) — dropped',
                          ts, int.from_bytes(src, 'big'), age, int.from_bytes(lock['src'], 'big'))
                return
        # Owner frame, or an allowed new call: (re)claim the slot. We keep the
        # lock across VOICE_TERM so the guard above can swallow the tail.
        self._voice_src[ts] = {'src': src, 't': now}

        log.debug('GROUP_VOICE len=%d burst=0x%02x raw[0:32]=%s from %s:%d',
                  len(data), burst_type, data[:32].hex(), host, port)

        self._translator.ipsc_voice_received(data, ts, burst_type)

    # ------------------------------------------------------------------
    # Registration and keepalive loop
    # ------------------------------------------------------------------

    def _register(self):
        pkt = (
            bytes([MASTER_REG_REQ])
            + self._our_id
            + self._ts_flags
            + self._cfg.ipsc_version
        )
        self._send(pkt, *self._master_addr)
        self._missed = 0
        self._state  = self._REGISTERING
        log.debug('IPSC peer: sent MASTER_REG_REQ to master %s:%d', *self._master_addr)

    def _send_alive(self):
        pkt = (
            bytes([MASTER_ALIVE_REQ])
            + self._our_id
            + self._ts_flags
            + self._cfg.ipsc_version
        )
        self._send(pkt, *self._master_addr)
        log.debug('MASTER_ALIVE_REQ → master %s:%d', *self._master_addr)

    def _lose_connection(self):
        was_connected  = self._connected
        self._connected = False
        self._state     = self._IDLE
        if was_connected:
            self._translator.peer_lost()

    async def _registration_and_keepalive(self):
        self._register()
        while True:
            await asyncio.sleep(self._cfg.keepalive_interval)
            self._translator.check_call_timeouts()

            if self._state == self._REGISTERING:
                # Count ticks without a reply; retry after keepalive_missed_max attempts
                self._missed += 1
                if self._missed >= self._cfg.keepalive_missed_max:
                    log.warning(
                        'IPSC peer: no registration reply from master %s:%d '
                        'after %d attempts — retrying',
                        *self._master_addr, self._cfg.keepalive_missed_max,
                    )
                    self._register()   # resets _missed to 0

            elif self._state in (self._REGISTERED, self._ACTIVE):
                if self._missed >= self._cfg.keepalive_missed_max:
                    log.warning(
                        'IPSC peer: %d consecutive keepalives unanswered by master %s:%d '
                        '— re-registering',
                        self._cfg.keepalive_missed_max, *self._master_addr,
                    )
                    self._lose_connection()
                    self._register()   # resets _missed to 0
                else:
                    self._send_alive()
                    self._missed += 1

            # Full mesh: once the master has given us the peer list, register
            # with and keepalive every peer directly.
            if self._state == self._ACTIVE:
                self._service_mesh_peers()

    # ------------------------------------------------------------------
    # Auth helpers (identical to IPSCMasterProtocol)
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
        _wire.debug('IPSC SEND %s %d %s', host, len(packet), packet.hex())
        self._transport.sendto(out, (host, port))

    # ------------------------------------------------------------------
    # Public interface (matches IPSCMasterProtocol)
    # ------------------------------------------------------------------

    def stop(self):
        """Send DE_REG_REQ to the master for a clean shutdown."""
        if self._connected:
            pkt = bytes([DE_REG_REQ]) + self._our_id
            self._send(pkt, *self._master_addr)
            log.info('IPSC peer: sent DE_REG_REQ to master %s:%d', *self._master_addr)
        self._connected = False

    def send_voice(self, packet: bytes):
        """Fan a pre-built GROUP_VOICE packet out to the whole IPSC mesh — the
        master plus every connected peer (unicast emulation of multicast)."""
        if not self._connected:
            return
        self._send(packet, *self._master_addr)
        for p in self._mesh.values():
            if p['connected']:
                self._send(packet, p['ip'], p['port'])

    def has_peers(self) -> bool:
        return self._connected
