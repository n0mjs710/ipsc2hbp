"""
HBP peer stack — asyncio DatagramProtocol + reconnect manager.

Acts as an HBP peer (repeater/client) connecting to an upstream HBP master
(BrandMeister, DMR+, FreeDMR, HBlink4).

Handshake (confirmed from hblink4 _handle_outbound_packet):
  → RPTL + radio_id(4)
  ← RPTACK + radio_id(4) + salt(4)       [data[6:10] = salt]
  → RPTK + radio_id(4) + sha256_hash(32)
  ← RPTACK + radio_id(4)                 [auth accepted]
  → RPTC + radio_id(4) + config(298)     [302 bytes total]
  ← RPTACK + radio_id(4)                 [config accepted → CONNECTED]

Keepalive:
  → RPTPING + radio_id(4)                [every KA_INTERVAL seconds]
  ← MSTPONG + radio_id(4) + ...
  3 missed pongs → disconnect + reconnect

Disconnect:
  ← MSTNAK → NAK, reconnect
  ← MSTCL  → server initiated close, reconnect
  → RPTCL + radio_id(4)                  [sent on clean local shutdown]
"""

import asyncio
import logging
import os
from hashlib import sha256
from time import time

from config import Config
from hbp.const import (
    HBPF_RPTL, HBPF_RPTK, HBPF_RPTC, HBPF_RPTO, HBPF_RPTPING, HBPF_RPTCL,
    HBPF_RPTACK, HBPF_MSTNAK, HBPF_MSTPONG, HBPF_MSTCL,
    HBPF_CMD_RPTA, HBPF_CMD_MSTN, HBPF_CMD_MSTP, HBPF_CMD_MSTC,
    RPTACK_NONCE_OFF, MSTPONG_ID_OFF,
    RPTC_SLOTS_VALUE,
)

log = logging.getLogger(__name__)

_KA_INTERVAL = 5.0    # seconds between RPTPING
_MAX_KA_AGE  = 15.0   # seconds without pong → disconnect (3 × KA_INTERVAL)
_RECONNECT_DELAY = 5.0


def _build_rptc(cfg: Config) -> bytes:
    """Build the 302-byte RPTC config blob (confirmed layout from hblink4)."""
    radio_id_b = cfg.hbp_repeater_id.to_bytes(4, 'big')
    def enc(s, n): return s.encode().ljust(n, b'\x00')[:n]
    return (
        HBPF_RPTC
        + radio_id_b
        + enc(cfg.callsign,    8)
        + enc(cfg.rx_freq,     9)
        + enc(cfg.tx_freq,     9)
        + enc(cfg.tx_power,    2)
        + enc(cfg.colorcode,   2)
        + enc(cfg.latitude,    8)
        + enc(cfg.longitude,   9)
        + enc(cfg.height,      3)
        + enc(cfg.location,   20)
        + enc(cfg.description,19)
        + RPTC_SLOTS_VALUE
        + enc(cfg.url,       124)
        + enc(cfg.software_id,40)
        + enc(cfg.package_id, 40)
    )


class _HBPProtocol(asyncio.DatagramProtocol):
    """Per-connection HBP state machine. Created fresh for each connection attempt."""

    def __init__(self, cfg: Config, translator, client):
        self._cfg        = cfg
        self._translator = translator
        self._client     = client
        self._radio_id_b = cfg.hbp_repeater_id.to_bytes(4, 'big')
        self._transport  = None
        self._state      = 'LOGIN'   # LOGIN → AUTH_SENT → CONFIG_SENT → [OPTIONS_SENT] → CONNECTED
        self._last_pong  = 0.0
        self._ping_task  = None
        self._done       = asyncio.Event()

    # ------------------------------------------------------------------
    # asyncio DatagramProtocol interface
    # ------------------------------------------------------------------

    def connection_made(self, transport):
        self._transport = transport
        self._send_raw(HBPF_RPTL + self._radio_id_b)
        log.info('HBP: → RPTL  radio_id=%d', self._cfg.hbp_repeater_id)

    def connection_lost(self, exc):
        if self._ping_task:
            self._ping_task.cancel()
        self._done.set()
        self._client._on_protocol_done()

    def error_received(self, exc):
        log.warning('HBP socket error: %s', exc)
        if self._state != 'DISCONNECTED':
            if self._state == 'CONNECTED':
                self._translator.hbp_disconnected()
            self._disconnect(send_rptcl=False)

    def datagram_received(self, data: bytes, addr):
        if len(data) < 4:
            return
        cmd4 = data[:4]

        # Dispatch by longest-match prefix
        if len(data) >= 6 and data[:6] == HBPF_RPTACK:
            self._on_rptack(data)
        elif len(data) >= 6 and data[:6] == HBPF_MSTNAK:
            log.error('HBP: ← MSTNAK — rejected by server')
            self._disconnect(send_rptcl=False)
        elif len(data) >= 7 and data[:7] == HBPF_MSTPONG:
            self._on_mstpong(data)
        elif len(data) >= 5 and data[:5] == HBPF_MSTCL:
            log.info('HBP: ← MSTCL — server initiated disconnect')
            self._disconnect(send_rptcl=False)
        elif cmd4 == b'DMRD':
            if self._state == 'CONNECTED':
                self._translator.hbp_voice_received(data)
        else:
            log.debug('HBP: unknown packet cmd=%s len=%d', data[:4], len(data))

    # ------------------------------------------------------------------
    # RPTACK state machine
    # ------------------------------------------------------------------

    def _on_rptack(self, data: bytes):
        if self._state == 'LOGIN':
            # RPTACK+salt: challenge
            if len(data) < RPTACK_NONCE_OFF + 4:
                log.error('HBP: RPTACK+salt too short (%d bytes)', len(data))
                return
            salt_bytes = data[RPTACK_NONCE_OFF : RPTACK_NONCE_OFF + 4]
            digest = bytes.fromhex(
                sha256(salt_bytes + self._cfg.hbp_passphrase).hexdigest()
            )
            self._send_raw(HBPF_RPTK + self._radio_id_b + digest)
            self._state = 'AUTH_SENT'
            log.info('HBP: ← RPTACK+salt  → RPTK')

        elif self._state == 'AUTH_SENT':
            # RPTACK: auth accepted → send config
            rptc = _build_rptc(self._cfg)
            self._send_raw(rptc)
            self._state = 'CONFIG_SENT'
            log.info('HBP: ← RPTACK(auth)  → RPTC (%d bytes)', len(rptc))

        elif self._state == 'CONFIG_SENT':
            # RPTACK: config accepted — send RPTO if options are configured
            if self._cfg.options:
                opts = self._cfg.options.encode().ljust(300, b'\x00')[:300]
                self._send_raw(HBPF_RPTO + self._radio_id_b + opts)
                self._state = 'OPTIONS_SENT'
                log.info('HBP: ← RPTACK(config)  → RPTO  options=%r', self._cfg.options)
            else:
                log.info('HBP: ← RPTACK(config)  CONNECTED to %s:%d',
                         self._cfg.hbp_master_ip, self._cfg.hbp_master_port)
                self._become_connected()

        elif self._state == 'OPTIONS_SENT':
            # RPTACK: options accepted → connected
            log.info('HBP: ← RPTACK(options)  CONNECTED to %s:%d',
                     self._cfg.hbp_master_ip, self._cfg.hbp_master_port)
            self._become_connected()

        else:
            log.debug('HBP: unexpected RPTACK in state %s', self._state)

    def _become_connected(self):
        self._state = 'CONNECTED'
        self._last_pong = time()
        loop = asyncio.get_event_loop()
        self._ping_task = loop.create_task(self._keepalive_loop())
        self._translator.hbp_connected()

    def _on_mstpong(self, data: bytes):
        self._last_pong = time()
        log.debug('HBP: ← MSTPONG')

    # ------------------------------------------------------------------
    # Keepalive
    # ------------------------------------------------------------------

    async def _keepalive_loop(self):
        while self._state == 'CONNECTED':
            await asyncio.sleep(_KA_INTERVAL)
            if self._state != 'CONNECTED':
                break
            self._send_raw(HBPF_RPTPING + self._radio_id_b)
            log.debug('HBP: → RPTPING')
            age = time() - self._last_pong
            if age > _MAX_KA_AGE:
                log.error('HBP: watchdog — no MSTPONG for %.1fs — disconnecting', age)
                self._translator.hbp_disconnected()
                self._disconnect(send_rptcl=False)
                return

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _send_raw(self, data: bytes):
        if self._transport:
            self._transport.sendto(data)

    def send_dmrd(self, data: bytes):
        if self._state == 'CONNECTED' and self._transport:
            self._transport.sendto(data)

    def is_connected(self) -> bool:
        return self._state == 'CONNECTED'

    def _disconnect(self, send_rptcl: bool = True):
        if send_rptcl and self._state == 'CONNECTED':
            self._send_raw(HBPF_RPTCL + self._radio_id_b)
            log.info('HBP: → RPTCL (clean disconnect)')
        self._state = 'DISCONNECTED'
        if self._ping_task:
            self._ping_task.cancel()
            self._ping_task = None
        if self._transport:
            self._transport.close()
            self._transport = None

    async def wait_done(self):
        await self._done.wait()


class HBPClient:
    """
    Manages HBP outbound connection lifecycle with auto-reconnect.

    For TRACKING mode: call activate() when IPSC peer registers,
    deactivate() when IPSC peer is lost.
    For PERSISTENT mode: activate() is called automatically on start().
    """

    def __init__(self, cfg: Config, translator):
        self._cfg        = cfg
        self._translator = translator
        self._loop       = None
        self._protocol   = None
        self._active     = False
        self._connect_task = None

    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        if self._cfg.hbp_mode == 'PERSISTENT':
            self.activate()

    def stop(self):
        """Clean shutdown — deactivate and cancel reconnect loop."""
        self._active = False
        if self._protocol:
            self._protocol._disconnect(send_rptcl=True)
        if self._connect_task and not self._connect_task.done():
            self._connect_task.cancel()

    def activate(self):
        """Enable HBP connection (called by translator when IPSC peer registers)."""
        if self._active:
            return
        self._active = True
        log.info('HBP client activated')
        if not self._connect_task or self._connect_task.done():
            self._connect_task = self._loop.create_task(self._connect_loop())

    def deactivate(self):
        """Disable HBP connection (called by translator when IPSC peer is lost)."""
        if not self._active:
            return
        self._active = False
        log.info('HBP client deactivated')
        if self._protocol:
            self._protocol._disconnect(send_rptcl=True)

    def send_dmrd(self, data: bytes):
        if self._protocol:
            self._protocol.send_dmrd(data)

    def is_connected(self) -> bool:
        return self._protocol is not None and self._protocol.is_connected()

    def _on_protocol_done(self):
        """Called by _HBPProtocol.connection_lost."""
        self._protocol = None

    async def _connect_loop(self):
        while self._active:
            try:
                proto = _HBPProtocol(self._cfg, self._translator, self)
                _, _ = await self._loop.create_datagram_endpoint(
                    lambda p=proto: p,
                    remote_addr=(self._cfg.hbp_master_ip, self._cfg.hbp_master_port),
                )
                self._protocol = proto
                log.info('HBP: UDP endpoint created → %s:%d',
                         self._cfg.hbp_master_ip, self._cfg.hbp_master_port)
                await proto.wait_done()
            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.error('HBP: connect failed: %s', exc)

            if self._active:
                log.info('HBP: reconnecting in %.0fs', _RECONNECT_DELAY)
                try:
                    await asyncio.sleep(_RECONNECT_DELAY)
                except asyncio.CancelledError:
                    return
