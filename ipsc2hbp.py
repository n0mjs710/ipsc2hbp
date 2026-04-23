"""
ipsc2hbp — entry point.

Wires IPSCProtocol, HBPProtocol, and CallTranslator together and runs
the asyncio event loop.  Phase 3: HBP client wired; translator still stub.
"""

import argparse
import asyncio
import logging
import signal
import sys

from config import Config, load as load_config


def _setup_logging(level: str):
    fmt = '%(asctime)s %(levelname)s [%(name)s] %(message)s'
    root = logging.getLogger()
    root.setLevel(getattr(logging, level))
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(fmt))
        root.addHandler(handler)
    else:
        for h in root.handlers:
            h.setLevel(getattr(logging, level))
            h.setFormatter(logging.Formatter(fmt))


class _StubTranslator:
    """Stub translator — used until bridge.py is implemented (Phase 4)."""

    def peer_registered(self, peer_id: bytes, host: str, port: int):
        logging.getLogger('stub').info(
            'peer_registered: id=%d  %s:%d', int.from_bytes(peer_id, 'big'), host, port
        )

    def peer_lost(self):
        logging.getLogger('stub').warning('peer_lost')

    def ipsc_voice_received(self, data: bytes, ts: int, burst_type: int):
        logging.getLogger('stub').debug(
            'ipsc_voice_received ts=%d burst_type=0x%02x len=%d', ts, burst_type, len(data)
        )

    def hbp_connected(self):
        logging.getLogger('stub').info('hbp_connected')

    def hbp_disconnected(self):
        logging.getLogger('stub').warning('hbp_disconnected')

    def hbp_voice_received(self, dmrd: bytes):
        logging.getLogger('stub').debug('hbp_voice_received len=%d', len(dmrd))

    def is_hbp_connected(self) -> bool:
        return False

    def is_ipsc_registered(self) -> bool:
        return False


def main():
    ap = argparse.ArgumentParser(description='IPSC to HomeBrew Protocol translator')
    ap.add_argument('-c', '--config', default='/etc/ipsc2hbp/ipsc2hbp.toml',
                    help='Path to TOML config file')
    ap.add_argument('--log-level', dest='log_level', default=None,
                    help='Override config log level (DEBUG|INFO|WARNING|ERROR)')
    args = ap.parse_args()

    try:
        cfg = load_config(args.config)
    except (FileNotFoundError, ValueError) as exc:
        sys.exit(f'Configuration error: {exc}')

    log_level = args.log_level.upper() if args.log_level else cfg.log_level
    _setup_logging(log_level)

    log = logging.getLogger('ipsc2hbp')
    log.info('ipsc2hbp starting — IPSC master_id=%d  peer_id=%d',
             cfg.ipsc_master_id, cfg.ipsc_peer_id)

    translator = _StubTranslator()

    from ipsc.protocol import IPSCProtocol
    from hbp.protocol import HBPClient

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    hbp_client = HBPClient(cfg, translator)

    # Graceful shutdown
    def _shutdown(signum, frame):
        log.info('Signal %d received — shutting down', signum)
        hbp_client.stop()
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _shutdown)

    # Start IPSC master endpoint
    ipsc_proto = IPSCProtocol(cfg, translator)
    ipsc_coro = loop.create_datagram_endpoint(
        lambda: ipsc_proto,
        local_addr=(cfg.ipsc_bind_ip, cfg.ipsc_bind_port),
    )

    try:
        loop.run_until_complete(ipsc_coro)
        log.info('IPSC master endpoint up — listening on %s:%d',
                 cfg.ipsc_bind_ip, cfg.ipsc_bind_port)
        hbp_client.start(loop)
        loop.run_forever()
    except OSError as exc:
        sys.exit(f'Failed to bind IPSC socket: {exc}')
    finally:
        log.info('ipsc2hbp stopped')
        loop.close()


if __name__ == '__main__':
    main()
