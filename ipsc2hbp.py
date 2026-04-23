"""
ipsc2hbp — entry point.

Wires IPSCProtocol, HBPClient, and CallTranslator together and runs
the asyncio event loop.
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
    log.info('ipsc2hbp starting — IPSC master_id=%d  peer_id=%d  HBP %s:%d  mode=%s',
             cfg.ipsc_master_id, cfg.ipsc_peer_id,
             cfg.hbp_master_ip, cfg.hbp_master_port, cfg.hbp_mode)

    from ipsc.protocol import IPSCProtocol
    from hbp.protocol import HBPClient
    from translate.bridge import CallTranslator

    translator = CallTranslator(cfg)
    ipsc_proto = IPSCProtocol(cfg, translator)
    hbp_client = HBPClient(cfg, translator)
    translator.set_protocols(ipsc_proto, hbp_client)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _shutdown(signum, frame):
        log.info('Signal %d received — shutting down', signum)
        hbp_client.stop()
        loop.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _shutdown)

    ipsc_coro = loop.create_datagram_endpoint(
        lambda: ipsc_proto,
        local_addr=(cfg.ipsc_bind_ip, cfg.ipsc_bind_port),
    )

    try:
        loop.run_until_complete(ipsc_coro)
        log.info('IPSC master endpoint up — %s:%d', cfg.ipsc_bind_ip, cfg.ipsc_bind_port)
        hbp_client.start(loop)
        loop.run_forever()
    except OSError as exc:
        sys.exit(f'Failed to bind IPSC socket: {exc}')
    finally:
        log.info('ipsc2hbp stopped')
        loop.close()


if __name__ == '__main__':
    main()
